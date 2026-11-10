'use strict';
// STUB of IFC's CCaaS voicebot orchestration (UC-06). It plays the CCaaS side only:
//   /call      start a call
//   /identify  caller gives a policy number; look the customer up (mock Client 360) and find them in Verify (SCIM)
//   /challenge Verify sends an email OTP to the address ON FILE (never one the caller states), or caller uses TOTP
//   /verify    validate the OTP / TOTP with Verify (tier-1: information, documents, simple transactions)
//   /stepup    tier-2 for sensitive requests: push to the registered IBM Verify app, or TOTP from an authenticator app
//   /stepup/verify, /stepup/status/:callId
//   /transaction  execute a request against the mock back-end APIs, only if the risk tier is satisfied
//   /transcript/:callId  what happened, including every Verify call (status, x-correlation-id, ms)
// UC-07 adds (only when a `handoff` config is passed to buildApp):
//   /handoff   the customer is already signed in to the mobile app: validate the app's access token with Verify (introspection),
//              bridge the call to that app session, mint a short-lived channel token (RFC 8693 token exchange), skip the OTP for tier 1
//   /agent/:callId  what a human agent's screen-pop would show; /handoff/latest  the newest bridged call (for the voice leg)
//   Every tier-1 or step-up request re-checks that the app session is still alive. Tier 2 still needs a step-up.
// Voice itself is simulated: the "caller" is demo/uc06-voice/caller.js (or run.js). Verify is the identity engine only.
// The stub talks to Verify with a LEAST-PRIVILEGE API client (ifc-demo-uc06-ccaas / ifc-demo-uc07-ccaas), not the 165-entitlement admin client.

const express = require('express');
const crypto = require('crypto');
const be = require('./backends');
const { createClient, stateFile } = require('../../demo/lib/verify');

const TIER1_TTL_MS = 10 * 60 * 1000;
const STEPUP_TTL_MS = 5 * 60 * 1000;
const ACTION_LABEL = {
  change_email: 'Change e-mail address', change_bank_account: 'Change bank account',
};

// handoff (optional, UC-07): { sts: oauthClient(stsClientId, stsSecret), allowedClientIds: [app client ids], maxAppAuthAgeSec }
function buildApp({ ccaasApi, handoff }) {
  const app = express();
  app.use(express.json());
  const calls = new Map();
  let latestBridged = null;

  // ---- helpers ------------------------------------------------------------------------------------------------
  const iso = () => new Date().toISOString();
  const digits = (s) => String(s || '').replace(/\D/g, '');
  const bot = (call, text) => { call.transcript.push({ at: iso(), who: 'BOT', text }); return text; };
  const caller = (call, text) => { call.transcript.push({ at: iso(), who: 'CALLER', text }); };
  const reply = (res, code, call, body) => {
    if (body.say) bot(call, body.say);
    res.status(code).json({ callId: call.id, ...body });
  };
  // Every Verify call is recorded (no secrets, no OTP values, no tokens).
  async function v(call, op, method, path, opts = {}) {
    const r = await ccaasApi(method, path, { quiet: true, ...opts });
    call.verifyCalls.push({
      at: iso(), op, method, path, status: r.status, cid: r.cid, ms: r.ms,
      messageId: (r.data && r.data.messageId) || undefined,
    });
    return r;
  }
  // Same, for OAuth-client calls made with the STS client (introspect / token exchange).
  async function o(call, op, method, path, fn) {
    const r = await fn();
    call.verifyCalls.push({ at: iso(), op, method, path, status: r.status, cid: r.cid, ms: r.ms, messageId: (r.data && r.data.error) || undefined });
    return r;
  }
  const newCall = (channel) => {
    const call = {
      id: crypto.randomUUID(), startedAt: iso(), channel, transcript: [], verifyCalls: [], idAttempts: 0, locked: false,
      customer: null, userId: null, email: null, factors: null, otp: null, verified: null, stepup: null, bridge: null,
    };
    calls.set(call.id, call);
    return call;
  };
  // Which step-up factors does this customer have? (TOTP app code, registered phone for push)
  async function loadFactors(call) {
    const t = await v(call, 'list TOTP enrolment', 'GET', '/v2.0/factors/totp', { query: { search: `userId="${call.userId}"` } });
    const sg = await v(call, 'list signature (push) enrolments', 'GET', '/v1.0/authnmethods/signatures', { query: { search: `owner="${call.userId}"` } });
    const totp = t.status === 200 ? (t.data.totp || []).find((x) => x.enabled) : null;
    const sig = sg.status === 200 ? (sg.data.signatures || []).find((x) => x.enabled && x.attributes && x.attributes.authenticatorId) : null;
    call.factors = {
      totpId: totp ? totp.id : null,
      signatureId: sig ? sig.id : null,
      authenticatorId: sig ? sig.attributes.authenticatorId : null,
    };
  }
  // UC-07 session bridge: the call is only as trustworthy as the app session it is linked to. Re-introspect the app's access
  // token; if it was revoked (logout) or the account was deactivated, the call drops back to "unverified".
  async function bridgeAlive(call) {
    if (!call.bridge) return true;
    const i = await o(call, 'introspect app token (bridge check)', 'POST', '/oauth2/introspect', () => handoff.sts.introspect(call.bridge.appToken));
    if (i.status === 200 && i.data && i.data.active === true) { if (call.verified) call.verified.at = Date.now(); return true; }
    call.verified = null; call.stepup = null;
    call.bridge.endedAt = iso(); call.bridge.endedBecause = i.status === 200 ? 'app token no longer active (logout, revocation or account deactivated)' : `introspection HTTP ${i.status}`;
    return false;
  }
  const appSessionEnded = (res, call) => reply(res, 401, call, {
    error: 'app_session_ended', say: 'I can no longer see your app session, so for your security I need to verify you another way.',
  });
  const getCall = (req, res) => {
    const call = calls.get(req.body.callId || req.params.callId);
    if (!call) { res.status(404).json({ error: 'unknown_call' }); return null; }
    return call;
  };
  const tier1Ok = (call) => !!call.verified && Date.now() - call.verified.at < TIER1_TTL_MS;
  const stepupOk = (call) => !!call.stepup && call.stepup.ok && !call.stepup.consumed && Date.now() - call.stepup.okAt < STEPUP_TTL_MS;
  const stepupOptions = (call) => {
    const o = [];
    if (call.factors && call.factors.signatureId) o.push('push');
    if (call.factors && call.factors.totpId) o.push('totp');
    return o;
  };

  // ---- endpoints ----------------------------------------------------------------------------------------------
  app.get('/health', (req, res) => res.json({ ok: true, service: 'voicebot-ccaas-stub' }));

  app.post('/reset', (req, res) => { calls.clear(); be.reset(); res.json({ ok: true }); });

  app.post('/call', (req, res) => {
    const call = newCall('phone');
    reply(res, 201, call, { say: 'Welcome to Intact Insurance. Please say or enter your policy number.' });
  });

  // ---- UC-07: app-to-voice handoff ----------------------------------------------------------------------------
  app.post('/handoff', async (req, res) => {
    const call = newCall('app-handoff');
    if (!handoff) return reply(res, 501, call, { error: 'handoff_not_configured' });
    const token = typeof req.body.accessToken === 'string' ? req.body.accessToken : '';
    caller(call, 'Taps "Speak with a Voicebot" in the app (token is not logged)');
    if (!token) return reply(res, 400, call, { error: 'missing_token', say: 'I could not see your app session. Please say or enter your policy number.' });

    // 1. CIAM validates the token generated by the mobile app
    const i = await o(call, 'introspect app token', 'POST', '/oauth2/introspect', () => handoff.sts.introspect(token));
    const t = i.status === 200 ? i.data : null;
    if (!t || t.active !== true) {
      return reply(res, 401, call, { error: 'invalid_app_token', say: 'I could not confirm your app session. Please say or enter your policy number.' });
    }
    // Only tokens issued to OUR apps, and never a token-exchange result (a voice-channel token must not be replayed as an app token)
    if (!handoff.allowedClientIds.includes(t.client_id) || t.grant_type === 'urn:ietf:params:oauth:grant-type:token-exchange') {
      return reply(res, 401, call, { error: 'untrusted_token', say: 'That session did not come from the Intact app. Please say or enter your policy number.' });
    }
    // 2. Who is it? sub is the Verify user id
    const u = await v(call, 'SCIM lookup by id (sub)', 'GET', `/v2.0/Users/${encodeURIComponent(t.sub)}`, { query: { attributes: 'id,userName,emails,active' } });
    const user = u.status === 200 ? u.data : null;
    const cust = user && be.findByUserName(user.userName);
    if (!user || user.active === false || !cust) {
      return reply(res, 404, call, { error: 'no_policyholder', say: 'I cannot find an active policy for your profile. Let me transfer you to an agent.' });
    }
    call.customer = cust; call.userId = user.id; call.email = user.emails[0].value;
    await loadFactors(call);
    // 3. Policy: how fresh must the app login be to skip the OTP? iat is the issue time of the access token [INFER: a proxy for auth time]
    const ageSec = Math.round(Date.now() / 1000 - t.iat);
    if (handoff.maxAppAuthAgeSec != null && ageSec > handoff.maxAppAuthAgeSec) {
      return reply(res, 200, call, {
        handedOff: false, reason: 'app_login_too_old', appLoginAgeSec: ageSec, methods: ['email_otp'].concat(call.factors.totpId ? ['totp'] : []),
        say: `I can see you signed in to the app, but not recently enough to skip a check. I will verify you with a code. I can e-mail one to the address ending ${be.mask(call.email).split('@')[1]}.`
          + (call.factors.totpId ? ' Or you can read me the code from your authenticator app.' : ''),
      });
    }
    // 4. Channel token: RFC 8693 token exchange, short lived, issued to the CCaaS STS client
    const x = await o(call, 'token exchange (app token -> voice-channel token)', 'POST', '/oauth2/token', () => handoff.sts.exchange(token));
    if (x.status !== 200 || !x.data.access_token) {
      return reply(res, 502, call, { error: 'exchange_failed', verifyError: x.data && x.data.error, say: 'I had a problem linking your app. Let me transfer you to an agent.' });
    }
    const vt = await o(call, 'introspect voice-channel token', 'POST', '/oauth2/introspect', () => handoff.sts.introspect(x.data.access_token));
    // 5. Session bridge. Raw tokens stay in memory and are never returned or logged.
    call.bridge = {
      appToken: token, voiceToken: x.data.access_token, sub: t.sub, appClientId: t.client_id, grantId: t.grant_id, amr: t.amr || [],
      appTokenIssuedAt: new Date(t.iat * 1000).toISOString(), linkedAt: iso(),
      voice: { ttlSec: x.data.expires_in, active: !!(vt.data && vt.data.active), grantType: vt.data && vt.data.grant_type, sameSubject: !!(vt.data && vt.data.sub === t.sub) },
    };
    call.verified = { method: 'app_token', at: Date.now(), atIso: iso() };
    latestBridged = call.id;
    reply(res, 200, call, {
      handedOff: true, tier: 1, verifiedBy: 'mobile app session', customer: { name: `${cust.given} ${cust.family}`, policyNumber: cust.policyNumber },
      bridge: { sub: t.sub, amr: call.bridge.amr, appLoginAgeSec: ageSec, appTokenExpiresInSec: t.exp - Math.round(Date.now() / 1000), voiceToken: call.bridge.voice },
      stepUpAvailable: stepupOptions(call),
      say: `Hello ${cust.given}, I can see you are signed in to the Intact app, so I do not need to ask you any security questions. How can I help you today?`,
    });
  });

  app.get('/handoff/latest', (req, res) => (latestBridged ? res.json({ callId: latestBridged }) : res.status(404).json({ error: 'no_bridged_call' })));

  // What a human agent's screen-pop would show.
  app.get('/agent/:callId', async (req, res) => {
    const call = getCall(req, res); if (!call) return;
    const alive = call.bridge ? await bridgeAlive(call) : null;
    res.json({
      callId: call.id, channel: call.channel,
      caller: call.customer ? { name: `${call.customer.given} ${call.customer.family}`, policyNumber: call.customer.policyNumber } : null,
      authentication: call.verified
        ? { status: 'AUTHENTICATED', by: call.verified.method === 'app_token' ? 'mobile app session' : call.verified.method, tier: 1, amr: call.bridge ? call.bridge.amr : undefined, sessionBridgeAlive: alive }
        : { status: 'NOT AUTHENTICATED', note: call.bridge && call.bridge.endedBecause },
      sensitiveRequests: stepupOk(call) ? 'step-up satisfied for ONE action' : 'step-up required (push or authenticator-app code)',
    });
  });

  app.post('/identify', async (req, res) => {
    const call = getCall(req, res); if (!call) return;
    caller(call, `Policy number: ${req.body.policyNumber}`);
    if (call.locked) return reply(res, 423, call, { error: 'call_locked', say: 'For your security I am transferring you to an agent.' });
    const cust = be.findByPolicy(req.body.policyNumber);
    if (!cust) {
      call.idAttempts += 1;
      if (call.idAttempts >= 3) call.locked = true;
      return reply(res, 404, call, { error: 'policy_not_found', say: 'I could not find that policy. Please try again.' });
    }
    const u = await v(call, 'SCIM lookup', 'GET', '/v2.0/Users', {
      query: { filter: `userName eq "${cust.userName}"`, attributes: 'id,userName,emails' },
    });
    const user = u.status === 200 && u.data.Resources && u.data.Resources[0];
    if (!user) return reply(res, 502, call, { error: 'identity_not_found', say: 'I cannot verify your account right now. Let me transfer you to an agent.' });

    call.customer = cust; call.userId = user.id; call.email = user.emails[0].value;
    await loadFactors(call);
    const methods = ['email_otp'].concat(call.factors.totpId ? ['totp'] : []);
    reply(res, 200, call, {
      identified: true, methods, stepUpAvailable: stepupOptions(call),
      say: `Thank you. To protect your account I need to verify you. I can e-mail a one-time code to the address ending ${be.mask(call.email).split('@')[1]}`
        + (call.factors.totpId ? ', or you can read me the code from your authenticator app.' : '.'),
    });
  });

  app.post('/challenge', async (req, res) => {
    const call = getCall(req, res); if (!call) return;
    if (!call.userId) return reply(res, 409, call, { error: 'identify_first', say: 'I need your policy number first.' });
    if (call.locked) return reply(res, 423, call, { error: 'call_locked', say: 'For your security I am transferring you to an agent.' });
    const method = req.body.method;
    caller(call, `Chooses ${method}`);
    if (method === 'email_otp') {
      const correlation = String(crypto.randomInt(1000, 10000));
      const r = await v(call, 'email OTP create', 'POST', '/v2.0/factors/emailotp/transient/verifications', {
        body: { correlation, emailAddress: call.email }, // address on file, never caller-supplied
      });
      if (r.status !== 201) {
        return reply(res, 502, call, { error: 'otp_not_delivered', verifyMessageId: r.data && r.data.messageId, say: 'I could not send the code. Let me transfer you to an agent.' });
      }
      call.otp = { method, txnId: r.data.id, correlation, attempts: 0, retries: r.data.retries, expiry: r.data.expiry };
      return reply(res, 200, call, {
        method, correlation, txnId: r.data.id, expiresAt: r.data.expiry, attemptsAllowed: r.data.retries + 1,
        say: `I have sent a code to your e-mail. It starts with ${correlation.split('').join(' ')}. Please read me only the digits AFTER the dash.`,
      });
    }
    if (method === 'totp') {
      if (!call.factors.totpId) return reply(res, 409, call, { error: 'no_totp', say: 'You have no authenticator app set up. Let me e-mail you a code instead.' });
      call.otp = { method, attempts: 0 };
      return reply(res, 200, call, { method, say: 'Please read me the 6-digit code from your authenticator app.' });
    }
    reply(res, 400, call, { error: 'unsupported_method', supported: ['email_otp', 'totp'], say: 'Sorry, I cannot use that method.' });
  });

  // Shared TOTP attempt (tier-1 and step-up)
  async function attemptTotp(call, op, code) {
    const r = await v(call, op, 'POST', `/v2.0/factors/totp/${call.factors.totpId}`, { body: { otp: digits(code) } });
    if (r.status === 204) return { ok: true };
    const id = r.data && r.data.messageId;
    if (r.status === 429) return { ok: false, locked: true, messageId: id };
    return { ok: false, messageId: id };
  }

  app.post('/verify', async (req, res) => {
    const call = getCall(req, res); if (!call) return;
    if (call.locked) return reply(res, 423, call, { error: 'call_locked', say: 'For your security I am transferring you to an agent.' });
    if (!call.otp) return reply(res, 409, call, { error: 'challenge_first', say: 'I have not sent you a code yet.' });
    caller(call, 'Reads a code (not logged)');
    let result;
    if (call.otp.method === 'email_otp') {
      const r = await v(call, 'email OTP attempt', 'POST', `/v2.0/factors/emailotp/transient/verifications/${call.otp.txnId}`, { body: { otp: digits(req.body.code) } });
      call.otp.attempts += 1;
      const id = r.data && r.data.messageId;
      if (r.status === 204) result = { ok: true };
      else if (id === 'CSIBN0080E') result = { ok: false, exhausted: true, messageId: id };
      else if (id === 'CSIBN0025E' || id === 'CSIBN0028E') result = { ok: false, expired: true, messageId: id };
      else result = { ok: false, messageId: id, attemptsLeft: Math.max(call.otp.retries + 1 - call.otp.attempts, 0) };
    } else {
      call.otp.attempts += 1;
      result = await attemptTotp(call, 'TOTP attempt (tier 1)', req.body.code);
    }
    if (result.ok) {
      call.verified = { method: call.otp.method, at: Date.now(), atIso: iso() };
      return reply(res, 200, call, { verified: true, method: call.otp.method, tier: 1, say: 'Thank you, you are verified. How can I help you today?' });
    }
    if (result.exhausted) {
      call.locked = true;
      return reply(res, 423, call, { verified: false, error: 'too_many_attempts', verifyMessageId: result.messageId, say: 'That was too many incorrect attempts. For your security I am transferring you to an agent.' });
    }
    if (result.locked) {
      return reply(res, 429, call, { verified: false, error: 'totp_temporarily_locked', verifyMessageId: result.messageId, say: 'Too many incorrect codes. Please wait a moment, or let me e-mail you a code instead.' });
    }
    if (result.expired) {
      return reply(res, 410, call, { verified: false, error: 'code_expired', verifyMessageId: result.messageId, say: 'That code has expired. Let me send you a new one.' });
    }
    reply(res, 401, call, { verified: false, error: 'wrong_code', attemptsLeft: result.attemptsLeft, verifyMessageId: result.messageId, say: 'That code was not correct. Please try again.' });
  });

  app.post('/stepup', async (req, res) => {
    const call = getCall(req, res); if (!call) return;
    if (!(await bridgeAlive(call))) return appSessionEnded(res, call);
    if (!tier1Ok(call)) return reply(res, 401, call, { error: 'not_verified', say: 'I need to verify you first.' });
    const method = req.body.method;
    const action = req.body.action || (call.pending && call.pending.action);
    caller(call, `Chooses step-up ${method}`);
    if (method === 'push') {
      if (!call.factors.signatureId) {
        return reply(res, 409, call, { error: 'no_registered_device', say: 'You have no registered phone for approvals. Please choose another method.' });
      }
      const label = ACTION_LABEL[action] || 'Confirm your request';
      const r = await v(call, 'push verification initiate', 'POST', `/v1.0/authenticators/${call.factors.authenticatorId}/verifications`, {
        body: {
          transactionData: {
            message: `${label} (call to Intact, policy ${call.customer.policyNumber})`,
            originIpAddress: '203.0.113.10', originUserAgent: 'IFC-CCaaS-Voicebot-stub/1.0',
            additionalData: [{ name: 'channel', value: 'voice' }],
          },
          pushNotification: { title: 'Intact Insurance', message: 'Approve to continue your phone request', send: true },
          authenticationMethods: [{ id: call.factors.signatureId, methodType: 'signature' }],
          logic: 'OR', expiresIn: 120,
        },
      });
      if (r.status !== 202) {
        return reply(res, 502, call, { error: 'push_not_sent', verifyStatus: r.status, verifyMessageId: r.data && r.data.messageId, say: 'I could not reach your phone. Please choose another method.' });
      }
      call.stepup = { method, txnId: r.data.id, ok: false, consumed: false };
      return reply(res, 202, call, { method, txnId: r.data.id, say: 'I have sent a notification to your phone. Please approve it in the IBM Verify app.' });
    }
    if (method === 'totp') {
      if (!call.factors.totpId) return reply(res, 409, call, { error: 'no_totp', say: 'You have no authenticator app set up.' });
      call.stepup = { method, ok: false, consumed: false, startedAt: Date.now() };
      return reply(res, 200, call, { method, say: 'For this request I need a NEW code from your authenticator app. Please wait for it to refresh, then read it to me.' });
    }
    if (method === 'passkey') {
      return reply(res, 501, call, { error: 'passkey_not_built', say: 'Passkey approval needs a browser hand-off, which this demo does not include.' });
    }
    reply(res, 400, call, { error: 'unsupported_method', supported: ['push', 'totp'], say: 'Sorry, I cannot use that method.' });
  });

  app.post('/stepup/verify', async (req, res) => {
    const call = getCall(req, res); if (!call) return;
    if (!call.stepup || call.stepup.method !== 'totp') return reply(res, 409, call, { error: 'stepup_not_started', say: 'I have not asked for an approval code.' });
    caller(call, 'Reads a step-up code (not logged)');
    const r = await attemptTotp(call, 'TOTP attempt (step-up)', req.body.code);
    if (r.ok) {
      Object.assign(call.stepup, { ok: true, okAt: Date.now(), okIso: iso() });
      return reply(res, 200, call, { stepUp: true, method: 'totp', say: 'Thank you. I can now continue with your request.' });
    }
    if (r.locked) return reply(res, 429, call, { stepUp: false, error: 'totp_temporarily_locked', verifyMessageId: r.messageId, say: 'Too many incorrect codes. Please wait a moment.' });
    reply(res, 401, call, { stepUp: false, error: 'wrong_code', verifyMessageId: r.messageId, say: 'That code was not accepted. Wait for a new code and try again.' });
  });

  app.get('/stepup/status/:callId', async (req, res) => {
    const call = getCall(req, res); if (!call) return;
    if (!call.stepup || call.stepup.method !== 'push') return reply(res, 409, call, { error: 'no_push_pending', say: 'There is no pending notification.' });
    if (call.stepup.ok) return res.json({ callId: call.id, state: 'VERIFY_SUCCESS', stepUp: true });
    const r = await v(call, 'push verification status', 'GET', `/v1.0/authenticators/${call.factors.authenticatorId}/verifications/${call.stepup.txnId}`);
    const state = r.status === 200 ? r.data.state : `HTTP_${r.status}`;
    if (state === 'VERIFY_SUCCESS') {
      Object.assign(call.stepup, { ok: true, okAt: Date.now(), okIso: iso() });
      bot(call, 'Thank you, approval received.');
    }
    res.json({ callId: call.id, state, stepUp: call.stepup.ok });
  });

  app.post('/transaction', async (req, res) => {
    const call = getCall(req, res); if (!call) return;
    const action = req.body.action;
    const spec = be.ACTIONS[action];
    caller(call, `Request: ${action}`);
    if (!spec) return reply(res, 400, call, { error: 'unknown_action', say: 'Sorry, I cannot help with that request.' });
    if (!(await bridgeAlive(call))) return appSessionEnded(res, call);
    if (!tier1Ok(call)) return reply(res, 401, call, { error: 'not_verified', say: 'I need to verify you before I can help with that.' });
    if (spec.tier === 2 && !stepupOk(call)) {
      call.pending = { action, at: Date.now() };
      if (call.stepup && call.stepup.consumed) call.stepup = null;
      return reply(res, 403, call, {
        error: 'step_up_required', tier: 2, options: stepupOptions(call),
        say: `${spec.kind === 'sensitive transaction' ? 'This is a sensitive request.' : ''} I need one more approval. You can approve a notification on your phone, or read me a new code from your authenticator app.`.trim(),
      });
    }
    const c = call.customer;
    let result, say;
    switch (action) {
      case 'outstanding_bill': result = be.billing(c); say = `Your outstanding balance is ${result.outstanding.toFixed(2)} ${result.currency}, due on ${result.dueDate}.`; break;
      case 'renewal_date': result = be.renewal(c); say = `Your policy renews on ${result.renewalDate}.`; break;
      case 'proof_of_insurance': result = be.proofOfInsurance(c, call.email); say = `I have e-mailed your proof of insurance to ${result.deliveredTo}.`; break;
      case 'storage': result = be.storage(c); say = `Done. Storage coverage for your ${result.vehicle} is requested, effective ${result.effective}.`; break;
      case 'change_email': {
        result = be.changeEmail(c, req.body.newEmail);
        if (result.error) return reply(res, 400, call, { error: result.error, say: 'That e-mail address does not look valid.' });
        say = `Done. Your e-mail address is now ${result.newEmail}.`; break;
      }
      case 'change_bank_account': result = be.changeBankAccount(c); say = 'Done. I have re-issued your pre-authorized debit mandate for the new account.'; break;
      default: return reply(res, 400, call, { error: 'unknown_action', say: 'Sorry, I cannot help with that request.' });
    }
    if (spec.tier === 2) call.stepup.consumed = true; // step-up approves ONE sensitive action
    reply(res, 200, call, { action, kind: spec.kind, tier: spec.tier, result, say });
  });

  app.get('/transcript/:callId', (req, res) => {
    const call = getCall(req, res); if (!call) return;
    res.json({
      callId: call.id, startedAt: call.startedAt, locked: call.locked, channel: call.channel,
      bridge: call.bridge && {
        sub: call.bridge.sub, appClientId: call.bridge.appClientId, amr: call.bridge.amr, appTokenIssuedAt: call.bridge.appTokenIssuedAt,
        linkedAt: call.bridge.linkedAt, voiceToken: call.bridge.voice, endedAt: call.bridge.endedAt, endedBecause: call.bridge.endedBecause,
      },
      verified: call.verified && { method: call.verified.method, at: call.verified.atIso },
      stepUp: call.stepup && { method: call.stepup.method, txnId: call.stepup.txnId, ok: call.stepup.ok, consumed: call.stepup.consumed },
      emailOtpTxnId: call.otp && call.otp.txnId,
      transcript: call.transcript, verifyCalls: call.verifyCalls,
    });
  });

  return app;
}

function loadCcaasApi() {
  const st = stateFile('uc06').read();
  if (!st || !st.ccaas) throw new Error('No UC-06 state. Run: node demo/uc06-voice/setup.js');
  return createClient(st.ccaas.clientId, st.ccaas.clientSecret).api;
}

function start(port, ccaasApi, handoff) {
  const app = buildApp({ ccaasApi: ccaasApi || loadCcaasApi(), handoff });
  return new Promise((resolve, reject) => {
    const server = app.listen(port, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

module.exports = { buildApp, start };

if (require.main === module) {
  const port = Number(process.env.UC06_PORT || 4030);
  start(port).then(() => console.log(`voicebot-ccaas stub listening on http://127.0.0.1:${port}`))
    .catch((e) => { console.error(e.message); process.exit(1); });
}

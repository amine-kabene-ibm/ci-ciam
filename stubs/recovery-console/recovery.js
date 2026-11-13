'use strict';
// UC-03 recovery logic = the "CIAM recovery service" + the "agent-assisted channel" of IFC's main flow.
// Used by the web console (server.js) and by demo/uc03-recovery/run.js, so both behave the same.
//
// What Verify does (native): the hosted "Forgot password" e-mail link, the e-mail OTP, the password reset by an agent, ending sessions, and the events.
// What this stub adds (IFC-side logic, not a Verify feature [INFER]): reading Verify's signals, scoring the request low/high, choosing the route,
// the "verified caller" window, and the recovery case log. There is NO Verify risk engine behind the score: it is a handful of explicit rules.
const crypto = require('crypto');
const { BASE, createClient } = require('../../demo/lib/verify');

const IBM_EXT = 'urn:ietf:params:scim:schemas:extension:ibm:2.0:User';
const PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const NOTIFY = 'urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification';

// Same words for a known low-risk customer and for an unknown user name: the answer must not reveal whether the account exists.
const SELF_SERVICE_MSG = 'Use "Forgot password" on the sign-in page. If an account exists, we will e-mail a time-limited link to its registered address.';
const mask = (e) => String(e || '').replace(/^(.).*(@.*)$/, '$1***$2');
const lc = (s) => String(s || '').toLowerCase();

// ---- the risk rules: pure functions of the signals, so they can be tested with synthetic data ----
// signals = { locked, factors:[{id, createdMs}], attempts:[{timeMs, result, device, country, origin}], priorSuccesses:[...] }
// attempts = password sign-ins of this user inside the "recent" window, newest first; prior = successes strictly before each attempt.
function assess(signals, cfg, now = Date.now()) {
  const reasons = []; const info = [];
  const recentFactors = (signals.factors || []).filter((f) => f.createdMs && now - f.createdMs < cfg.recentFactorMs);
  if (recentFactors.length) {
    reasons.push({ code: 'RECENT_FACTOR_CHANGE', label: 'an authenticator was added recently', evidence: `${recentFactors.length} factor(s), newest ${Math.round((now - Math.max(...recentFactors.map((f) => f.createdMs))) / 1000)} s ago` });
  }
  const seenBefore = (a, pick) => (signals.history || []).some((h) => h.result === 'success' && h.timeMs < a.timeMs && pick(h) && pick(h) === pick(a));
  const hasBaseline = (a) => (signals.history || []).some((h) => h.result === 'success' && h.timeMs < a.timeMs);
  const newDevice = (signals.attempts || []).filter((a) => a.device && hasBaseline(a) && !seenBefore(a, (x) => x.device));
  if (newDevice.length) reasons.push({ code: 'NEW_DEVICE', label: 'recent sign-in attempts from a device never seen on a successful sign-in', evidence: `${newDevice.length} attempt(s), device "${String(newDevice[0].device).slice(0, 48)}"` });
  const newCountry = (signals.attempts || []).filter((a) => a.country && hasBaseline(a) && !seenBefore(a, (x) => x.country));
  if (newCountry.length) reasons.push({ code: 'NEW_GEOGRAPHY', label: 'recent sign-in attempts from a country never seen on a successful sign-in', evidence: `country ${newCountry[0].country}` });
  const newIp = (signals.attempts || []).filter((a) => a.origin && hasBaseline(a) && !seenBefore(a, (x) => x.origin));
  if (newIp.length) info.push({ code: 'NEW_NETWORK', label: 'attempts from an IP address not seen before (informational, not scored)', evidence: newIp[0].origin });
  if (!(signals.history || []).some((h) => h.result === 'success')) info.push({ code: 'NO_BASELINE', label: 'no earlier successful sign-in in the history window: device and country cannot be judged' });
  if (signals.locked) info.push({ code: 'LOCKED', label: 'the account is locked (the usual reason to recover; not scored)' });
  const level = reasons.length ? 'high' : 'low';
  return { level, score: reasons.length, reasons, info, route: level === 'high' ? 'assisted' : 'self-service' };
}

// cfg: { agentClientId, agentClientSecret, portalClientId, redirectUri, agentLabel, historyMs, recentAttemptMs, recentFactorMs, verifiedTtlSec }
function createRecoveryConsole(cfg) {
  const agent = createClient(cfg.agentClientId, cfg.agentClientSecret).api;
  const ttl = (cfg.verifiedTtlSec || 300) * 1000;
  const rcfg = { recentFactorMs: cfg.recentFactorMs || 24 * 3600 * 1000 };
  const trustedMs = () => cfg.trustedFactorMs || rcfg.recentFactorMs; // an authenticator younger than this is NOT accepted as proof of identity (read on every call)
  const cases = new Map();
  let seq = 0;

  async function findCustomer(userName) {
    const r = await agent('GET', '/v2.0/Users', {
      query: { filter: `userName eq "${String(userName).replace(/"/g, '')}"`, attributes: `id,userName,name,active,emails,meta,${IBM_EXT}:lastLogin,${IBM_EXT}:lastLoginType,${IBM_EXT}:pwdChangedTime,${IBM_EXT}:pwdAccountLockedTime` }, quiet: true,
    });
    if (r.status !== 200) return { error: `directory lookup failed: HTTP ${r.status}`, httpStatus: r.status, cid: r.cid };
    return { user: (r.data.Resources || [])[0] || null };
  }

  // Verify's events API keeps ~15-90 s of lag, ignores `search`/`filter` [LIVE], and caps a page at 1000: so read time windows and filter here.
  async function fetchEvents(fromMs, toMs) {
    const out = []; let to = toMs;
    for (let page = 0; page < 6; page++) {
      const r = await agent('GET', '/v1.0/events', { query: { range_type: 'time', from: fromMs, to, size: 1000, sort_order: 'desc' }, quiet: true });
      if (r.status !== 200) return { error: `events API: HTTP ${r.status}`, httpStatus: r.status, cid: r.cid };
      const evs = (((r.data || {}).response || {}).events || {}).events || [];
      out.push(...evs);
      if (evs.length < 1000) break;
      to = Number(evs[evs.length - 1].time) - 1;
    }
    return { events: out };
  }

  const isMine = (e, userName) => { const d = e.data || {}; return [d.username, d.target, d.targetid_username].some((x) => lc(x) === lc(userName)); };

  // Collect the signals Verify exposes for this customer. Nothing is typed by the agent.
  async function signals(userName) {
    const f = await findCustomer(userName);
    if (f.error) return f;
    if (!f.user) return { error: 'customer not found', httpStatus: 404 };
    const u = f.user; const x = u[IBM_EXT] || {};
    const t = await agent('GET', '/v2.0/factors/totp', { query: { search: `userId="${u.id}"` }, quiet: true });
    if (t.status !== 200) return { error: `factor list: HTTP ${t.status}`, httpStatus: t.status, cid: t.cid };
    const factors = ((t.data && t.data.totp) || []).map((z) => ({ id: z.id, type: 'totp', createdMs: Date.parse(z.created), validated: !!z.validated }));
    const now = Date.now();
    const ev = await fetchEvents(now - (cfg.historyMs || 6 * 3600 * 1000), now);
    if (ev.error) return ev;
    const pw = ev.events.filter((e) => e.event_type === 'authentication' && (e.data || {}).subtype === 'user_password' && isMine(e, userName))
      .map((e) => ({ timeMs: Number(e.time), result: e.data.result, device: e.data.devicetype || null, country: (e.geoip || {}).country_iso_code || null, origin: e.data.origin || null, city: (e.geoip || {}).city_name || null }));
    const attempts = pw.filter((a) => now - a.timeMs < (cfg.recentAttemptMs || 30 * 60 * 1000));
    return {
      user: { id: u.id, userName: u.userName, name: u.name && u.name.formatted, email: u.emails && u.emails[0] && u.emails[0].value, active: u.active },
      signals: {
        locked: !!x.pwdAccountLockedTime, lastLogin: x.lastLogin || null, pwdChangedTime: x.pwdChangedTime || null, factors,
        attempts, history: pw, eventsRead: ev.events.length,
      },
    };
  }

  // The customer starts recovery in the IFC portal. The customer only learns the route, never the reasons (an attacker must not learn what trips the rules).
  async function startRecovery(userName, opts = {}) {
    const id = `C${++seq}`;
    const c = { id, userName, openedAt: Date.now(), steps: [], verification: null, verifiedAt: null, used: false };
    const s = await signals(userName);
    if (s.error && s.httpStatus !== 404) return s;
    if (s.error) { // unknown name: same answer as for a normal customer (no user enumeration), nothing is stored
      return { public: { route: 'self-service', message: SELF_SERVICE_MSG, loginUrl: loginUrl() }, case: null };
    }
    c.userId = s.user.id; c.email = s.user.email; c.snapshot = s.signals;
    c.risk = assess(s.signals, rcfg);
    c.route = c.risk.route;
    note(c, 'recovery started', true, `risk=${c.risk.level} route=${c.route} reasons=${c.risk.reasons.map((r) => r.code).join(',') || 'none'}`);
    cases.set(id, c);
    const pub = c.route === 'assisted'
      ? { route: 'assisted', caseRef: id, message: 'For your security we need to verify your identity with an agent. Please call us and quote this reference.' }
      : { route: 'self-service', message: SELF_SERVICE_MSG, loginUrl: loginUrl() };
    return opts.full ? { public: pub, caseId: id, case: view(c) } : { public: pub, caseId: id };
  }

  function loginUrl() {
    return `${BASE}/v1.0/endpoint/default/authorize?` + new URLSearchParams({ client_id: cfg.portalClientId, response_type: 'code', redirect_uri: cfg.redirectUri, scope: 'openid', state: 'ifcdemo03state0001', nonce: 'ifcdemo03nonce0001' });
  }
  function note(c, step, ok, detail) { c.steps.push({ at: new Date().toISOString(), step, ok, detail: detail || null }); }
  function view(c) {
    return {
      id: c.id, userName: c.userName, openedAt: c.openedAt, route: c.route, risk: c.risk, email: mask(c.email),
      factors: (c.snapshot.factors || []).length, locked: c.snapshot.locked, lastLogin: c.snapshot.lastLogin,
      verified: !!c.verifiedAt && !c.used && Date.now() < c.verifiedAt + ttl, verifiedLeftSec: c.verifiedAt && !c.used ? Math.max(0, Math.round((c.verifiedAt + ttl - Date.now()) / 1000)) : null,
      used: c.used, steps: c.steps, verification: c.verification && { method: c.verification.method, correlation: c.verification.correlation, attempts: c.verification.attempts, state: c.verification.state },
      recentAttempts: (c.snapshot.attempts || []).slice(0, 6).map((a) => ({ time: new Date(a.timeMs).toISOString(), result: a.result, device: a.device, country: a.country, origin: a.origin })),
    };
  }
  const get = (id) => { const c = cases.get(id); return c ? { c } : { error: 'unknown case', httpStatus: 404 }; };

  // Which ways may the agent verify the caller? A factor added inside the "recent" window is NOT trusted (the attacker may have added it).
  function verificationOptions(id) {
    const g = get(id); if (g.error) return g;
    const all = (g.c.snapshot.factors || []).filter((f) => f.validated);
    const trusted = all.filter((f) => now() - f.createdMs >= trustedMs());
    const fresh = all.filter((f) => now() - f.createdMs < trustedMs());
    return { options: [
      { method: 'emailotp', to: mask(g.c.email), trusted: true, note: 'sent by Verify to the address ON FILE; the agent cannot change it' },
      ...(trusted.length ? [{ method: 'totp', trusted: true, note: 'authenticator enrolled before the recent-change window' }] : []),
      ...(fresh.length ? [{ method: 'totp', trusted: false, note: 'not offered: enrolled inside the recent-change window (the attacker may have added it)' }] : []),
    ] };
  }
  const now = () => Date.now();

  // Verify the caller: Verify e-mails a one-time code to the registered address; the caller reads it out to the agent.
  async function startVerification(id, method = 'emailotp') {
    const g = get(id); if (g.error) return g;
    const c = g.c;
    if (method === 'totp') { // the caller reads the code of an ESTABLISHED authenticator; nothing is sent
      const f = (c.snapshot.factors || []).find((x) => x.validated && now() - x.createdMs >= trustedMs());
      if (!f) return { error: 'no trusted authenticator: it was enrolled inside the recent-change window or does not exist', httpStatus: 409 };
      c.verification = { method: 'totp', factorId: f.id, attempts: 0, expiresAt: now() + 300000, state: 'ready' };
      note(c, 'verification by authenticator code started', true, 'authenticator enrolled before the recent-change window');
      return { verification: { method: 'totp', sentTo: null, correlation: null, expiresAt: new Date(c.verification.expiresAt).toISOString(), attemptsAllowed: 5 } };
    }
    const correlation = String(crypto.randomInt(1000, 10000));
    const o = await agent('POST', '/v2.0/factors/emailotp/transient/verifications', { body: { correlation, emailAddress: c.email }, quiet: true });
    if (o.status !== 201) return { error: `OTP not sent: HTTP ${o.status} ${(o.data && o.data.messageId) || ''}`, httpStatus: 502, cid: o.cid };
    c.verification = { method: 'emailotp', txnId: o.data.id, correlation, attempts: 0, retries: o.data.retries, expiresAt: Date.parse(o.data.expiry) || now() + 300000, state: 'sent' };
    note(c, 'verification code sent to the address on file', true, `correlation ${correlation}, expires ${o.data.expiry}`);
    return { verification: { method: 'emailotp', correlation, sentTo: mask(c.email), expiresAt: o.data.expiry, attemptsAllowed: o.data.retries + 1, sentMs: o.ms, cid: o.cid } };
  }
  async function confirmVerification(id, code) {
    const g = get(id); if (g.error) return g;
    const c = g.c; const v = c.verification;
    if (!v || v.state === 'locked') return { error: v ? 'too many wrong codes: start a new verification' : 'no verification started', httpStatus: 409 };
    if (now() > v.expiresAt) { v.state = 'expired'; return { error: 'code expired: start a new verification', httpStatus: 410 }; }
    if (v.method === 'totp') {
      const t = await agent('POST', `/v2.0/factors/totp/${v.factorId}`, { body: { otp: String(code || '').replace(/\D/g, '') }, quiet: true });
      v.attempts++;
      if (t.status === 204) { v.state = 'verified'; c.verifiedAt = now(); note(c, 'caller verified', true, `authenticator code, after ${v.attempts} attempt(s)`); return { verified: { ttlSec: ttl / 1000, attempts: v.attempts, cid: t.cid } }; }
      if (v.attempts >= 5) v.state = 'locked';
      note(c, 'verification failed', false, (t.data && t.data.messageId) || `HTTP ${t.status}`);
      return { error: 'wrong code', httpStatus: 401, verifyMessageId: (t.data && t.data.messageId) || null, cid: t.cid };
    }
    const digits = String(code || '').includes('-') ? String(code).split('-').pop().replace(/\D/g, '') : String(code || '').replace(/\D/g, '');
    const r = await agent('POST', `/v2.0/factors/emailotp/transient/verifications/${v.txnId}`, { body: { otp: digits }, quiet: true });
    v.attempts++;
    if (r.status === 204) { v.state = 'verified'; c.verifiedAt = now(); note(c, 'caller verified', true, `after ${v.attempts} attempt(s)`); return { verified: { ttlSec: ttl / 1000, attempts: v.attempts, cid: r.cid } }; }
    const mid = r.data && r.data.messageId;
    if (mid === 'CSIBN0080E') v.state = 'locked';
    note(c, 'verification failed', false, mid || `HTTP ${r.status}`);
    return { error: 'wrong code', httpStatus: 401, verifyMessageId: mid || null, cid: r.cid };
  }

  function requireVerified(id) {
    const g = get(id); if (g.error) return g;
    const c = g.c;
    if (!c.verifiedAt) return { error: 'caller is not verified: the agent cannot reset the password yet', httpStatus: 403 };
    if (c.used) return { error: 'this verification was already used for a reset: verify again', httpStatus: 403 };
    if (now() > c.verifiedAt + ttl) return { error: 'verification window has ended: verify the caller again', httpStatus: 403 };
    return { c };
  }

  // Agent action: reset the password (Verify generates a temporary one and e-mails it to the address on file; the agent never sees it),
  // then end every active session. [LIVE] the reset alone leaves an already-issued access token active; DELETE sessions is what kills it.
  async function resetAndEndSessions(id) {
    const g = requireVerified(id); if (g.error) return g;
    const c = g.c;
    const r = await agent('PATCH', `/v2.0/Users/${c.userId}/passwordResetter`, {
      body: { schemas: [PATCH_OP], operations: [{ op: 'replace', value: { password: 'auto-generate', [NOTIFY]: { notifyType: 'EMAIL', notifyPassword: true, notifyManager: false } } }] }, quiet: true,
    });
    if (r.status !== 204) { note(c, 'password reset', false, `HTTP ${r.status}`); return { error: `reset failed: HTTP ${r.status}`, httpStatus: 502, cid: r.cid }; }
    const s = await agent('DELETE', `/v1.0/auth/sessions/${c.userId}`, { quiet: true });
    c.used = true;
    note(c, 'password reset + sessions ended', s.status === 204, `reset ${r.status}, sessions ${s.status}; temporary password e-mailed to ${mask(c.email)}`);
    return { reset: { httpStatus: r.status, cid: r.cid, sessionsHttpStatus: s.status, sessionsCid: s.cid, notified: `e-mail to ${mask(c.email)}`, mustChangePassword: true } };
  }

  // Audit trail = Verify's events for this customer (who/what/when/from where) + the recovery case log kept by this console.
  async function audit({ userName, sinceMs }) {
    const ev = await fetchEvents(sinceMs || now() - 30 * 60 * 1000, now());
    if (ev.error) return ev;
    const rows = [];
    for (const e of ev.events) {
      if (!isMine(e, userName)) continue;
      const d = e.data || {};
      let kind = `${e.event_type}${d.subtype ? '/' + d.subtype : ''}${d.action ? ' ' + d.action : ''}`;
      if (e.event_type === 'management' && d.resource === 'user' && d.action === 'reset password') kind = 'agent password reset';
      rows.push({
        time: new Date(Number(e.time)).toISOString(), type: e.event_type, kind, result: d.result || null, messageId: d.messageid || null,
        cause: d.cause ? String(d.cause).replace(/user "[^"]*"/, 'the user') : null, by: d.performedby_clientname || d.client_name || null,
        origin: d.origin || null, country: (e.geoip || {}).country_iso_code || null, city: (e.geoip || {}).city_name || null, device: d.devicetype ? String(d.devicetype).slice(0, 60) : null,
      });
    }
    rows.sort((a, b) => (a.time < b.time ? 1 : -1));
    return { audit: { rows, eventsRead: ev.events.length, cases: [...cases.values()].filter((c) => lc(c.userName) === lc(userName)).map(view) } };
  }

  return { findCustomer, signals, startRecovery, verificationOptions, startVerification, confirmVerification, resetAndEndSessions, audit, fetchEvents, caseView: (id) => (cases.get(id) ? view(cases.get(id)) : null), allCases: () => [...cases.values()].map(view), loginUrl };
}

module.exports = { createRecoveryConsole, assess, IBM_EXT, mask };

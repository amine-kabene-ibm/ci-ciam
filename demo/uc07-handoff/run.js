'use strict';
// UC-07 scenario runner: the customer signs in to the "mobile app" and is handed to the voicebot, against the REAL Verify tenant.
//   node demo/uc07-handoff/run.js
// Evidence (status codes, ids, timings; never secrets, tokens or codes): demo/out/uc07.json
const axios = require('axios');
const { evidence, sleep, createClient, oauthClient, api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const stub = require('../../stubs/voicebot-ccaas/server');
const be = require('../../stubs/voicebot-ccaas/backends');
const c = require('./common');

const ev = evidence('uc07');
const results = [];

(async () => {
  const st = c.state.read();
  if (!st) { console.error('Run setup first: node demo/uc07-handoff/setup.js'); process.exit(1); }
  const ccaas = c.ccaasApi(st);
  const server = await stub.start(0, ccaas, c.handoffConfig(st));
  // A second voicebot whose policy says "an app login older than 'now' no longer skips the check" (scenario F)
  const strict = await stub.start(0, ccaas, c.handoffConfig(st, { maxAppAuthAgeSec: -1 }));
  const mk = (srv) => axios.create({ baseURL: `http://127.0.0.1:${srv.address().port}`, validateStatus: () => true });
  const http = mk(server); const httpStrict = mk(strict);
  const call = async (h, method, p, body) => { const t0 = Date.now(); const r = await h.request({ method, url: p, data: body }); return { status: r.status, data: r.data, ms: Date.now() - t0 }; };
  const post = (p, b) => call(http, 'post', p, b);
  await http.post('/reset');

  const record = (scenario, title, r, expectStatus, extra = {}) => {
    const pass = r.status === expectStatus;
    results.push({ scenario, title, pass });
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${title}  -> HTTP ${r.status}${pass ? '' : ` (expected ${expectStatus})`}`);
    if (r.data && r.data.say) console.log(`    BOT: ${r.data.say}`);
    ev.step(`${scenario}: ${title}`, { pass, httpStatus: r.status, expected: expectStatus, ms: r.ms, error: r.data && r.data.error, ...extra });
    return r;
  };
  const check = (scenario, title, pass, extra = {}) => {
    results.push({ scenario, title, pass });
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${title}`);
    ev.step(`${scenario}: ${title}`, { pass, ...extra });
  };
  const verifyCalls = async (h, callId, scenario) => {
    const t = (await h.get(`/transcript/${callId}`)).data;
    ev.step(`${scenario}: Verify calls made by the CCaaS`, { verifyCalls: t.verifyCalls, bridge: t.bridge });
    return t;
  };
  const login = async (label) => {
    const l = await c.appLogin(st);
    ev.step(`${label}: customer signs in to the mobile app (password grant on the app client)`, { httpStatus: l.status, ms: l.ms, cid: l.cid, amr: l.amr, expiresIn: l.expiresIn });
    if (!l.accessToken) throw new Error(`app login failed: HTTP ${l.status} cid=${l.cid}`);
    return l;
  };

  // ---- A. the hand-off: no questions asked for tier 1 ----------------------------------------------------------
  console.log('\nA. Customer signed in to the app taps "Speak with a Voicebot": no OTP, tier-1 requests answered');
  const lA = await login('A');
  console.log(`    app login: methods used (amr) = ${JSON.stringify(lA.amr)}, ${lA.ms} ms`);
  const hA = record('A', 'hand-off: Verify validates the app token, call is bridged to the app session', await post('/handoff', { accessToken: lA.accessToken }), 200);
  const callA = hA.data.callId;
  check('A', 'bot greets the customer by name without any security question', hA.data.handedOff === true && /Marie/.test(hA.data.say || '') && !/code|policy number/i.test(hA.data.say));
  check('A', 'app login methods (amr) are carried to the contact centre', Array.isArray(hA.data.bridge && hA.data.bridge.amr) && hA.data.bridge.amr.includes('password'), { amr: hA.data.bridge && hA.data.bridge.amr });
  const vt = hA.data.bridge.voiceToken;
  check('A', 'RFC 8693 token exchange issued a short-lived voice-channel token for the same subject', vt.active === true && vt.sameSubject === true && vt.ttlSec <= c.VOICE_TOKEN_TTL_SEC && vt.grantType === 'urn:ietf:params:oauth:grant-type:token-exchange', { voiceToken: vt });
  const bill = record('A', 'what is my outstanding bill amount (Billing API) - no OTP asked', await post('/transaction', { callId: callA, action: 'outstanding_bill' }), 200);
  record('A', 'renewal date (Policy API)', await post('/transaction', { callId: callA, action: 'renewal_date' }), 200);
  record('A', 'e-mail me my proof of insurance / pink slip (Client 360 API)', await post('/transaction', { callId: callA, action: 'proof_of_insurance' }), 200);
  record('A', 'put my car in storage (Policy-change API)', await post('/transaction', { callId: callA, action: 'storage' }), 200);
  check('A', 'billing answer is for THIS customer (matches the mock back end)', !!bill.data.result && bill.data.result.outstanding === c.customer.billing.outstanding);
  const agentA = (await http.get(`/agent/${callA}`)).data;
  check('A', 'agent screen-pop: AUTHENTICATED by mobile app session, bridge alive', agentA.authentication.status === 'AUTHENTICATED' && agentA.authentication.by === 'mobile app session' && agentA.authentication.sessionBridgeAlive === true, { agent: agentA });
  const tA = await verifyCalls(http, callA, 'A');
  check('A', 'no OTP or TOTP call was made for this customer', !tA.verifyCalls.some((x) => /OTP|TOTP attempt|challenge/i.test(x.op) && !/enrolment/.test(x.op)));

  // ---- B. sensitive request: step-up is still enforced ---------------------------------------------------------
  console.log('\nB. Sensitive request is NOT covered by the hand-off: step-up is still enforced');
  record('B', 'change my e-mail (app session only)', await post('/transaction', { callId: callA, action: 'change_email', newEmail: 'new.address@example.com' }), 403);
  record('B', 'step-up: choose authenticator-app code', await post('/stepup', { callId: callA, method: 'totp', action: 'change_email' }), 200);
  record('B', 'step-up with a wrong code is rejected', await post('/stepup/verify', { callId: callA, code: c.player.wrong() }), 401);
  let su = await c.player.next();
  let suR = await post('/stepup/verify', { callId: callA, code: su.code });
  for (let i = 0; suR.status === 429 && i < 6; i++) { // lockout caused by the wrong code just above [LIVE, see UC-06]
    console.log('    (TOTP temporarily locked by Verify after the wrong code: waiting 20 s)');
    await sleep(20000);
    su = await c.player.next();
    suR = await post('/stepup/verify', { callId: callA, code: su.code });
  }
  record('B', 'step-up with the right code', suR, 200);
  record('B', 'change my e-mail now succeeds', await post('/transaction', { callId: callA, action: 'change_email', newEmail: 'new.address@example.com' }), 200);
  record('B', 'a SECOND sensitive request needs a NEW step-up', await post('/transaction', { callId: callA, action: 'change_bank_account' }), 403);
  record('B', 'push is offered only when a phone is registered: none here, so the bot says so', await post('/stepup', { callId: callA, method: 'push', action: 'change_bank_account' }), 409);
  await verifyCalls(http, callA, 'B');

  // ---- C. invalid or untrusted tokens are refused ---------------------------------------------------------------
  console.log('\nC. Bad tokens are refused and the caller falls back to normal verification');
  record('C', 'no token', await post('/handoff', {}), 400);
  record('C', 'garbage token', await post('/handoff', { accessToken: 'not-a-real-token' }), 401);
  const lC = await login('C');
  record('C', 'tampered token (last character changed)', await post('/handoff', { accessToken: lC.accessToken.slice(0, -1) + (lC.accessToken.endsWith('A') ? 'B' : 'A') }), 401);
  // a valid, active token that did not come from the app: the voice-channel token itself must not be replayable as an app token
  const xC = await oauthClient(st.sts.clientId, st.sts.secret).exchange(lC.accessToken);
  record('C', 'a valid voice-channel (token-exchange) token replayed as an app token', await post('/handoff', { accessToken: xC.data.access_token }), 401);
  // a valid, active token from a client that is not one of the Intact apps (the CCaaS' own STS exchange is one; use the STS client token for the app)
  const other = await oauthClient(st.sts.clientId, st.sts.secret).introspect(xC.data.access_token);
  check('C', 'that replayed token is ACTIVE at Verify but refused by policy (untrusted client / grant)', other.data.active === true, { introspect: { status: other.status, cid: other.cid } });
  await oauthClient(st.app.clientId, st.app.clientSecret).revoke(lC.accessToken);
  await oauthClient(st.sts.clientId, st.sts.secret).revoke(xC.data.access_token);

  // ---- D. the bridge dies with the app session -----------------------------------------------------------------
  console.log('\nD. Customer signs out of the app: the voice session bridge drops immediately');
  const lD = await login('D');
  const hD = record('D', 'hand-off', await post('/handoff', { accessToken: lD.accessToken }), 200);
  const callD = hD.data.callId;
  record('D', 'tier-1 request works while the app session is alive', await post('/transaction', { callId: callD, action: 'outstanding_bill' }), 200);
  const t0 = Date.now();
  const rev = await oauthClient(st.app.clientId, st.app.clientSecret).revoke(lD.accessToken);
  ev.step('D: app signs out (token revocation)', { httpStatus: rev.status, cid: rev.cid, ms: rev.ms });
  check('D', 'token revocation accepted (200)', rev.status === 200);
  const rD = record('D', 'next request after sign-out is refused', await post('/transaction', { callId: callD, action: 'outstanding_bill' }), 401);
  const secondsToDrop = (Date.now() - t0) / 1000;
  check('D', `refusal was immediate (${secondsToDrop.toFixed(1)} s after revocation)`, secondsToDrop < 10 && rD.data.error === 'app_session_ended', { secondsAfterRevocation: secondsToDrop });
  const agentD = (await http.get(`/agent/${callD}`)).data;
  check('D', 'agent screen-pop now shows NOT AUTHENTICATED', agentD.authentication.status === 'NOT AUTHENTICATED', { agent: agentD });
  const xD = await oauthClient(st.sts.clientId, st.sts.secret).exchange(lD.accessToken);
  check('D', 'a REVOKED app token cannot be exchanged for a voice-channel token (400)', xD.status === 400 && !(xD.data && xD.data.access_token), { httpStatus: xD.status, cid: xD.cid });
  const tD = await verifyCalls(http, callD, 'D');
  check('D', 'bridge end is recorded with its reason', !!(tD.bridge && tD.bridge.endedBecause), { endedBecause: tD.bridge && tD.bridge.endedBecause });
  record('D', 'a revoked app token cannot be exchanged for a new voice-channel token', await call(http, 'post', '/handoff', { accessToken: lD.accessToken }), 401);

  // ---- E. account deactivated while on the call ----------------------------------------------------------------
  console.log('\nE. Broker/customer account deactivated (SCIM) during the call: bridge drops');
  const lE = await login('E');
  const hE = record('E', 'hand-off', await post('/handoff', { accessToken: lE.accessToken }), 200);
  const callE = hE.data.callId;
  const patch = (active) => api('PATCH', `/v2.0/Users/${st.user.id}`, {
    body: { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'active', value: active }] },
  });
  const tE0 = Date.now();
  const dE = await patch(false);
  check('E', 'SCIM PATCH active=false accepted (204)', dE.status === 204, { httpStatus: dE.status, cid: dE.cid });
  const rE = record('E', 'next request is refused', await post('/transaction', { callId: callE, action: 'outstanding_bill' }), 401);
  check('E', `refusal was immediate (${((Date.now() - tE0) / 1000).toFixed(1)} s after deactivation)`, rE.data.error === 'app_session_ended' && Date.now() - tE0 < 10000, { seconds: (Date.now() - tE0) / 1000 });
  const loginWhileOff = await c.appLogin(st);
  check('E', 'a new app login is refused while the account is deactivated', loginWhileOff.status !== 200, { httpStatus: loginWhileOff.status });
  const aE = await patch(true);
  check('E', 'account re-activated (204) so the demo can continue', aE.status === 204, { httpStatus: aE.status });
  await verifyCalls(http, callE, 'E');

  // ---- F. policy: an old app login does not skip the check -----------------------------------------------------
  console.log('\nF. Policy: an app login that is too old does not skip verification');
  const lF = await login('F');
  const hF = record('F', 'hand-off against a voicebot whose policy allows no app-login age', await call(httpStrict, 'post', '/handoff', { accessToken: lF.accessToken }), 200);
  check('F', 'not handed off: the bot falls back to a code (e-mail or authenticator app)', hF.data.handedOff === false && hF.data.reason === 'app_login_too_old' && hF.data.methods.includes('email_otp'));
  record('F', 'tier-1 request is refused until the caller verifies', await call(httpStrict, 'post', '/transaction', { callId: hF.data.callId, action: 'outstanding_bill' }), 401);
  await oauthClient(st.app.clientId, st.app.clientSecret).revoke(lF.accessToken);

  // ---- G. phone-first caller keeps working (UC-06 path) --------------------------------------------------------
  console.log('\nG. A caller who did NOT come from the app still gets the UC-06 verification');
  const callG = (await post('/call', {})).data.callId;
  record('G', 'phone call: identify by policy number', await post('/identify', { callId: callG, policyNumber: c.customer.policyNumber }), 200);
  record('G', 'phone call: bill is refused before verification', await post('/transaction', { callId: callG, action: 'outstanding_bill' }), 401);

  // ---- H. least privilege --------------------------------------------------------------------------------------
  console.log('\nH. The voicebot identities are least-privilege');
  const cc = createClient(st.ccaas.clientId, st.ccaas.clientSecret).api;
  const denials = [
    ['API client cannot create users', await cc('POST', '/v2.0/Users', { body: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: 'ifc-demo-uc07-should-not-exist' }, quiet: true })],
    ['API client cannot delete users', await cc('DELETE', `/v2.0/Users/${st.user.id}`, { quiet: true })],
    ['API client cannot list API clients', await cc('GET', '/v1.0/apiclients', { quiet: true })],
  ];
  for (const [t, r] of denials) check('H', t, r.status === 403, { httpStatus: r.status, cid: r.cid });
  const stsApi = oauthClient(st.sts.clientId, st.sts.secret);
  const wrong = await oauthClient(st.sts.clientId, 'wrong-secret').introspect('x');
  check('H', 'the STS client authenticates with its secret: a wrong secret is refused (401)', wrong.status === 401, { httpStatus: wrong.status, cid: wrong.cid });
  const fresh = await login('H');
  const direct = await stsApi.introspect(fresh.accessToken);
  check('H', 'introspection returns only what the voicebot needs (no secrets, no id token)', direct.status === 200 && direct.data.active === true && !('id_token' in direct.data) && !('access_token' in direct.data), { claims: Object.keys(direct.data || {}) });
  await oauthClient(st.app.clientId, st.app.clientSecret).revoke(fresh.accessToken);
  ev.step('H: entitlement counts', { ccaasClient: st.ccaas.entitlements.length, adminClient: 165, ccaasEntitlements: st.ccaas.entitlements });

  server.close(); strict.close();
  const failed = results.filter((r) => !r.pass);
  failed.forEach((r) => console.log(`  FAIL  ${r.scenario}: ${r.title}`));
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  console.log('evidence:', ev.save({ passed: results.length - failed.length, total: results.length }));
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

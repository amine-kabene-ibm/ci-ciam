'use strict';
// UC-06 scenario runner: plays the policyholder calling the voicebot, against the REAL Verify tenant.
//   node demo/uc06-voice/run.js            automated scenarios (no human needed)
//   node demo/uc06-voice/run.js --push     also runs the push step-up; needs a phone registered via enroll-phone.js [HUMAN]
// The stub is started in-process on a random port. Evidence (status codes, ids, timings, never secrets or codes):
//   demo/out/uc06.json
const axios = require('axios');
const { evidence, sleep, createClient } = require('../lib/verify');
const stub = require('../../stubs/voicebot-ccaas/server');
const be = require('../../stubs/voicebot-ccaas/backends');
const { state, customer, nextTotpCode, wrongTotp } = require('./common');

const withPush = process.argv.includes('--push');
const ev = evidence('uc06');
const results = [];

(async () => {
  if (!state.read()) { console.error('Run setup first: node demo/uc06-voice/setup.js'); process.exit(1); }
  const server = await stub.start(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  const http = axios.create({ baseURL: base, validateStatus: () => true });
  const post = async (p, body) => { const t0 = Date.now(); const r = await http.post(p, body); return { status: r.status, data: r.data, ms: Date.now() - t0 }; };
  await http.post('/reset');

  const say = (r) => (r.data && r.data.say ? `    BOT: ${r.data.say}` : '');
  const record = (scenario, title, r, expectStatus, extra = {}) => {
    const pass = r.status === expectStatus;
    results.push({ scenario, title, pass });
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${title}  -> HTTP ${r.status}${pass ? '' : ` (expected ${expectStatus})`}`);
    const s = say(r); if (s) console.log(s);
    ev.step(`${scenario}: ${title}`, { pass, httpStatus: r.status, expected: expectStatus, ms: r.ms, error: r.data && r.data.error, ...extra });
    return r;
  };
  const newCall = async () => { const r = await post('/call', {}); return r.data.callId; };
  const identifyAndTotp = async (callId, scenario) => {
    record(scenario, 'identify caller by policy number', await post('/identify', { callId, policyNumber: customer.policyNumber }), 200);
    record(scenario, 'challenge: authenticator-app code', await post('/challenge', { callId, method: 'totp' }), 200);
    let c = await nextTotpCode();
    let r = await post('/verify', { callId, code: c.code });
    // Verify counts wrong TOTP codes per enrolment over time and answers 429 CSIBN0081E for ~20-60 s [LIVE]. Scenario C submits a
    // deliberately wrong code, so a back-to-back re-run can start inside that lockout. Wait it out instead of failing.
    for (let i = 0; r.status === 429 && i < 6; i++) {
      console.log('    (TOTP temporarily locked by Verify from earlier wrong codes: waiting 20 s)');
      await sleep(20000);
      c = await nextTotpCode();
      r = await post('/verify', { callId, code: c.code });
    }
    return record(scenario, `verify tier 1 (TOTP, window ${c.offset >= 0 ? '+' : ''}${c.offset})`, r, 200);
  };
  const transcript = async (callId) => (await http.get(`/transcript/${callId}`)).data;
  const keepVerifyCalls = (t, scenario) => ev.step(`${scenario}: Verify calls made by the CCaaS`, { verifyCalls: t.verifyCalls });

  // ---- A. information query, document request, simple transaction: tier 1 only ---------------------------------
  console.log('\nA. Information query, document request and simple transaction (tier 1: one verified factor)');
  const callA = await newCall();
  await identifyAndTotp(callA, 'A');
  const bill = record('A', 'what is my outstanding bill amount (Billing API)', await post('/transaction', { callId: callA, action: 'outstanding_bill' }), 200);
  record('A', 'renewal date (Policy API)', await post('/transaction', { callId: callA, action: 'renewal_date' }), 200);
  record('A', 'e-mail me my proof of insurance / pink slip (Client 360 API)', await post('/transaction', { callId: callA, action: 'proof_of_insurance' }), 200);
  record('A', 'put my car in storage (Policy-change API)', await post('/transaction', { callId: callA, action: 'storage' }), 200);
  const billOk = !!bill.data.result && bill.data.result.outstanding === be.customers[0].billing.outstanding;
  results.push({ scenario: 'A', title: 'billing answer matches the mock back end', pass: billOk });
  ev.step('A: billing answer matches the mock back end', { pass: billOk });

  // ---- B. sensitive request without step-up is refused ---------------------------------------------------------
  console.log('\nB. Sensitive request WITHOUT step-up is refused');
  record('B', 'change my e-mail (same call, tier 1 only)', await post('/transaction', { callId: callA, action: 'change_email', newEmail: 'new.address@example.com' }), 403);

  // ---- C. step-up with a fresh authenticator-app code ----------------------------------------------------------
  console.log('\nC. Step-up with a NEW authenticator-app code, then the sensitive request succeeds once');
  record('C', 'step-up: choose authenticator-app code', await post('/stepup', { callId: callA, method: 'totp', action: 'change_email' }), 200);
  record('C', 'step-up with a wrong code is rejected', await post('/stepup/verify', { callId: callA, code: wrongTotp() }), 401);
  let su = await nextTotpCode();
  let suR = await post('/stepup/verify', { callId: callA, code: su.code });
  for (let i = 0; suR.status === 429 && i < 6; i++) { // lockout caused by the wrong code just above, see identifyAndTotp
    console.log('    (TOTP temporarily locked by Verify after the wrong code: waiting 20 s)');
    await sleep(20000);
    su = await nextTotpCode();
    suR = await post('/stepup/verify', { callId: callA, code: su.code });
  }
  record('C', 'step-up with the right code', suR, 200);
  record('C', 'change my e-mail now succeeds', await post('/transaction', { callId: callA, action: 'change_email', newEmail: 'new.address@example.com' }), 200);
  record('C', 'a SECOND sensitive request needs a NEW step-up', await post('/transaction', { callId: callA, action: 'change_bank_account' }), 403);
  keepVerifyCalls(await transcript(callA), 'A-C');

  // ---- D. push step-up -----------------------------------------------------------------------------------------
  console.log('\nD. Push step-up to the registered IBM Verify app');
  const callD = await newCall();
  await identifyAndTotp(callD, 'D');
  const pushTry = await post('/stepup', { callId: callD, method: 'push', action: 'change_bank_account' });
  if (pushTry.status === 409) {
    record('D', 'no phone registered: bot says so and offers another method [HUMAN must enrol a phone]', pushTry, 409, { humanStep: 'node demo/uc06-voice/enroll-phone.js' });
  } else if (!withPush) {
    console.log('  SKIP  a phone IS registered, but push approval needs a human. Re-run with --push to send the notification.');
    ev.step('D: push', { skipped: true, reason: 'phone registered; pass --push to send', httpStatus: pushTry.status });
  } else {
    record('D', 'push notification sent to the registered phone', pushTry, 202);
    console.log('    >>> APPROVE THE NOTIFICATION ON THE PHONE (120 s) <<<');
    let st2 = 'PENDING'; const t0 = Date.now();
    while (st2 === 'PENDING' && Date.now() - t0 < 125000) { await sleep(2000); st2 = (await http.get(`/stepup/status/${callD}`)).data.state; }
    const okPush = st2 === 'VERIFY_SUCCESS';
    results.push({ scenario: 'D', title: `push result ${st2}`, pass: okPush });
    console.log(`  ${okPush ? 'PASS' : 'FAIL'}  push result: ${st2} after ${Math.round((Date.now() - t0) / 1000)} s`);
    ev.step('D: push approval', { pass: okPush, state: st2, seconds: Math.round((Date.now() - t0) / 1000) });
    if (okPush) record('D', 'change bank account after push approval', await post('/transaction', { callId: callD, action: 'change_bank_account' }), 200);
  }
  keepVerifyCalls(await transcript(callD), 'D');

  // ---- E. wrong codes and lockout ------------------------------------------------------------------------------
  console.log('\nE. Wrong codes and lockout (the e-mail OTP is really sent by Verify to the presenter mailbox: one e-mail)');
  const callE = await newCall();
  record('E', 'identify caller', await post('/identify', { callId: callE, policyNumber: customer.policyNumber }), 200);
  const ch = record('E', 'challenge: e-mail OTP sent by Verify to the address ON FILE', await post('/challenge', { callId: callE, method: 'email_otp' }), 200);
  if (ch.status === 200) {
    // Verify allows 5 attempts per OTP (retries=4) [LIVE]: the 5th wrong code returns CSIBN0080E and the transaction is FAILED.
    for (let i = 1; i <= 5; i++) {
      const r = await post('/verify', { callId: callE, code: String(100000 + i * 7919).slice(0, 6) });
      if (i === 1) record('E', 'wrong e-mail code is rejected, attempts left reported', r, 401, { attemptsLeft: r.data.attemptsLeft });
      else if (i === 4) record('E', '4th wrong code still rejected (one attempt left)', r, 401, { attemptsLeft: r.data.attemptsLeft });
      else if (i === 5) record('E', '5th wrong code exhausts the OTP: call locked, hand over to an agent', r, 423, { verifyMessageId: r.data.verifyMessageId });
    }
    record('E', 'a locked call refuses everything', await post('/transaction', { callId: callE, action: 'outstanding_bill' }), 401);
  }
  keepVerifyCalls(await transcript(callE), 'E');

  // ---- F. identification failures ------------------------------------------------------------------------------
  console.log('\nF. Unknown policy numbers');
  const callF = await newCall();
  for (let i = 1; i <= 3; i++) record('F', `unknown policy number, attempt ${i}`, await post('/identify', { callId: callF, policyNumber: `AUTO-0000${i}` }), 404);
  record('F', 'call is locked after 3 misses', await post('/identify', { callId: callF, policyNumber: customer.policyNumber }), 423);
  record('F', 'transaction without verification is refused', await post('/transaction', { callId: await newCall(), action: 'outstanding_bill' }), 401);

  // ---- G. least privilege --------------------------------------------------------------------------------------
  console.log('\nG. The CCaaS API client is least-privilege');
  const st = state.read();
  const ccaas = createClient(st.ccaas.clientId, st.ccaas.clientSecret).api;
  const denials = [
    ['cannot create users', await ccaas('POST', '/v2.0/Users', { body: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: 'ifc-demo-uc06-should-not-exist' }, quiet: true })],
    ['cannot delete users', await ccaas('DELETE', `/v2.0/Users/${st.user.id}`, { quiet: true })],
    ['cannot list API clients', await ccaas('GET', '/v1.0/apiclients', { quiet: true })],
  ];
  for (const [t, r] of denials) {
    const pass = r.status === 403;
    results.push({ scenario: 'G', title: t, pass });
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  CCaaS client ${t}  -> HTTP ${r.status}`);
    ev.step(`G: CCaaS client ${t}`, { pass, httpStatus: r.status, cid: r.cid });
  }
  ev.step('G: entitlement counts', { ccaasClient: st.ccaas.entitlements.length, adminClient: 165, ccaasEntitlements: st.ccaas.entitlements });

  server.close();
  const failed = results.filter((r) => !r.pass);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  console.log('evidence:', ev.save({ passed: results.length - failed.length, total: results.length, pushRun: withPush }));
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });

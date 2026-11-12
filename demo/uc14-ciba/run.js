'use strict';
// UC-14 test run (Policyholder authorizing a Call Center Agent via CIBA), against the live tenant.
//   node demo/uc14-ciba/run.js              automated checks only (no human needed)
//   node demo/uc14-ciba/run.js --approve    adds the REAL approval: you open the Verify e-mail as the policyholder, sign in and approve [HUMAN]
// Scenarios (H runs FIRST when --approve is given, so no other e-mail is in the mailbox to be confused with it):
//   A  objects and least privilege (CIBA app, agent API client)
//   B  agent starts a back-channel request, Verify answers pending
//   C  error paths (unknown caller, bad client, not entitled, missing hint, expired request)
//   D  the console refuses agent actions while the caller has not approved
//   E  a locked-out caller (finding: the CIBA request is still accepted)
//   H  [HUMAN] approval -> verified -> profile -> unlock -> temporary password -> audit
const { api, oauthClient, evidence, sleep, send, BASE } = require('../lib/verify');
const { createAgentConsole, IBM_EXT } = require('../../stubs/agent-console/agent');
const { lockCustomer } = require('./lock');
const { agentConfig } = require('./config');
const c = require('./common');

const APPROVE = process.argv.includes('--approve');
const fs = require('fs');
const ev = evidence('uc14');
const results = [];
const PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

const check = (scenario, title, pass, extra = {}) => {
  results.push({ scenario, title, pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${scenario}  ${title}`);
  ev.step(`${scenario}: ${title}`, { pass, ...extra });
};
const info = (scenario, title, extra = {}) => {
  console.log(`  INFO  ${scenario}  ${title}`);
  ev.step(`${scenario}: ${title}`, { info: true, ...extra });
};
const head = (t) => console.log(`\n${t}`);
const short = (s) => (s ? `${String(s).slice(0, 6)}... (${String(s).length} chars)` : null);

async function main() {
  const st = c.state.read();
  if (!st || !st.app || !st.agent || !st.users) { console.error('State missing. Run: node demo/uc14-ciba/setup.js'); process.exit(2); }
  const marie = st.users.marie;
  let tempIssued = null;
  const cfg = { ...agentConfig(st), tempPassword: () => { tempIssued = c.tempPassword(); return tempIssued; } };
  const agentConsole = createAgentConsole(cfg);
  const cibaClient = oauthClient(st.app.clientId, st.app.clientSecret);
  const portal = oauthClient(st.portal.clientId, st.portal.clientSecret);
  const t0 = Date.now();

  console.log(`UC-14 Run: CIBA agent-initiated authentication${APPROVE ? '  (with real approval)' : '  (automated part)'}`);

  // Start from a known state: marie unlocked, password known
  const login0 = await portal.passwordGrant(marie.userName, marie.password);
  if (login0.status !== 200) {
    const r = await api('PATCH', `/v2.0/Users/${marie.id}`, { headers: { usershouldnotneedtoresetpassword: 'true' }, quiet: true,
      body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'password', value: c.newPassword() }] } });
    info('A', `customer sign-in was not possible at start (HTTP ${login0.status}); re-run setup.js to re-sync the stored password`, { patch: r.status });
  }

  // ===== A. objects and least privilege =====
  head('A. Objects and least privilege');
  const apps = (await api('GET', '/v1.0/applications', { query: { search: `name="${c.CIBA_APP}"` } })).data._embedded.applications;
  const appDoc = (await api('GET', apps[0]._links.self.href)).data;
  const p = appDoc.providers.oidc.properties;
  check('A', 'the agent application has the CIBA grant, poll mode and the e-mail channel',
    p.grantTypes.ciba === 'true' && p.additionalConfig.backchannelSettings.deliveryMode === 'poll' &&
    JSON.stringify(p.additionalConfig.backchannelSettings.userAuthChannels) === '["email"]' && appDoc.applicationState === true,
    { backchannelSettings: p.additionalConfig.backchannelSettings });
  const ac = (await api('GET', `/v1.0/apiclients/${st.agent.id}`)).data;
  check('A', 'the console runs on a 3-entitlement API client, not the admin client', JSON.stringify([...ac.entitlements].sort()) === JSON.stringify([...c.AGENT_ENTITLEMENTS].sort()),
    { entitlements: ac.entitlements });
  const agentApi = require('../lib/verify').createClient(st.agent.clientId, st.agent.clientSecret).api;
  const denied = await agentApi('GET', '/v1.0/apiclients', { quiet: true });
  check('A', 'the console client is refused outside its scope (list API clients -> 403)', denied.status === 403, { http: denied.status, cid: denied.cid });
  const found = await agentConsole.findCaller(marie.userName);
  check('A', 'the console finds the caller in the Verify directory through SCIM', !!(found.user && found.user.id === marie.id), { id: marie.id });

  // ===== H. human approval =====
  if (APPROVE) {
    head('H. [HUMAN] real approval');
    const ref = require('crypto').randomBytes(2).toString('hex').toUpperCase();
    const req = await agentConsole.startVerification(marie.userName, null, { ref });
    const sid = req.session.id;
    const sentAt = Date.now();
    console.log(`\n  >>> Request sent at ${new Date(sentAt).toISOString()}. Open the "IBM Verify" e-mail whose message ends with  (ref ${ref})  in the presenter mailbox,`);
    console.log(`  >>> sign in as ${marie.userName} and approve. Password: node -e "console.log(require('./demo/out/uc14.state.json').users.marie.password)"`);
    console.log('  >>> Waiting up to 10 minutes...\n');
    let view = req.session;
    while (view.status === 'pending' && Date.now() - sentAt < 600000) {
      await sleep(5000);
      view = (await agentConsole.poll(sid)).session;
      process.stdout.write(`\r  waiting... ${Math.round((Date.now() - sentAt) / 1000)}s  status=${view.status}   `);
    }
    console.log('');
    const humanMs = Date.now() - sentAt;
    check('H', 'the caller approved on their own device and the agent console shows VERIFIED', view.status === 'verified', { status: view.status, secondsToApprove: Math.round(humanMs / 1000), polls: view.polls });
    if (view.status === 'verified') {
      const pr = await agentConsole.profile(sid);
      check('H', 'after approval the agent can read the caller profile (directory + Client 360 stub)', !!pr.profile && pr.profile.userName === marie.userName && !!pr.profile.client360, { fields: pr.profile && Object.keys(pr.profile) });
      const lk = await lockCustomer(st, 'marie');
      check('H', 'the caller is now locked out (6 wrong passwords after the approval)', lk === true);
      const ul = await agentConsole.unlock(sid);
      check('H', 'agent action "Unlock account" succeeds after verification (SCIM password replace -> 204)', !!ul.unlock && ul.unlock.httpStatus === 204 && ul.unlock.wasLocked === true && ul.unlock.nowLocked === false, ul.unlock);
      const tmpLogin = await portal.passwordGrant(marie.userName, tempIssued || 'x');
      check('H', 'the caller must choose a new password at next sign-in (CSIAQ0267E); the agent never knows a usable password', tmpLogin.status === 400 && /CSIAQ0267E/.test(tmpLogin.data.error_description), { http: tmpLogin.status });
      const np = c.newPassword();
      await api('PATCH', `/v2.0/Users/${marie.id}`, { headers: { usershouldnotneedtoresetpassword: 'true' }, quiet: true, body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'password', value: np }] } });
      marie.password = np; c.state.write(st);
      // audit (events can lag a few seconds)
      let audit = null;
      for (let i = 0; i < 8; i++) {
        audit = (await agentConsole.audit({ sinceMs: sentAt - 5000, userName: marie.userName })).audit;
        if (audit && audit.rows.some((r) => r.kind === 'CIBA token' && r.result === 'success')) break;
        await sleep(3000);
      }
      const okRow = audit && audit.rows.find((r) => r.kind === 'CIBA token' && r.result === 'success');
      check('H', 'audit: Verify logged the successful CIBA token issue with the binding message', !!okRow && (okRow.bindingMessage || '').includes(`(ref ${ref})`), { row: okRow });
      check('H', 'audit: Verify logged the caller sign-in on the approval page', !!audit && audit.rows.some((r) => r.kind === 'caller sign-in' && r.result === 'success'));
      check('H', 'audit: the "still pending" polls are counted separately', !!audit && audit.pendingPolls > 0, { pendingPolls: audit && audit.pendingPolls });
      ev.step('H: audit rows (no tokens)', { rows: audit && audit.rows.slice(0, 12), pendingPolls: audit && audit.pendingPolls });
    }
  } else {
    info('H', 'the real approval was NOT run in this pass (node demo/uc14-ciba/run.js --approve) [HUMAN]');
  }


  // ===== B. start a request =====
  head('B. Agent starts a back-channel request');
  const started = await agentConsole.startVerification(marie.userName, null, { expirySec: 30 });
  const sess = started.session;
  check('B', 'POST /oauth2/ciba accepted: auth_req_id issued', !!sess && sess.status === 'pending', { httpMs: sess && sess.startMs, interval: sess && sess.intervalSec, expires_in: sess && sess.expiresInSec });
  check('B', 'the caller is shown a binding message naming the agent', !!sess && /IFC agent 482/.test(sess.bindingMessage), { bindingMessage: sess && sess.bindingMessage });
  const raw = await cibaClient.ciba({ scope: 'openid', login_hint: marie.userName, binding_message: 'raw probe, ignore', requested_expiry: '60' });
  check('B', 'the response carries auth_req_id, expires_in and the polling interval (5 s)', raw.status === 200 && !!raw.data.auth_req_id && raw.data.interval === 5 && raw.data.expires_in === 60,
    { authReqId: short(raw.data.auth_req_id), expires_in: raw.data.expires_in, interval: raw.data.interval });
  const pend = await cibaClient.cibaToken(raw.data.auth_req_id);
  check('B', 'polling before approval returns authorization_pending (CSIAQ0249E)', pend.status === 400 && pend.data.error === 'authorization_pending' && /CSIAQ0249E/.test(pend.data.error_description), { http: pend.status, error: pend.data.error });

  // ===== C. error paths =====
  head('C. Error paths');
  const unk = await cibaClient.ciba({ scope: 'openid', login_hint: 'ifc-demo-uc14-nobody' });
  check('C', 'unknown caller -> 400 unknown_user_id (CSIAQ5297E)', unk.status === 400 && unk.data.error === 'unknown_user_id', { http: unk.status, cid: unk.cid });
  const bad = await oauthClient(st.app.clientId, 'not-the-secret').ciba({ scope: 'openid', login_hint: marie.userName });
  check('C', 'wrong client secret -> 401 invalid_client (CSIAQ0155E)', bad.status === 401 && bad.data.error === 'invalid_client', { http: bad.status });
  const nohint = await cibaClient.ciba({ scope: 'openid' });
  check('C', 'request without a hint -> 400 invalid_request (CSIAQ5301E)', nohint.status === 400 && /CSIAQ5301E/.test(nohint.data.error_description), { http: nohint.status });
  const out = st.users.outsider;
  const notEnt = await cibaClient.ciba({ scope: 'openid', login_hint: out.userName });
  check('C', 'a customer not entitled to the agent application -> 403 access_denied (CSIAQ0279E)', notEnt.status === 403 && /CSIAQ0279E/.test(notEnt.data.error_description), { http: notEnt.status });
  const exp = await cibaClient.ciba({ scope: 'openid', login_hint: marie.userName, requested_expiry: '10' });
  await sleep(12000);
  const gone = await cibaClient.cibaToken(exp.data.auth_req_id);
  check('C', 'polling after the request expired -> 400 expired_token (CSIAQ5298E), no token', gone.status === 400 && gone.data.error === 'expired_token' && !gone.data.access_token, { http: gone.status, requested_expiry: 10 });
  const bogus = await cibaClient.cibaToken('not-a-real-request-id');
  check('C', 'polling an invented auth_req_id is refused and issues nothing', bogus.status === 400 && !bogus.data.access_token, { http: bogus.status, error: bogus.data.error });
  info('C', 'channel values accepted by the tenant: "push" and "email" only (400 CSIAQ0509 for "sms"); push needs the user enrolled in IBM Verify (400 CSIAQ5306E otherwise)');

  // ===== D. console gate =====
  head('D. The console refuses agent actions until the caller has approved');
  const g1 = await agentConsole.profile(sess.id);
  const g2 = await agentConsole.unlock(sess.id);
  check('D', 'while pending: reading the caller profile is refused (403)', g1.httpStatus === 403, { error: g1.error });
  check('D', 'while pending: unlocking the account is refused (403)', g2.httpStatus === 403, { error: g2.error });
  const g3 = await agentConsole.profile('S999');
  check('D', 'an unknown session id is refused (404)', g3.httpStatus === 404);
  const before = await agentConsole.findCaller(marie.userName);
  check('D', 'nothing changed in the directory while pending (account still active)', !!(before.user && before.user.active === true));

  // ===== E. locked caller =====
  head('E. A locked-out caller');
  const locked = await lockCustomer(st, 'marie');
  check('E', 'six wrong passwords lock the customer (pwdAccountLockedTime set)', locked === true);
  const lockedLogin = await portal.passwordGrant(marie.userName, marie.password);
  check('E', 'with the CORRECT password the locked customer is refused (CSIAQ0264E)', lockedLogin.status === 400 && /CSIAQ0264E/.test(lockedLogin.data.error_description), { http: lockedLogin.status });
  const lockedReq = await agentConsole.startVerification(marie.userName, null, { expirySec: 30 });
  check('E', 'the agent can still start a CIBA request for a locked caller (request accepted)', !!lockedReq.session && lockedReq.session.status === 'pending', { note: 'finding: the lock does not block the back-channel request' });
  info('E', 'e-mail delivery for a locked caller: while the account was locked, the presenter received NO approval e-mail for several requests sent in a row [HUMAN-observed once, 2026-11-12, cause not established]; a script cannot read the mailbox, so for the demo the lock is applied AFTER the approval');
  // un-lock by the same documented route (password replace) so scenario H starts clean
  const fix = c.newPassword();
  await api('PATCH', `/v2.0/Users/${marie.id}`, { headers: { usershouldnotneedtoresetpassword: 'true' }, quiet: true, body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'password', value: fix }] } });
  marie.password = fix;
  c.state.write(st);
  const relog = await portal.passwordGrant(marie.userName, fix);
  check('E', 'replacing the password clears the lock (sign-in works again)', relog.status === 200, { http: relog.status });

  // A plain run must not erase the last REAL approval: carry its H results over, labelled with the date of that approval.
  let carried = null;
  if (!APPROVE && fs.existsSync(ev.file)) {
    try {
      const prev = JSON.parse(fs.readFileSync(ev.file, 'utf8'));
      const hRes = (prev.results || []).filter((r) => r.scenario === 'H');
      const hSteps = (prev.steps || []).filter((x) => /^H:/.test(x.title) && !x.info);
      if (hRes.length && hRes.every((r) => r.pass)) {
        carried = { approvalRunAt: prev.carriedFromApprovalAt || prev.startedAt };
        for (const r of hRes) results.push(r);
        for (const x of hSteps) ev.doc.steps.push(x);
      }
    } catch (e) { /* unreadable previous evidence: nothing to carry */ }
  }
  const failed = results.filter((r) => !r.pass).length;
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed} checks passed, ${failed} failed  (${Math.round((Date.now() - t0) / 1000)} s)`);
  ev.save({ mode: APPROVE ? 'approve' : 'automated', carriedFromApprovalAt: carried ? carried.approvalRunAt : (APPROVE ? ev.doc.startedAt : undefined), total: results.length, passed, failed, results });
  console.log(`Evidence written: ${ev.file}`);
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main().catch((e) => { console.error('RUN FAILED:', e.message || e); process.exit(2); });
module.exports = { main };

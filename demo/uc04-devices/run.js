'use strict';
// UC-04 test run (trusted devices, push, self-service revoke), against the live tenant, with a SIMULATED IBM Verify app (demo/lib/verifyDevice.js).
//   node demo/uc04-devices/run.js
// The simulated phone does what the app does after a QR scan and when a push arrives (register, enrol the approval key, poll, sign, answer).
// It is NOT a real phone: no APNs/FCM delivery, no Face ID. Those stay [HUMAN] (enroll-phone.js).
// Scenarios:
//   A  objects and the back-end device service's least privilege
//   B  "Register Device": the customer registers TWO trusted devices with their own token (iPhone + Android)
//   C  push confirmation after registration (IFC main flow)
//   D  push approve / deny / fraud, with the location in the message, and device latency
//   E  hosted sign-in with 2 devices: choose the device, approve -> code; deny -> refused
//   F  security: wrong key, replay, other device, expiry, another customer
//   G  disable / re-enable a device (fraud response)
//   H  self-service revoke: push refused, sign-in offers only the remaining device
//   I  IFC's own branded app: authenticator client
//   J  several devices per user (limit probe) and least-privilege matrix
//   K  audit trail (events API)
const crypto = require('crypto');
const http = require('http');
const { api, createClient, evidence, send, BASE, sleep } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { Browser } = require('../uc08-sso/browser');
const { VerifyDevice, call } = require('../lib/verifyDevice');
const { createDeviceService, PUSH_BODY } = require('../../stubs/device-portal/devices');
const c = require('./common');

const ev = evidence('uc04');
const results = [];
const check = (scenario, title, pass, extra = {}) => {
  results.push({ scenario, title, pass: !!pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${scenario}  ${title}`);
  ev.step(`${scenario}: ${title}`, { pass: !!pass, ...extra });
};
const info = (scenario, title, extra = {}) => { console.log(`  INFO  ${scenario}  ${title}`); ev.step(`${scenario}: ${title}`, { info: true, ...extra }); };
const head = (t) => console.log(`\n${t}`);
const DEV_Q = { filter: 'id,creationTime,transactionData', search: 'state="PENDING"', sort: '-creationTime' }; // what the app sends when it lists pending requests
const has = (r, code) => JSON.stringify((r && (r.data || r.error)) || '').includes(code);

async function main() {
  const st = c.state.read();
  if (!st || !st.users || !st.service || !st.console || !st.login) { console.error('State missing. Run: node demo/uc04-devices/setup.js'); process.exit(2); }
  const t0 = Date.now();
  const marie = st.users.marie; const olivier = st.users.olivier;
  const asCustomer = (u) => createDeviceService({ userName: u.userName, password: u.password, consoleClientId: st.console.clientId, consoleClientSecret: st.console.clientSecret });
  const mine = asCustomer(marie);   // the signed-in customer (mobile app / portal) = her own token, no admin rights
  const theirs = asCustomer(olivier);
  const svcClient = createClient(st.service.clientId, st.service.clientSecret);
  const adminFor = (owner) => createDeviceService({ owner, request: (m, p, b, q) => svcClient.api(m, p, { body: b, query: q, quiet: true }) });
  const svc = adminFor(marie.id); // the back-end device service acting for Marie

  // the redirect_uri of the login app: a tiny listener so the scripted browser stops at the callback
  const listener = http.createServer((q, r) => r.end('ok')).listen(c.CALLBACK_PORT, '127.0.0.1');
  console.log('UC-04 Run: trusted devices, push, self-service revoke  (simulated IBM Verify app)');

  try {
    // start clean: no device left from an earlier run
    for (const u of [marie, olivier]) {
      const l = await adminFor(u.id).list();
      for (const d of l.devices || []) await adminFor(u.id).revoke(d.id);
    }

    // ===== A. objects and least privilege =====
    head('A. Objects and least privilege');
    const ac = (await api('GET', `/v1.0/apiclients/${st.service.id}`)).data;
    check('A', 'the device service runs on a 5-entitlement API client, not the admin client', JSON.stringify([...ac.entitlements].sort()) === JSON.stringify([...c.SERVICE_ENTITLEMENTS].sort()), { entitlements: ac.entitlements });
    const denied = await svcClient.api('GET', '/v1.0/apiclients', { quiet: true });
    check('A', 'the device service is refused outside its scope (list API clients -> 403)', denied.status === 403, { http: denied.status, cid: denied.cid });
    const scim = await svcClient.api('GET', '/v2.0/Users', { query: { count: 1 }, quiet: true });
    check('A', 'the device service cannot read the user directory (SCIM -> 403)', scim.status === 403, { http: scim.status, cid: scim.cid });
    const acl = ((await api('GET', '/v1.0/authenticators/clients')).data.clients || []).find((x) => x.name === c.MOBILE_CLIENT);
    check('A', "IFC's own authenticator client (registration profile) exists", !!acl, { id: acl && acl.id });
    const pol = (await api('GET', `/v5.0/policyvault/accesspolicy/${st.policy.id}`)).data;
    check('A', 'the sign-in policy asks for approval on a registered device', pol.rules[0].result.action === 'ACTION_MFA_ALWAYS' && pol.rules[0].result.authnMethods.includes('signatures'), { rule: pol.rules[0].result });

    // ===== B. register two trusted devices as the customer =====
    head('B. "Register Device": the customer registers two trusted devices');
    const png = await mine.initiate('Intact (Marie)', { format: 'png' });
    check('B', 'the customer gets a QR image for the real IBM Verify app (initiation, PNG)', !!png.png && png.png.slice(0, 4).toString('hex') === '89504e47', { cid: png.cid, bytes: png.png && png.png.length });
    const r1 = await mine.simulateScan({ deviceName: 'Marie iPhone 15', platformType: 'IOS', deviceType: 'iPhone', osVersion: '17.5' });
    check('B', 'device 1 (iPhone) registered with the customer\'s own token, no admin', !r1.error && r1.steps.redeem.status === 200 && r1.steps.enrol.status === 201 && r1.steps.finalize.status === 200, { steps: r1.steps, initiationMs: r1.initiationMs, registerMs: r1.registerMs });
    const r2 = await mine.simulateScan({ deviceName: 'Marie Pixel 8', platformType: 'Android', deviceType: 'Pixel 8', osVersion: '14' });
    check('B', 'device 2 (Android) registered the same way', !r2.error && r2.steps.finalize.status === 200, { steps: r2.steps, registerMs: r2.registerMs });
    const dev1 = r1.device; const dev2 = r2.device;
    const l1 = await mine.list();
    check('B', 'ONE user holds TWO trusted devices, both ACTIVE', (l1.devices || []).length === 2 && l1.devices.every((d) => d.state === 'ACTIVE' && d.enabled), { devices: (l1.devices || []).map((d) => ({ name: d.deviceName, platform: d.platformType, state: d.state })), ms: l1.ms });
    check('B', 'the list tells the devices apart (name and platform)', new Set((l1.devices || []).map((d) => `${d.deviceName}/${d.platformType}`)).size === 2 && (l1.devices || []).some((d) => d.platformType === 'Android'));
    const olist = await theirs.list();
    check('B', 'another customer sees none of them', (olist.devices || []).length === 0, { count: (olist.devices || []).length });
    const sl = await svc.list();
    check('B', 'the back-end device service sees the same two devices for that customer', (sl.devices || []).length === 2, { count: (sl.devices || []).length });

    // ===== C. push confirmation after registration =====
    head('C. Push confirmation on successful registration (IFC main flow)');
    const conf = await svc.push(dev2.id, { title: 'Intact Financial', message: 'Your device "Marie Pixel 8" is now registered. Tap Approve to confirm it was you.', type: 'Device registered', location: 'Montreal, QC, Canada' });
    check('C', 'confirmation push to the new device accepted (202, PENDING)', !conf.error && conf.txn.state === 'PENDING', { ms: conf.ms, cid: conf.cid, http: conf.httpStatus });
    const confAns = await dev2.handleNext('approve', { timeoutMs: 15000, intervalMs: 300 });
    check('C', 'the new device receives it and the message says it was registered', !!confAns.txn && /registered/.test(confAns.txn.transactionData), { deviceSawItAfterMs: confAns.seenMs });
    const confDone = await svc.waitFor(dev2.id, conf.txn.id);
    check('C', 'approval confirms the registration (VERIFY_SUCCESS)', confDone.txn && confDone.txn.state === 'VERIFY_SUCCESS', { state: confDone.txn && confDone.txn.state, waitedMs: confDone.waitedMs });
    const alert = await svc.push(dev1.id, { message: 'A new device ("Marie Pixel 8") was added to your account. Was it you?', type: 'New device added' });
    const alertAns = await dev1.handleNext('approve', { timeoutMs: 15000, intervalMs: 300 });
    check('C', 'the already-trusted device is alerted too (new device added)', !alert.error && !!alertAns.txn && /new device/i.test(alertAns.txn.transactionData), { deviceSawItAfterMs: alertAns.seenMs });

    // ===== D. push approve / deny / fraud =====
    head('D. Push approve, deny, fraud (location shown)');
    const loc = 'Toronto, ON, Canada';
    const pA = await svc.push(dev1.id, { message: 'Approve this payment of $150.00?', location: loc, type: 'Payment', ip: '198.51.100.23' });
    const dA = await dev1.handleNext('approve', { timeoutMs: 15000, intervalMs: 300 });
    check('D', 'the device sees the pending request with message, IP and the location', !!dA.txn && dA.txn.transactionData.includes(loc) && dA.txn.transactionData.includes('198.51.100.23'), { deviceSawItAfterMs: dA.seenMs });
    const doneA = await svc.waitFor(dev1.id, pA.txn.id);
    check('D', 'approve -> VERIFY_SUCCESS with the user action recorded', doneA.txn && doneA.txn.state === 'VERIFY_SUCCESS' && (doneA.txn.userActions || []).length > 0, { state: doneA.txn && doneA.txn.state, answerHttp: dA.answer && dA.answer.status, waitedMs: doneA.waitedMs });
    const pD = await svc.push(dev2.id, { message: 'Approve this payment of $9,000.00?', location: 'Lagos, Nigeria', type: 'Payment' });
    const dD = await dev2.handleNext('deny', { timeoutMs: 15000, intervalMs: 300 });
    const doneD = await svc.waitFor(dev2.id, pD.txn.id);
    check('D', 'deny -> USER_DENIED', !!dD.txn && doneD.txn && doneD.txn.state === 'USER_DENIED', { state: doneD.txn && doneD.txn.state });
    const pF = await svc.push(dev1.id, { message: 'Approve this login?', type: 'Sign-in' });
    const dF = await dev1.handleNext('fraud', { timeoutMs: 15000, intervalMs: 300 });
    const doneF = await svc.waitFor(dev1.id, pF.txn.id);
    check('D', '"this was not me" -> USER_FRAUDULENT (a fraud signal, not just a deny)', !!dF.txn && doneF.txn && doneF.txn.state === 'USER_FRAUDULENT', { state: doneF.txn && doneF.txn.state });
    check('D', 'push is delivered to the device within 2 s of the request', pA.ms < 2000 && dA.seenMs < 2000, { pushHttpMs: pA.ms, deviceSawItAfterMs: dA.seenMs });
    const corr = await svc.req('POST', `/v1.0/authenticators/${dev1.id}/verifications`, { ...PUSH_BODY(pA.sigId, { message: 'number matching?' }), correlationEnabled: true });
    const cp = await dev1.pending();
    const ct = cp.data && cp.data.verifications && cp.data.verifications[0];
    info('D', 'number matching (correlationEnabled in the push request): accepted but NOT effective on this tenant', { requestHttp: corr.status, correlationEnabledSeenByDevice: ct ? ct.correlationEnabled : null, correlationValuePresent: !!(ct && ct.correlationValue) });
    if (ct) await dev1.answer(ct, 'deny');
    check('D', 'the app\'s `type` and `originLocation` additionalData travel with the request (shown by the real app, [HUMAN] to see)', /originLocation/.test(dA.txn.transactionData) && /"type"|name.{0,5}type/.test(dA.txn.transactionData), { transactionData: dA.txn.transactionData.slice(0, 400) });

    // ===== E. hosted sign-in with two devices =====
    head('E. Sign-in on IFC\'s application: password, then approve on a trusted device');
    const loginUrl = () => c.authorizeUrl(st.login.clientId);
    const startLogin = async () => { const br = new Browser(); const pg = await br.open(loginUrl(), { username: marie.userName, password: marie.password }); return { br, pg }; };
    let { br, pg } = await startLogin();
    const offered = c.methodsOf(pg).filter((m) => m.type === 'signature').map((m) => m.label);
    check('E', 'with 2 devices the sign-in page lets the customer choose which device to approve on', /select/i.test(c.tagOf(pg.html)) && offered.length === 2 && offered.some((l) => l.startsWith('Marie iPhone 15')) && offered.some((l) => l.startsWith('Marie Pixel 8')), { page: c.tagOf(pg.html), offered });
    pg = await c.pickDevice(br, pg, 'Marie iPhone 15');
    check('E', 'after choosing, Verify shows "pending challenge on your device"', /ibmverify/.test(c.tagOf(pg.html)), { page: c.tagOf(pg.html) });
    const eA = await dev1.handleNext('approve', { timeoutMs: 15000, intervalMs: 300 });
    const tA = Date.now();
    pg = await br.post(c.actionOf(pg), { operation: 'verify', authStatus: 'FAILED' });
    check('E', 'approve on the chosen device -> authorization code issued (sign-in completes)', !!eA.txn && /[?&]code=/.test(pg.url), { redirectMs: Date.now() - tA, deviceSawItAfterMs: eA.seenMs });
    ({ br, pg } = await startLogin());
    pg = await c.pickDevice(br, pg, 'Marie Pixel 8');
    const eD = await dev2.handleNext('deny', { timeoutMs: 15000, intervalMs: 300 });
    pg = await br.post(c.actionOf(pg), { operation: 'verify', authStatus: 'FAILED' });
    check('E', 'deny on the device -> sign-in refused (CSIAH3102E), no code', !!eD.txn && !/[?&]code=/.test(pg.url) && /CSIAH3102E/.test(c.errorCode(pg) + pg.html.slice(0, 20000)), { error: c.errorCode(pg) });
    ({ br, pg } = await startLogin());
    pg = await c.pickDevice(br, pg, 'Marie iPhone 15');
    const early = await br.post(c.actionOf(pg), { operation: 'verify', authStatus: 'FAILED' });
    check('E', 'submitting before anyone approved does not sign in (page stays pending)', !/[?&]code=/.test(early.url) && /ibmverify/.test(c.tagOf(early.html)), { page: c.tagOf(early.html) });
    await dev1.handleNext('deny', { timeoutMs: 15000, intervalMs: 300 });

    // ===== F. security =====
    head('F. Security');
    const pW = await svc.push(dev1.id, { message: 'Approve (wrong key test)?' });
    const rogue = VerifyDevice.fromJSON(JSON.parse(JSON.stringify(dev1)));
    rogue.privateKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
    const wtx = (await dev1.pending()).data.verifications[0];
    const wrong = await rogue.answer(wtx, 'approve');
    const wdone = await svc.waitFor(dev1.id, pW.txn.id);
    check('F', 'an approval signed with a different key is refused (400 CSIBH0031E) and the request fails (VERIFY_FAILED)', wrong.status === 400 && has(wrong, 'CSIBH0031E') && wdone.txn.state === 'VERIFY_FAILED', { http: wrong.status, state: wdone.txn && wdone.txn.state });
    const replay = await dev1.answer(dA.txn, 'approve');
    check('F', 'replaying an already-answered approval is refused (400 CSIBH0030E)', replay.status === 400 && has(replay, 'CSIBH0030E'), { http: replay.status });
    const pX = await svc.push(dev1.id, { message: 'Approve (other device test)?' });
    const xtx = (await dev1.pending()).data.verifications[0];
    const other = await dev2.answer(xtx, 'approve');
    check('F', 'another registered device cannot answer this device\'s request (404 CSIBH0028E)', other.status === 404 && has(other, 'CSIBH0028E'), { http: other.status });
    await dev1.answer(xtx, 'deny');
    const pT = await svc.push(dev1.id, { message: 'Approve (expiry test)?', expiresIn: 5 });
    const tDone = await svc.waitFor(dev1.id, pT.txn.id, { timeoutMs: 20000 });
    check('F', 'an unanswered request expires on its own (TIMEOUT)', tDone.txn && tDone.txn.state === 'TIMEOUT', { state: tDone.txn && tDone.txn.state, waitedMs: tDone.waitedMs });
    const xr = await theirs.req('GET', `/v1.0/authenticators/${dev1.id}`);
    check('F', 'another customer cannot read this customer\'s device (403 CSIBH0002E)', xr.status === 403 && has(xr, 'CSIBH0002E'), { http: xr.status });
    const xd = await theirs.revoke(dev1.id);
    check('F', 'another customer cannot revoke this customer\'s device (403 CSIBH0002E)', xd.httpStatus === 403 && has(xd, 'CSIBH0002E'), { http: xd.httpStatus });
    const xp = await theirs.push(dev1.id, { message: 'hostile push', signatureId: pA.sigId });
    check('F', 'another customer cannot push to this customer\'s device', xp.httpStatus >= 400 && xp.httpStatus < 500, { http: xp.httpStatus });
    const stillBoth = await mine.list();
    check('F', 'the two devices are still registered after the attempts', (stillBoth.devices || []).length === 2);

    // ===== G. disable / enable =====
    head('G. Disable / re-enable a device (fraud response)');
    const patch = async (id, enabled) => send({ method: 'PATCH', url: `${BASE}/v1.0/authenticators/${id}`, headers: { Authorization: `Bearer ${await svcClient.getToken()}`, 'Content-Type': 'application/json-patch+json', Accept: 'application/json' }, data: JSON.stringify([{ op: 'replace', path: '/enabled', value: enabled }]), validateStatus: () => true });
    const dis = await patch(dev2.id, false);
    check('G', 'PATCH enabled=false (json-patch) disables the device -> 204', dis.status === 204, { http: dis.status });
    const pDis = await svc.push(dev2.id, { message: 'to a disabled device' });
    check('G', 'a push to a disabled device is refused (400 CSIBH0036E)', pDis.httpStatus === 400 && has(pDis, 'CSIBH0036E'), { http: pDis.httpStatus });
    const disTok = await call('GET', dev2.transactionUri, { token: dev2.accessToken, query: DEV_Q }); // raw call: pending() would try a token refresh
    check('G', 'the disabled device itself is refused when it asks for requests (400 CSIBH0036E or 401: the code varies with token state)', (disTok.status === 400 && has(disTok, 'CSIBH0036E')) || disTok.status === 401, { http: disTok.status, body: JSON.stringify(disTok.data).slice(0, 200) });
    const en = await patch(dev2.id, true);
    const pEn = await svc.push(dev2.id, { message: 'back on' });
    const eAns = await dev2.handleNext('approve', { timeoutMs: 15000, intervalMs: 300 });
    check('G', 're-enabled -> push works again and the device answers', en.status === 204 && !pEn.error && !!eAns.txn && eAns.answer.status === 204, { enableHttp: en.status });

    // ===== H. self-service revoke =====
    head('H. Self-service revoke by the customer');
    const rv = await mine.revoke(dev1.id);
    check('H', 'the customer revokes her own device with her own token -> 204', rv.revoked === true, { ms: rv.ms, cid: rv.cid, http: rv.httpStatus });
    const after = await mine.list();
    check('H', 'the revoked device is gone from the list, the other remains', (after.devices || []).length === 1 && after.devices[0].deviceName === 'Marie Pixel 8');
    const pRev = await svc.push(dev1.id, { message: 'to a revoked device', signatureId: pA.sigId });
    check('H', 'a push to the revoked device is refused (404 CSIBH0018E)', pRev.httpStatus === 404 && has(pRev, 'CSIBH0018E'), { http: pRev.httpStatus });
    const revTok = await call('GET', dev1.transactionUri, { token: dev1.accessToken, query: DEV_Q });
    check('H', 'the revoked device\'s own token is dead (404)', revTok.status === 404 || revTok.status === 401, { http: revTok.status });
    ({ br, pg } = await startLogin());
    check('H', 'sign-in now goes straight to the one remaining device (no choice page)', /ibmverify/.test(c.tagOf(pg.html)), { page: c.tagOf(pg.html) });
    const hAns = await dev2.handleNext('approve', { timeoutMs: 15000, intervalMs: 300 });
    pg = await br.post(c.actionOf(pg), { operation: 'verify', authStatus: 'FAILED' });
    check('H', 'approving on the remaining device still signs the customer in', !!hAns.txn && /[?&]code=/.test(pg.url));

    // ===== I. IFC's own branded app =====
    head('I. IFC\'s own app: authenticator client');
    const mc = await svc.simulateScan({ deviceName: 'IFC mobile app (branded)', platformType: 'IOS', deviceType: 'iPhone', applicationId: 'ca.intact.mobile', clientId: acl.id });
    check('I', 'a device registers under IFC\'s own authenticator client (initiation with its clientId)', !mc.error && mc.steps.finalize.status === 200, { steps: mc.steps });
    const ml = await svc.list();
    const mdev = (ml.devices || []).find((d) => d.deviceName === 'IFC mobile app (branded)');
    check('I', 'the registration carries IFC\'s client id, not the IBM Verify app\'s', !!mdev && mdev.clientId === acl.id && mdev.clientId !== c.VERIFY_PROFILE_CLIENT_ID, { clientIdIsIfc: !!mdev && mdev.clientId === acl.id });
    const mp = await svc.push(mc.id, { message: 'push via the branded registration' });
    const mAns = await mc.device.handleNext('approve', { timeoutMs: 15000, intervalMs: 300 });
    const mDone = await svc.waitFor(mc.id, mp.txn.id);
    check('I', 'the same push API works for the branded registration (VERIFY_SUCCESS)', !mp.error && !!mAns.txn && mDone.txn && mDone.txn.state === 'VERIFY_SUCCESS', { state: mDone.txn && mDone.txn.state });
    const fb = await api('POST', '/v1.0/authenticators/clients', { body: { name: `${c.P}probe-fcm`, firebase: { serverKey: 'x' } }, quiet: true });
    for (const x of ((await api('GET', '/v1.0/authenticators/clients')).data.clients || []).filter((x) => x.name === `${c.P}probe-fcm`)) await api('DELETE', `/v1.0/authenticators/clients/${x.id}`, { quiet: true });
    info('I', 'Firebase / APNs credentials cannot be set through the API: an authenticator client accepts only a name', { postWithFirebaseField: fb.status });
    info('I', 'IFC\'s own app push (proprietary SDK, Firebase, Salesforce Marketing Cloud) needs the IBM Verify MFA SDK in IFC\'s app and IBM to attach push credentials: [DOCS]/[HUMAN], not run');
    info('I', 'real APNs/FCM delivery, Face ID / Touch ID and the real app\'s screen (location, number) are [HUMAN]: the simulated phone polls Verify instead of receiving a notification');

    // ===== J. several devices, least-privilege matrix =====
    head('J. More than two devices, and least privilege');
    for (let i = 3; i <= 4; i++) await svc.simulateScan({ deviceName: `Marie extra device ${i}`, platformType: i % 2 ? 'IOS' : 'Android' });
    const five = await svc.list();
    check('J', 'a customer can hold 4 or more registered devices at once (13 were registered in the exploration; no limit hit)', (five.devices || []).length >= 4 && five.devices.every((d) => d.state === 'ACTIVE'), { count: (five.devices || []).length });
    const ro = await idem.ensureApiClient(`${c.P}probe-readonly`, ['readAuthenticatorsAnyUser']);
    const roC = createClient(ro.clientId, ro.clientSecret);
    const roList = await roC.api('GET', '/v1.0/authenticators', { query: { search: `owner="${marie.id}"` }, quiet: true });
    const roInit = await roC.api('POST', '/v1.0/authenticators/initiation', { body: { owner: marie.id, clientId: c.VERIFY_PROFILE_CLIENT_ID, accountName: 'x' }, quiet: true });
    const roDel = await roC.api('DELETE', `/v1.0/authenticators/${dev2.id}`, { quiet: true });
    check('J', 'read-only client: can list devices, cannot register or delete one', roList.status === 200 && roInit.status === 403 && roDel.status === 403, { list: roList.status, initiation: roInit.status, delete: roDel.status });
    const mp2 = await idem.ensureApiClient(`${c.P}probe-mfapush`, ['readAuthenticatorsAnyUser', 'manageAuthenticatorsAnyUser', 'readEnrollMFAMethodAnyUser', 'mfaPush']);
    const mpC = createClient(mp2.clientId, mp2.clientSecret);
    const mpSvc = createDeviceService({ owner: marie.id, request: (m, p, b, q) => mpC.api(m, p, { body: b, query: q, quiet: true }) });
    const mpPush = await mpSvc.push(dev2.id, { message: 'mfaPush only' });
    check('J', 'the "mfaPush" entitlement does NOT allow push; "authnAnyUser" does (finding)', !!mpPush.error && mpPush.httpStatus === 403, { mfaPushOnlyHttp: mpPush.httpStatus });
    await idem.deleteApiClientsByPrefix(`${c.P}probe-`);
    for (const d of five.devices || []) if (d.deviceName.startsWith('Marie extra')) await svc.revoke(d.id);
    await svc.revoke(mc.id);
    const finalList = await mine.list();
    check('J', 'the service can revoke devices on behalf of the customer (back-office / fraud team)', (finalList.devices || []).length === 1 && finalList.devices[0].deviceName === 'Marie Pixel 8', { left: (finalList.devices || []).map((d) => d.deviceName) });

    // ===== K. audit =====
    head('K. Audit trail (events API, can lag 25-40 s)');
    const wanted = () => ({ from: t0 - 5000, to: Date.now() });
    let evs = []; let ok = false; const created = []; let deleted = []; let succ = []; let den = [];
    for (let i = 0; i < 14 && !ok; i++) {
      await sleep(i === 0 ? 20000 : 10000);
      const w = wanted();
      const r = await svcClient.api('GET', '/v1.0/events', { query: { range_type: 'time', from: w.from, to: w.to, size: 1000, sort_order: 'desc' }, quiet: true });
      evs = (((r.data || {}).response || {}).events || {}).events || [];
      const d = (e) => e.data || {};
      const mgmt = evs.filter((e) => d(e).resource === 'mfa_device');
      created.length = 0; created.push(...mgmt.filter((e) => d(e).action === 'created'));
      deleted = mgmt.filter((e) => d(e).action === 'deleted');
      const auth = evs.filter((e) => d(e).mfamethod === 'IBM Verify Push');
      succ = auth.filter((e) => d(e).mfaresult === 'VERIFY_SUCCESS');
      den = auth.filter((e) => d(e).mfaresult === 'USER_DENIED');
      ok = created.length >= 2 && deleted.length >= 1 && succ.length >= 1 && den.length >= 1;
      process.stdout.write(`\r  polling events... ${i + 1}  created=${created.length} deleted=${deleted.length} success=${succ.length} denied=${den.length}   `);
    }
    console.log('');
    const d0 = (e) => e.data || {};
    check('K', 'audit: device registrations are logged (resource mfa_device, action created)', created.length >= 2, { count: created.length, devices: created.slice(0, 6).map((e) => d0(e).mfadevice) });
    check('K', 'audit: a device the customer registered herself is marked self-service (self=true)', created.some((e) => String(d0(e).self) === 'true'), { selfFlags: created.slice(0, 6).map((e) => d0(e).self) });
    check('K', 'audit: revoking a device is logged (action deleted, with the device name)', deleted.length >= 1 && deleted.some((e) => d0(e).mfadevice), { count: deleted.length, devices: deleted.slice(0, 4).map((e) => d0(e).mfadevice) });
    check('K', 'audit: approved push sign-ins are logged (mfamethod "IBM Verify Push", VERIFY_SUCCESS, device name)', succ.length >= 1 && succ.some((e) => d0(e).mfadevice), { count: succ.length });
    check('K', 'audit: denied push sign-ins are logged (USER_DENIED)', den.length >= 1, { count: den.length });
  } finally {
    listener.close();
    await idem.deleteApiClientsByPrefix(`${c.P}probe-`).catch(() => {});
  }

  const failed = results.filter((r) => !r.pass).length;
  const passed = results.length - failed;
  console.log(`\n${passed} checks passed, ${failed} failed  (${Math.round((Date.now() - t0) / 1000)} s)`);
  ev.save({ mode: 'automated', total: results.length, passed, failed, results });
  console.log(`Evidence written: ${ev.file}`);
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main().catch((e) => { console.error('RUN FAILED:', e.message || e); process.exit(2); });
module.exports = { main };

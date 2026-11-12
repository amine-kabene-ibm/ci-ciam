'use strict';
// UC-01 test run (self-service registration + progressive profiling), against the live tenant. No human needed:
// the verification e-mail is REAL (sent by IBM Verify); the script reads it from a disposable mail.tm inbox.
//   node demo/uc01-registration/run.js
// Scenarios:
//   A  objects and least privilege (attributes, group, DCR app, registration API client)
//   B  input validation before any e-mail is sent
//   C  verification challenge: real OTP e-mails sent and read (timings)
//   D  wrong codes and attempt exhaustion; expired / reused / unknown transaction
//   E  identity created with minimal data (e-mail + password); weak password keeps the code valid; Client 360 id; Client 360 down
//   F  duplicate detection (e-mail, case variants, policy number, unique-constraint backstop)
//   G  sign-in with the new identity (password grant): token claims, no Client 360 call at sign-in
//   H  progressive profiling: one stage per visit, validation, phone duplicate, completeness
const axios = require('axios');
const { Browser } = require('../uc08-sso/browser');
const { api: adminApi, createClient, oauthClient, evidence, send } = require('../lib/verify');
const { startServer: startClient360 } = require('../../stubs/client360/server');
const { createPortal, listen } = require('../../stubs/registration-portal/server');
const { createRegistrationService } = require('../../stubs/registration-portal/service');
const idem = require('../lib/idempotent');
const c = require('./common');

const ev = evidence('uc01');
const results = [];
const check = (scenario, title, pass, extra = {}) => {
  results.push({ scenario, title, pass: !!pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${scenario}  ${title}`);
  ev.step(`${scenario}: ${title}`, { pass: !!pass, ...extra });
};
const info = (scenario, title, extra = {}) => {
  console.log(`  INFO  ${scenario}  ${title}`);
  ev.step(`${scenario}: ${title}`, { info: true, ...extra });
};
const head = (t) => console.log(`\n${t}`);
const decode = (jwt) => JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString());

async function main() {
  const st = c.state.read();
  if (!st || !st.registration || !st.portal || !st.group) { console.error('State missing. Run: node demo/uc01-registration/setup.js'); process.exit(2); }
  const t0 = Date.now();
  console.log('UC-01 Run: self-service registration and progressive profiling (real Verify e-mail OTP)');

  // Start from a known state: no customer left from an earlier run (their policy number would collide).
  const grp = await adminApi('GET', `/v2.0/Groups/${st.group.id}`);
  for (const m of (grp.data && grp.data.members) || []) await idem.deleteUser(m.value);

  const c360 = await startClient360(c.PORTS.client360);
  const regApi = createClient(st.registration.clientId, st.registration.clientSecret).api;
  const portal = createPortal({ port: c.PORTS.portal, api: regApi, client360Url: c360.url, groupId: st.group.id, clientId: st.portal.clientId, clientSecret: st.portal.clientSecret });
  const web = await listen(portal, c.PORTS.portal);
  const post = async (p, body) => { const r = await axios.post(web.url + p, body, { validateStatus: () => true }); return { status: r.status, data: r.data }; };
  const oauth = oauthClient(st.portal.clientId, st.portal.clientSecret);
  const dead = createRegistrationService({ api: regApi, client360Url: 'http://127.0.0.1:4019', groupId: st.group.id });

  const mk = async (label) => ({ label, ...(await c.createInbox()) });
  const [inA, inB, inC, inD] = [await mk('A'), await mk('B'), await mk('C'), await mk('D')];
  const pwA = c.newPassword(); const pwB = c.newPassword(); const pwC = c.newPassword();

  try {
    // ===== A. objects and least privilege =====
    head('A. Objects and least privilege');
    const attrs = await idem.listTenantAttributes();
    const names = c.ATTRIBUTES.map((a) => a.scim);
    const mine = attrs.filter((a) => names.includes(a.schemaAttribute.scimName));
    check('A', 'the three custom attributes exist (client360Id, policyNumber, hasVehicle)', mine.length === 3, { slots: mine.map((a) => a.schemaAttribute.name) });
    const pol = mine.find((a) => a.schemaAttribute.scimName === 'policyNumber');
    check('A', 'policyNumber carries the unique constraint', !!(pol && pol.constraints && pol.constraints.unique === true));
    const ac = (await adminApi('GET', `/v1.0/apiclients/${st.registration.id}`)).data;
    check('A', 'the registration service runs on a 4-entitlement API client, not the admin client', JSON.stringify([...ac.entitlements].sort()) === JSON.stringify([...c.REG_ENTITLEMENTS].sort()), { entitlements: ac.entitlements });
    const denied = await regApi('GET', '/v1.0/apiclients', { quiet: true });
    check('A', 'the registration client is refused outside its scope (list API clients -> 403)', denied.status === 403, { http: denied.status, cid: denied.cid });
    const apps = (await idem.listApplications()).filter((a) => a.name === c.PORTAL_APP);
    const appDoc = (await adminApi('GET', apps[0]._links.self.href)).data.providers.oidc.properties;
    check('A', 'the portal application sends all known user attributes in the ID token', String(appDoc.sendAllKnownUserAttributes) === 'true');

    // ===== B. input validation =====
    head('B. Input validation (no e-mail is sent)');
    const b1 = await post('/api/register/start', { email: 'not-an-email' });
    check('B', 'invalid e-mail address is refused before anything is sent (400)', b1.status === 400 && b1.data.error === 'invalid_email');
    const b2 = await post('/api/register/start', { email: inA.address, policyNumber: 'banana' });
    check('B', 'malformed policy number is refused (400)', b2.status === 400 && b2.data.error === 'invalid_policy_number');
    const b3 = await post('/api/register/complete', { txn: 'nope', code: '123456', password: pwA });
    check('B', 'unknown transaction is refused (404)', b3.status === 404);

    // ===== C. verification challenge =====
    head('C. Verification challenge (real e-mails from IBM Verify)');
    const sA = await post('/api/register/start', { email: inA.address.toUpperCase() }); // typed in capitals: stored in lower case
    check('C', 'prospect: duplicate check passes and Verify sends the verification e-mail (HTTP 200)', sA.status === 200 && !!sA.data.txn && sA.data.attemptsAllowed === 5, { otpSentMs: sA.data.otpSentMs, totalMs: sA.data.ms, attemptsAllowed: sA.data.attemptsAllowed });
    const sB = await post('/api/register/start', { email: inB.address, policyNumber: 'auto-31877', postalCode: 'h2x 1y4' });
    check('C', 'existing customer: policy AUTO-31877 + matching postal code is linked at registration', sB.status === 200 && sB.data.policyLinked === true, { totalMs: sB.data.ms });
    const sC = await dead.start({ email: inC.address });
    check('C', 'Client 360 down: registration still starts (client360: unavailable)', sC.status === 200 && sC.client360 === 'unavailable');
    const sD = await post('/api/register/start', { email: inD.address, policyNumber: 'AUTO-31877', postalCode: 'M5V 2T6' });
    check('C', 'policy with a wrong postal code is NOT linked (registered as a prospect)', sD.status === 200 && sD.data.policyLinked === false);
    info('C', 'waiting for the real e-mails (mail.tm delivery took 4 s to about 2 min in earlier runs)');
    const [oA, oB, oC] = await Promise.all([
      c.waitForOtp(inA, { correlation: sA.data.correlation }), c.waitForOtp(inB, { correlation: sB.data.correlation }), c.waitForOtp(inC, { correlation: sC.correlation }),
    ]);
    check('C', 'the three Verify e-mails arrived and carry the on-screen correlation number', !!(oA.code && oB.code && oC.code), { deliveryMs: [oA.ms, oB.ms, oC.ms] });

    // ===== D. wrong codes and exhaustion =====
    head('D. Wrong codes, exhaustion, reuse');
    const wrong = [];
    for (let i = 0; i < 4; i++) wrong.push(await post('/api/register/complete', { txn: sD.data.txn, code: '000000', password: pwA }));
    check('D', 'four wrong codes -> 401 wrong_code with the attempts left counting down', wrong.every((w) => w.status === 401 && w.data.error === 'wrong_code') && wrong[3].data.attemptsLeft === 1, { attemptsLeft: wrong.map((w) => w.data.attemptsLeft) });
    const w5 = await post('/api/register/complete', { txn: sD.data.txn, code: '000000', password: pwA });
    check('D', 'the fifth wrong code locks the challenge (423 too_many_attempts, CSIBN0080E)', w5.status === 423 && w5.data.verifyMessageId === 'CSIBN0080E', { verifyMessageId: w5.data.verifyMessageId });
    const w6 = await post('/api/register/complete', { txn: sD.data.txn, code: '000000', password: pwA });
    check('D', 'afterwards the transaction is dead (409 already_used); no account was created', w6.status === 409 && (await adminApi('GET', '/v2.0/Users', { query: { filter: `userName eq "${inD.address}"` } })).data.totalResults === 0);

    // ===== E. identity created with minimal data =====
    head('E. Identity created: e-mail + password only');
    const weak = await post('/api/register/complete', { txn: sB.data.txn, code: oB.code, password: 'abc' });
    check('E', 'weak password is refused (400 weak_password) and the e-mail code stays valid', weak.status === 400 && weak.data.error === 'weak_password' && weak.data.otpStillValid === true, { verifyMessageId: weak.data.verifyMessageId });
    const eB = await post('/api/register/complete', { txn: sB.data.txn, code: oB.code, password: pwB });
    check('E', 'same code + a strong password -> account created (201), no new e-mail needed', eB.status === 201 && !!eB.data.userId, { createMs: eB.data.createMs, totalMs: eB.data.ms });
    check('E', 'policy-linked customer gets the policy owner\'s Client 360 id C360-100231', eB.data.client360Id === 'C360-100231' && eB.data.policyLinked === true);
    const eA = await post('/api/register/complete', { txn: sA.data.txn, code: oA.code, password: pwA });
    check('E', 'prospect: account created (201) with a prospect Client 360 id (C360-P...)', eA.status === 201 && /^C360-P[0-9A-F]{8}$/.test(eA.data.client360Id || ''), { createMs: eA.data.createMs, totalMs: eA.data.ms });
    const eC = await dead.complete({ txn: sC.txn, code: oC.code, password: pwC });
    check('E', 'Client 360 down: account is still created, link marked pending (client360: unavailable)', eC.status === 201 && eC.client360 === 'unavailable' && !eC.client360Id);
    const reuse = await post('/api/register/complete', { txn: sB.data.txn, code: oB.code, password: pwB });
    check('E', 'a used transaction cannot create a second account (409 already_used)', reuse.status === 409 && reuse.data.error === 'already_used');
    const uA = (await adminApi('GET', `/v2.0/Users/${eA.data.userId}`)).data;
    const uB = (await adminApi('GET', `/v2.0/Users/${eB.data.userId}`)).data;
    const uC = (await adminApi('GET', `/v2.0/Users/${eC.userId}`)).data;
    check('E', 'minimal data: no name, no phone, no address on the new identity', !uA.name && !(uA.phoneNumbers || []).length && !(uA.addresses || []).length, { fields: Object.keys(uA).filter((k) => !k.startsWith('urn:')).sort() });
    check('E', 'userName = e-mail, stored lower case although it was typed in capitals', uA.userName === inA.address.toLowerCase() && uA.emails[0].value === uA.userName);
    const ent = (u) => (u['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] || {}).employeeNumber;
    const cust = (u) => Object.fromEntries((((u['urn:ietf:params:scim:schemas:extension:ibm:2.0:User'] || {}).customAttributes) || []).map((a) => [a.name, a.values[0]]));
    check('E', 'Client 360 id stored on the identity: employeeNumber and custom attribute client360Id', ent(uB) === 'C360-100231' && cust(uB).client360Id === 'C360-100231', { employeeNumber: ent(uB) });
    check('E', 'policy number stored as the unique custom attribute policyNumber', cust(uB).policyNumber === 'AUTO-31877');
    check('E', 'Client 360 down: no id stored (employeeNumber absent)', !ent(uC));
    const gm = (await adminApi('GET', `/v2.0/Groups/${st.group.id}`)).data.members || [];
    check('E', 'all three customers were added to the ifc-demo-uc01-customers group', [eA.data.userId, eB.data.userId, eC.userId].every((id) => gm.some((m) => m.value === id)));
    info('E', 'timings (ms)', { prospectStartToOtpSent: sA.data.otpSentMs, prospectCreate: eA.data.createMs, prospectCompleteTotal: eA.data.ms, otpDeliveryToInbox: [oA.ms, oB.ms, oC.ms] });
    info('E', 'the identity is created only AFTER the e-mail is proven; a registration that is abandoned leaves nothing in the directory');

    // ===== F. duplicate detection =====
    head('F. Duplicate detection (e-mail, phone, policyholder ID)');
    const f1 = await post('/api/register/start', { email: inA.address });
    check('F', 'same e-mail again -> 409 duplicate on email, before any e-mail is sent', f1.status === 409 && f1.data.matchedOn.join() === 'email' && !f1.data.txn, { matchedOn: f1.data.matchedOn, ms: f1.data.ms });
    const f2 = await post('/api/register/start', { email: inA.address.toUpperCase() });
    const f3 = await post('/api/register/start', { email: `  ${inA.address}  ` });
    check('F', 'upper case and padded e-mail variants are caught too (409)', f2.status === 409 && f3.status === 409);
    const f4 = await post('/api/register/start', { email: `new-${inA.address}`, policyNumber: 'AUTO-31877', postalCode: 'H2X 1Y4' });
    check('F', 'different e-mail but the SAME matched policy -> 409 duplicate on policy', f4.status === 409 && f4.data.matchedOn.join() === 'policy', { matchedOn: f4.data.matchedOn });
    const f5 = await post('/api/register/start', { email: inD.address, policyNumber: 'AUTO-31877', postalCode: 'Z9Z 9Z9' });
    check('F', 'someone who only KNOWS the policy number (wrong postal code) is not treated as its owner: no policy duplicate (200)', f5.status === 200 && f5.data.policyLinked === false, { note: 'a second challenge e-mail goes to the typed address only' });
    const IBM = 'urn:ietf:params:scim:schemas:extension:ibm:2.0:User';
    const back = await regApi('POST', '/v2.0/Users', { quiet: true, headers: { usershouldnotneedtoresetpassword: 'true' }, body: {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User', IBM], userName: `ifc-demo-uc01-backstop@example.com`, emails: [{ type: 'work', value: 'ifc-demo-uc01-backstop@example.com' }],
      password: c.newPassword(), [IBM]: { customAttributes: [{ name: 'policyNumber', values: ['AUTO-31877'] }] },
    } });
    if (back.status === 201) await idem.deleteUser(back.data.id);
    check('F', 'backstop: even if the application check were skipped, the tenant refuses a second account with the same policyNumber (400)', back.status === 400, { http: back.status, cid: back.cid });
    const noRule = createRegistrationService({ api: regApi, client360Url: c360.url, groupId: st.group.id, rules: { email: false, phone: true, policy: false } });
    const dupOff = await noRule.findDuplicates({ email: inA.address, policy: 'AUTO-31877' });
    check('F', 'the duplicate rules are configurable per IFC policy (email/phone/policy switched off -> nothing matched)', dupOff.length === 0);
    info('F', 'Verify itself only blocks an identical userName (409, case-insensitive). A different userName with the same e-mail is NOT blocked by Verify (201), which is why the e-mail / phone / policy rules live in IFC\'s registration service [LIVE]');

    // ===== G. sign-in =====
    head('G. Sign-in with the new identity');
    const callsBefore = c360.calls();
    const login = await oauth.passwordGrant(uB.userName, pwB);
    check('G', 'the new customer signs in with e-mail + password (token issued)', login.status === 200 && !!login.data.id_token, { http: login.status, ms: login.ms });
    const claims = login.status === 200 ? decode(login.data.id_token) : {};
    check('G', 'ID token: sub is the Verify user id and the Client 360 id arrives as employee_id', claims.sub === eB.data.userId && claims.employee_id === 'C360-100231', { claimNames: Object.keys(claims).sort(), employee_id: claims.employee_id });
    check('G', 'no Client 360 call at sign-in (the stand-in counter did not move)', c360.calls() === callsBefore, { callsBefore, callsAfter: c360.calls() });
    info('G', 'custom attributes (client360Id, policyNumber, hasVehicle) are NOT emitted in the ID token, even with sendAllKnownUserAttributes; only enterprise attributes are, so the Client 360 id travels as employeeNumber -> employee_id [LIVE]', { customInToken: ['client360Id', 'policyNumber', 'hasVehicle'].filter((k) => k in claims) });
    const loginA = await oauth.passwordGrant(uA.userName, pwA);
    check('G', 'the prospect signs in too (stored lower case, typed password)', loginA.status === 200);
    const loginBad = await oauth.passwordGrant(uA.userName, 'WrongPassw0rd!x');
    check('G', 'a wrong password is refused (400)', loginBad.status === 400);

    // ===== H. progressive profiling =====
    head('H. Progressive profiling');
    const p0 = await portal.service.getProfile(eB.data.userId);
    check('H', 'after signup the profile is 25% complete and the next question is the address stage only', p0.completeness === 25 && p0.nextStage && p0.nextStage.id === 'address', { completeness: p0.completeness, next: p0.nextStage && p0.nextStage.id });
    const h1 = await portal.service.saveStage(eB.data.userId, 'address', { postalCode: '12345', preferredLanguage: 'fr-CA' });
    check('H', 'invalid postal code is refused with a field error (400)', h1.status === 400 && h1.fields.postalCode === 'invalid_postal_code');
    const h2 = await portal.service.saveStage(eB.data.userId, 'address', { postalCode: 'h2x1y4', preferredLanguage: 'fr-CA' });
    check('H', 'address stage saved by SCIM PATCH (postal code normalised, language fr-CA); next question is the vehicle stage', h2.status === 200 && h2.profile.postalCode === 'H2X 1Y4' && h2.profile.preferredLanguage === 'fr-CA' && h2.nextStage.id === 'about' && h2.completeness === 75, { patchMs: h2.patchMs, completeness: h2.completeness });
    const phone = `+1514555${String(Math.floor(1000 + Math.random() * 9000))}`;
    const hA = await portal.service.saveStage(eA.data.userId, 'about', { hasVehicle: 'yes', mobile: phone });
    check('H', 'prospect saves the vehicle stage with an optional mobile number (phone stored)', hA.status === 200 && !!hA.profile.mobile, { patchMs: hA.patchMs });
    const h3 = await portal.service.saveStage(eB.data.userId, 'about', { hasVehicle: 'maybe' });
    check('H', 'invalid choice refused (400)', h3.status === 400 && h3.fields.hasVehicle === 'invalid_choice');
    const h4 = await portal.service.saveStage(eB.data.userId, 'about', { hasVehicle: 'yes', mobile: phone.replace('+1', '1 (').replace(/^(1 \(\d{3})/, '$1)') });
    check('H', 'duplicate by phone: the same mobile number (typed in another format) on a second account -> 409 matchedOn phone', h4.status === 409 && h4.matchedOn.join() === 'phone', { matchedOn: h4.matchedOn });
    const h5 = await portal.service.saveStage(eB.data.userId, 'about', { hasVehicle: 'no' });
    check('H', 'vehicle stage saved without a phone: profile 100% complete and nothing more is asked', h5.status === 200 && h5.completeness === 100 && h5.nextStage === null, { patchMs: h5.patchMs });
    const filter = await adminApi('GET', '/v2.0/Users', { query: { filter: `${IBM}:customAttributes.hasVehicle eq "no"`, attributes: 'id,userName' } });
    check('H', 'the answers are queryable in the directory (SCIM filter on the custom attribute hasVehicle)', filter.status === 200 && (filter.data.Resources || []).some((r) => r.id === eB.data.userId));
    const me = await send({ method: 'get', url: `${require('../lib/verify').BASE}/v2.0/Me`, validateStatus: () => true, headers: { Authorization: `Bearer ${login.data.access_token}`, Accept: 'application/scim+json' } });
    const mePatch = await send({ method: 'patch', url: `${require('../lib/verify').BASE}/v2.0/Me`, validateStatus: () => true, headers: { Authorization: `Bearer ${login.data.access_token}`, Accept: 'application/scim+json', 'Content-Type': 'application/scim+json' },
      data: { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'preferredLanguage', value: 'en-CA' }] } });
    check('H', 'the customer\'s own token reads the profile (GET /v2.0/Me 200); self-update via PATCH /v2.0/Me is refused (405), so IFC\'s service writes it', me.status === 200 && mePatch.status === 405, { get: me.status, patch: mePatch.status });
    const trace = portal.trace.map((t) => `${t.method} ${t.path} ${t.status}`);
    info('H', 'Verify API calls the portal made (as seen in the page trace)', { distinct: [...new Set(trace)].slice(0, 20) });

    // ===== I. the portal's own browser sign-in (scripted browser, no JavaScript engine) =====
    head('I. Portal sign-in through the hosted Verify login (scripted browser)');
    const br = new Browser();
    const page = await br.open(`${web.url}/login`, { username: uC.userName, password: pwC });
    const sid = br.jar(new URL(web.url).origin).ifc_uc01_sid;
    check('I', 'GET /login -> Verify hosted login -> /callback: the portal holds a session (code + PKCE, ID token verified)', !!sid && page.status === 200, { steps: page.steps, kind: page.kind, ms: page.ms });
    const meR = await axios.get(`${web.url}/api/me`, { headers: { Cookie: `ifc_uc01_sid=${sid}` }, validateStatus: () => true });
    check('I', 'GET /api/me for the Client-360-down customer: profile 25% (e-mail only), next question is the address stage, employee_id absent', meR.status === 200 && meR.data.completeness === 25 && meR.data.nextStage.id === 'address' && !meR.data.idToken.employee_id, { completeness: meR.data.completeness });
    const sv = await axios.post(`${web.url}/api/profile/address`, { postalCode: 'm5v2t6', preferredLanguage: 'en-CA' }, { headers: { Cookie: `ifc_uc01_sid=${sid}` }, validateStatus: () => true });
    check('I', 'POST /api/profile/address with the session saves the stage and the next question becomes the vehicle stage', sv.status === 200 && sv.data.nextStage.id === 'about', { patchMs: sv.data.patchMs });
    const anon = await axios.get(`${web.url}/api/me`, { validateStatus: () => true });
    check('I', 'without a session /api/me is refused (401)', anon.status === 401);
  } finally {
    await web.close(); await c360.close();
  }

  const failed = results.filter((r) => !r.pass).length;
  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed} checks passed, ${failed} failed  (${Math.round((Date.now() - t0) / 1000)} s)`);
  ev.save({ total: results.length, passed, failed, results });
  console.log(`Evidence written: ${ev.file}`);
  process.exit(failed ? 1 : 0);
}

if (require.main === module) main().catch((e) => { console.error('RUN FAILED:', e.message || e); process.exit(2); });
module.exports = { main };

'use strict';
// UC-04 verification: reads the evidence written by run.js (demo/out/uc04.json) and checks it. It does not call the tenant.
//   node demo/uc04-devices/verify.js
// Exit 0 only if every required automated check passed, the evidence holds no secret, and the limits are stated.
// The [HUMAN] real-phone checks are listed separately: they cannot be proven by a script.
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'out', 'uc04.json');
if (!fs.existsSync(file)) { console.error(`No evidence at ${file}. Run: node demo/uc04-devices/run.js`); process.exit(2); }
const raw = fs.readFileSync(file, 'utf8');
const doc = JSON.parse(raw);

const REQUIRED = [
  ['A', 'the device service runs on a 5-entitlement API client'],
  ['A', 'the device service is refused outside its scope'],
  ['A', 'the device service cannot read the user directory'],
  ['A', "IFC's own authenticator client"],
  ['A', 'the sign-in policy asks for approval on a registered device'],
  ['B', 'QR image for the real IBM Verify app'],
  ['B', 'device 1 (iPhone) registered with the customer'],
  ['B', 'device 2 (Android) registered'],
  ['B', 'ONE user holds TWO trusted devices'],
  ['B', 'the list tells the devices apart'],
  ['B', 'another customer sees none of them'],
  ['B', 'the back-end device service sees the same two devices'],
  ['C', 'confirmation push to the new device accepted'],
  ['C', 'the new device receives it and the message says it was registered'],
  ['C', 'approval confirms the registration'],
  ['C', 'the already-trusted device is alerted too'],
  ['D', 'the device sees the pending request with message, IP and the location'],
  ['D', 'approve -> VERIFY_SUCCESS'],
  ['D', 'deny -> USER_DENIED'],
  ['D', 'USER_FRAUDULENT'],
  ['D', 'push is delivered to the device within 2 s'],
  ['D', "`originLocation` additionalData travel"],
  ['E', 'lets the customer choose which device to approve on'],
  ['E', 'Verify shows "pending challenge on your device"'],
  ['E', 'approve on the chosen device -> authorization code issued'],
  ['E', 'deny on the device -> sign-in refused'],
  ['E', 'submitting before anyone approved does not sign in'],
  ['F', 'signed with a different key is refused'],
  ['F', 'replaying an already-answered approval is refused'],
  ['F', "another registered device cannot answer this device's request"],
  ['F', 'an unanswered request expires on its own'],
  ['F', "another customer cannot read this customer's device"],
  ['F', "another customer cannot revoke this customer's device"],
  ['F', "another customer cannot push to this customer's device"],
  ['F', 'the two devices are still registered after the attempts'],
  ['G', 'disables the device -> 204'],
  ['G', 'a push to a disabled device is refused'],
  ['G', 'the disabled device itself is refused'],
  ['G', 're-enabled -> push works again'],
  ['H', 'the customer revokes her own device with her own token -> 204'],
  ['H', 'the revoked device is gone from the list'],
  ['H', 'a push to the revoked device is refused'],
  ['H', "the revoked device's own token is dead"],
  ['H', 'sign-in now goes straight to the one remaining device'],
  ['H', 'approving on the remaining device still signs the customer in'],
  ['I', "a device registers under IFC's own authenticator client"],
  ['I', "the registration carries IFC's client id"],
  ['I', 'the same push API works for the branded registration'],
  ['J', 'a customer can hold 4 or more registered devices'],
  ['J', 'read-only client: can list devices, cannot register or delete one'],
  ['J', 'the "mfaPush" entitlement does NOT allow push'],
  ['J', 'the service can revoke devices on behalf of the customer'],
  ['K', 'device registrations are logged'],
  ['K', 'marked self-service'],
  ['K', 'revoking a device is logged'],
  ['K', 'approved push sign-ins are logged'],
  ['K', 'denied push sign-ins are logged'],
];

const problems = [];
const passed = (sc, frag) => (doc.results || []).some((r) => r.scenario === sc && r.pass === true && r.title.includes(frag));
const rows = REQUIRED.map(([sc, frag]) => ({ sc, frag, ok: passed(sc, frag) }));
for (const r of rows) if (!r.ok) problems.push(`${r.sc}: not passed: "${r.frag}"`);

const total = (doc.results || []).length;
const passCount = (doc.results || []).filter((r) => r.pass).length;
if (doc.total !== total || doc.passed !== passCount || doc.failed !== total - passCount) problems.push('summary counts do not match the results');
if (doc.failed !== 0) problems.push(`evidence reports ${doc.failed} failed check(s)`);
if (doc.tenant !== (process.env.OIDC_CI_BASE_URI || doc.tenant).replace(/\/+$/, '')) problems.push('evidence tenant differs from .env');

const secretPatterns = {
  jwt: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  privateKeyPem: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  tokenField: /"(access|refresh)_?token"\s*:\s*"[^"]{10,}"/i,
  secretField: /"(client_?secret|secret|password)"\s*:\s*"[^"]{6,}"/i,
  registrationCode: /"code"\s*:\s*"[^"]{8,}"/,
};
const leaks = Object.entries(secretPatterns).filter(([, re]) => re.test(raw)).map(([k]) => k);
if (leaks.length) problems.push(`evidence contains secret-like material: ${leaks.join(', ')}`);

const limits = (doc.steps || []).filter((s) => s.info).map((s) => s.title.toLowerCase());
for (const m of ['number matching', 'firebase / apns', 'real apns/fcm delivery']) {
  if (!limits.some((t) => t.includes(m))) problems.push(`limit not stated in evidence: "${m}"`);
}

console.log('UC-04 Verification (trusted devices, push, self-service revoke)\n');
for (const r of rows) console.log(`  ${r.ok ? 'PASS' : 'FAIL'}  ${r.sc}  ${r.frag}`);
console.log(`\nEvidence: ${total} checks in run.js (mode: ${doc.mode}), ${passCount} passed, ${total - passCount} failed; ${rows.filter((r) => r.ok).length}/${REQUIRED.length} required checks found PASS`);
console.log(`Secret scan of evidence: ${leaks.length ? 'LEAK ' + leaks.join(', ') : 'clean (no JWT, private key, token, registration code or secret values)'}`);

console.log('\nPROVEN BEHAVIOURS [LIVE] (with a SIMULATED IBM Verify app, demo/lib/verifyDevice.js):');
console.log('  [LIVE] One user holds several trusted devices (2 shown, 13 reached in exploration, no limit hit); the list shows name, platform, state.');
console.log('  [LIVE] The customer registers a device with her OWN token (initiation without owner) = the app\'s "Register Device"; QR as PNG for the real app.');
console.log('  [LIVE] Push to one device: POST /v1.0/authenticators/{id}/verifications; the device sees message + IP + location; approve / deny / fraud / timeout states.');
console.log('  [LIVE] Sign-in policy "signatures": 2 devices -> the customer chooses; approve -> code, deny -> CSIAH3102E.');
console.log('  [LIVE] Self-service revoke: DELETE /v1.0/authenticators/{id} with the customer\'s own token (204); push refused, sign-in offers the rest. Another customer: 403.');
console.log('  [LIVE] Disable/enable (json-patch), wrong-key / replay / other-device / expiry all refused as shown; audit events for create / delete / approve / deny.');
console.log('  [LIVE] IFC\'s own authenticator client: registrations carry its client id and use the same push API.');
console.log('  [LIVE] Push needs entitlement authnAnyUser; mfaPush alone does not work.');
console.log('\nSTILL [HUMAN] / NOT PROVEN:');
console.log('  [HUMAN] A real phone: IBM Verify app scan (enroll-phone.js), real APNs/FCM notification, Face ID / Touch ID, the app screen showing the location.');
console.log('  [HUMAN] The "Register Device" tap inside IFC\'s own app (needs the IBM Verify MFA SDK in that app).');
console.log('  [DOCS]  Firebase / APNs / Salesforce Marketing Cloud credentials for IFC\'s own app: not settable through the API; ask IBM.');
console.log('  [LIVE]  Number matching: the flag is accepted but has no effect on this tenant.');

if (problems.length) { console.error('\nVERIFICATION PROBLEMS:'); for (const p of problems) console.error(`  - ${p}`); process.exit(1); }
console.log('\nVERIFICATION PASSED');
process.exit(0);

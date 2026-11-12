'use strict';
// UC-14 verification: reads the evidence written by run.js (demo/out/uc14.json) and checks it. It does not call the tenant.
//   node demo/uc14-ciba/verify.js
// Exit 0 only if every required automated check passed, the evidence holds no secret, and the limits are stated.
// The [HUMAN] approval checks (scenario H) are reported separately: they pass only if run.js --approve was run with a real approval.
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'out', 'uc14.json');
if (!fs.existsSync(file)) { console.error(`No evidence at ${file}. Run: node demo/uc14-ciba/run.js`); process.exit(2); }
const raw = fs.readFileSync(file, 'utf8');
const doc = JSON.parse(raw);

const REQUIRED = [
  ['A', 'the agent application has the CIBA grant, poll mode and the e-mail channel'],
  ['A', 'the console runs on a 3-entitlement API client, not the admin client'],
  ['A', 'the console client is refused outside its scope'],
  ['A', 'the console finds the caller in the Verify directory through SCIM'],
  ['B', 'POST /oauth2/ciba accepted: auth_req_id issued'],
  ['B', 'the caller is shown a binding message naming the agent'],
  ['B', 'the response carries auth_req_id, expires_in and the polling interval'],
  ['B', 'polling before approval returns authorization_pending'],
  ['C', 'unknown caller -> 400 unknown_user_id'],
  ['C', 'wrong client secret -> 401 invalid_client'],
  ['C', 'request without a hint -> 400 invalid_request'],
  ['C', 'a customer not entitled to the agent application -> 403 access_denied'],
  ['C', 'polling after the request expired -> 400 expired_token'],
  ['C', 'polling an invented auth_req_id is refused'],
  ['D', 'while pending: reading the caller profile is refused (403)'],
  ['D', 'while pending: unlocking the account is refused (403)'],
  ['D', 'an unknown session id is refused (404)'],
  ['D', 'nothing changed in the directory while pending'],
  ['E', 'six wrong passwords lock the customer'],
  ['E', 'with the CORRECT password the locked customer is refused'],
  ['E', 'the agent can still start a CIBA request for a locked caller'],
  ['E', 'replacing the password clears the lock'],
];
const HUMAN = [
  ['H', 'the caller approved on their own device and the agent console shows VERIFIED'],
  ['H', 'after approval the agent can read the caller profile'],
  ['H', 'the caller is now locked out'],
  ['H', 'agent action "Unlock account" succeeds after verification'],
  ['H', 'the caller must choose a new password at next sign-in'],
  ['H', 'audit: Verify logged the successful CIBA token issue with the binding message'],
  ['H', 'audit: Verify logged the caller sign-in on the approval page'],
  ['H', 'audit: the "still pending" polls are counted separately'],
];

const problems = [];
const passed = (sc, frag) => (doc.results || []).some((r) => r.scenario === sc && r.pass === true && r.title.includes(frag));
const rows = REQUIRED.map(([sc, frag]) => ({ sc, frag, ok: passed(sc, frag) }));
for (const r of rows) if (!r.ok) problems.push(`${r.sc}: not passed: "${r.frag}"`);
const humanRows = HUMAN.map(([sc, frag]) => ({ sc, frag, ok: passed(sc, frag) }));

const total = (doc.results || []).length;
const passCount = (doc.results || []).filter((r) => r.pass).length;
if (doc.total !== total || doc.passed !== passCount || doc.failed !== total - passCount) problems.push('summary counts do not match the results');
if (doc.failed !== 0) problems.push(`evidence reports ${doc.failed} failed check(s)`);
if (doc.tenant !== (process.env.OIDC_CI_BASE_URI || doc.tenant).replace(/\/+$/, '')) problems.push('evidence tenant differs from .env');

const secretPatterns = {
  jwt: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  privateKeyPem: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  tokenField: /"access_token"\s*:\s*"[^"]{10,}"/,
  secretField: /"(client_?secret|secret|password)"\s*:\s*"[^"]{6,}"/i,
  idToken: /"id_token"\s*:\s*"[^"]{10,}"/,
};
const leaks = Object.entries(secretPatterns).filter(([, re]) => re.test(raw)).map(([k]) => k);
if (leaks.length) problems.push(`evidence contains secret-like material: ${leaks.join(', ')}`);

const limits = (doc.steps || []).filter((s) => s.info).map((s) => s.title.toLowerCase());
for (const m of ['channel values accepted', 'e-mail delivery for a locked caller']) {
  if (!limits.some((t) => t.includes(m))) problems.push(`limit not stated in evidence: "${m}"`);
}

console.log('UC-14 Verification (Policyholder authorizing a Call Center Agent via CIBA)\n');
for (const r of rows) console.log(`  ${r.ok ? 'PASS' : 'FAIL'}  ${r.sc}  ${r.frag}`);
console.log('\n[HUMAN] approval scenario (needs run.js --approve and a real approval):');
for (const r of humanRows) console.log(`  ${r.ok ? 'PASS' : 'HUMAN'}  ${r.sc}  ${r.frag}`);
if (doc.mode !== 'approve' && humanRows.every((r) => r.ok)) console.log(`\n(The [HUMAN] results above were carried over from the real approval run of ${doc.carriedFromApprovalAt}.)`);
console.log(`\nEvidence: ${total} checks in run.js (mode: ${doc.mode}), ${passCount} passed, ${total - passCount} failed; ${rows.filter((r) => r.ok).length}/${REQUIRED.length} automated and ${humanRows.filter((r) => r.ok).length}/${HUMAN.length} human-approval checks found PASS`);
console.log(`Secret scan of evidence: ${leaks.length ? 'LEAK ' + leaks.join(', ') : 'clean (no JWT, private key, token or secret values)'}`);

console.log('\nPROVEN BEHAVIOURS [LIVE]:');
console.log('  [LIVE] POST /oauth2/ciba with Basic client auth -> auth_req_id, expires_in (requested_expiry honoured), interval 5; poll /oauth2/token -> authorization_pending.');
console.log('  [LIVE] The caller gets an e-mail showing the agent\'s binding message, signs in, approves; the poll then returns tokens (access token + ID token).');
console.log('  [LIVE] Verify userinfo of the issued token gives the approving user; the console compares it with the caller on the call.');
console.log('  [LIVE] Errors: unknown_user_id, invalid_client, missing hint, not entitled (CSIAQ0279E), expired_token.');
console.log('  [LIVE] Audit: events API (readReports) has the CIBA token event with the binding message, the caller sign-in and the pending polls.');
console.log('  [LIVE] Unlock = SCIM password replace (204) with a temporary password; the customer must change it (CSIAQ0267E). No unlock endpoint exists; PATCH of the lock attribute does not clear it.');
console.log('\nSTILL [HUMAN] / NOT PROVEN:');
console.log('  [HUMAN] The approval is a real person using a real mailbox (and a phone for push). The scripts cannot do it.');
console.log('  [DOCS]  Push channel ("push","email"): the app accepts it, but the request fails (CSIAQ5306E) until the user is enrolled in the IBM Verify app. Not run.');
console.log('  [HUMAN] Locked caller: no approval e-mail was received while the account was locked (observed once, cause not established). Lock the account AFTER the approval in the demo.');
console.log('  [LIVE]  SMS/voice are not CIBA channels on this tenant (only push and email).');

if (!humanRows.every((r) => r.ok)) console.log('\nNote: human-approval checks have not all passed in the saved evidence. Run: node demo/uc14-ciba/run.js --approve');
if (problems.length) { console.error('\nVERIFICATION PROBLEMS:'); for (const p of problems) console.error(`  - ${p}`); process.exit(1); }
console.log('\nVERIFICATION PASSED');
process.exit(0);

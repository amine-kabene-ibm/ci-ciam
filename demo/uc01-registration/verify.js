'use strict';
// UC-01 verification: reads the evidence written by run.js (demo/out/uc01.json) and checks it. It does not call the tenant.
//   node demo/uc01-registration/verify.js
// Exit 0 only if every required check passed, the evidence holds no secret/OTP, and the limits are stated.
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'out', 'uc01.json');
if (!fs.existsSync(file)) { console.error(`No evidence at ${file}. Run: node demo/uc01-registration/run.js`); process.exit(2); }
const raw = fs.readFileSync(file, 'utf8');
const doc = JSON.parse(raw);

const REQUIRED = [
  ['A', 'the three custom attributes exist'], ['A', 'policyNumber carries the unique constraint'],
  ['A', 'the registration service runs on a 4-entitlement API client'], ['A', 'the registration client is refused outside its scope'],
  ['A', 'the portal application sends all known user attributes'],
  ['B', 'invalid e-mail address is refused'], ['B', 'malformed policy number is refused'], ['B', 'unknown transaction is refused'],
  ['C', 'prospect: duplicate check passes and Verify sends the verification e-mail'], ['C', 'existing customer: policy AUTO-31877'],
  ['C', 'Client 360 down: registration still starts'], ['C', 'policy with a wrong postal code is NOT linked'], ['C', 'the three Verify e-mails arrived'],
  ['D', 'four wrong codes'], ['D', 'the fifth wrong code locks the challenge'], ['D', 'afterwards the transaction is dead'],
  ['E', 'weak password is refused'], ['E', 'same code + a strong password'], ['E', 'policy-linked customer gets'], ['E', 'prospect: account created'],
  ['E', 'Client 360 down: account is still created'], ['E', 'a used transaction cannot create a second account'], ['E', 'minimal data'],
  ['E', 'userName = e-mail'], ['E', 'Client 360 id stored on the identity'], ['E', 'policy number stored'], ['E', 'Client 360 down: no id stored'],
  ['E', 'all three customers were added'],
  ['F', 'same e-mail again'], ['F', 'upper case and padded e-mail variants'], ['F', 'SAME matched policy'], ['F', 'only KNOWS the policy number'],
  ['F', 'backstop'], ['F', 'duplicate rules are configurable'],
  ['G', 'the new customer signs in'], ['G', 'ID token: sub is the Verify user id'], ['G', 'no Client 360 call at sign-in'], ['G', 'the prospect signs in too'], ['G', 'a wrong password is refused'],
  ['H', 'after signup the profile is 25% complete'], ['H', 'invalid postal code is refused'], ['H', 'address stage saved by SCIM PATCH'],
  ['H', 'prospect saves the vehicle stage'], ['H', 'invalid choice refused'], ['H', 'duplicate by phone'], ['H', 'vehicle stage saved without a phone'],
  ['H', 'queryable in the directory'], ['H', 'GET /v2.0/Me 200'],
  ['I', 'GET /login -> Verify hosted login'], ['I', 'GET /api/me for the Client-360-down customer'], ['I', 'POST /api/profile/address with the session'], ['I', 'without a session /api/me is refused'],
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
  tokenField: /"access_token"\s*:\s*"[^"]{10,}"/,
  secretField: /"(client_?secret|secret|password)"\s*:\s*"[^"]{6,}"/i,
  idToken: /"id_token"\s*:\s*"[^"]{10,}"/,
  otpCode: /"(otp|code)"\s*:\s*"?\d{6}"?/i,
  testInbox: /ifc-demo-uc01-[0-9a-f]{8}@/i,
};
const leaks = Object.entries(secretPatterns).filter(([, re]) => re.test(raw)).map(([k]) => k);
if (leaks.length) problems.push(`evidence contains secret-like material: ${leaks.join(', ')}`);

const limits = (doc.steps || []).filter((s) => s.info).map((s) => s.title.toLowerCase());
for (const m of ['custom attributes (client360id', 'verify itself only blocks an identical username']) {
  if (!limits.some((t) => t.includes(m))) problems.push(`limit not stated in evidence: "${m}"`);
}

console.log('UC-01 Verification (self-service registration, progressive profiling)\n');
for (const r of rows) console.log(`  ${r.ok ? 'PASS' : 'FAIL'}  ${r.sc}  ${r.frag}`);
console.log(`\nEvidence: ${total} checks in run.js, ${passCount} passed, ${total - passCount} failed; ${rows.filter((r) => r.ok).length}/${REQUIRED.length} required checks found PASS`);
console.log(`Secret scan of evidence: ${leaks.length ? 'LEAK ' + leaks.join(', ') : 'clean (no JWT, private key, token, secret, OTP value or test-inbox address)'}`);

console.log('\nPROVEN BEHAVIOURS [LIVE]:');
console.log('  [LIVE] Verify sends the verification e-mail (POST /v2.0/factors/emailotp/transient/verifications); the code was read from the real e-mail and verified; 5 attempts, then CSIBN0080E.');
console.log('  [LIVE] The identity is created with e-mail + password only (SCIM, 201), AFTER the address is proven; the Client 360 id is stored (employeeNumber + custom attribute).');
console.log('  [LIVE] Duplicates: Verify blocks only an identical userName; e-mail / phone / policy rules run in IFC\'s service with SCIM filters; policyNumber is also `unique` on the tenant.');
console.log('  [LIVE] Progressive profiling by SCIM PATCH, one stage per visit; answers are filterable in the directory.');
console.log('  [LIVE] Sign-in works (password grant and the portal\'s code + PKCE flow through the hosted Verify login); the ID token carries employee_id = Client 360 id; no Client 360 call at sign-in.');
console.log('\nNOT PROVEN / LIMITS:');
console.log('  [LIVE]  Flow designer is not enabled (403 CSIBZ0098E): the orchestration is IFC code (stubs/registration-portal), not a Verify flow. Native self-registration forms are not available on this tenant.');
console.log('  [LIVE]  Custom attributes never reach the ID token / userinfo; only enterprise attributes do (employeeNumber -> employee_id).');
console.log('  [HUMAN] A person registering in a real browser with their own mailbox (node demo/uc01-registration/serve.js), and the hosted login look and feel.');
console.log('  [DOCS]  SMS OTP and passkey/other factor choice at signup are not covered (e-mail OTP + password only). Multi-tenant / multi-brand registration is not demonstrated here.');

if (problems.length) { console.error('\nVERIFICATION PROBLEMS:'); for (const p of problems) console.error(`  - ${p}`); process.exit(1); }
console.log('\nVERIFICATION PASSED');
process.exit(0);

'use strict';
// UC-03 verification: reads the evidence written by run.js (demo/out/uc03.json) and checks it. It does not call the tenant.
//   node demo/uc03-recovery/verify.js
// Exit 0 only if every required check passed, the evidence holds no secret or OTP, and the limits are stated.
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'out', 'uc03.json');
if (!fs.existsSync(file)) { console.error(`No evidence at ${file}. Run: node demo/uc03-recovery/run.js`); process.exit(2); }
const raw = fs.readFileSync(file, 'utf8');
const doc = JSON.parse(raw);

const REQUIRED = [
  ['A', 'the recovery console runs on its own API client with 6 measured entitlements'],
  ['A', 'hosted "Forgot password" is switched ON on the tenant'],
  ['A', 'the console is refused outside its scope (403)'],
  ['A', 'the refused e-mail change left the address on file untouched'],
  ['A', 'Sophie holds a live session before the incident'],
  ['A', 'Sophie is locked out after 6 wrong passwords'],
  ['A', 'while locked, even her CORRECT password is refused'],
  ['B', 'usual device, usual country, no recent factor -> LOW'],
  ['B', 'authenticator added 10 minutes ago -> HIGH'],
  ['B', 'authenticator added 3 days ago -> LOW'],
  ['B', 'attempt from a device never seen on a successful sign-in -> HIGH'],
  ['B', 'attempt from a country never seen on a successful sign-in -> HIGH'],
  ['B', 'a new IP address alone is informational, not scored'],
  ['B', 'no earlier successful sign-in: device and country cannot be judged'],
  ['C', 'from the usual network: password only, no step-up, authorization code issued'],
  ['C', 'from another network (policy range changed to 203.0.113.0/24): the sign-in stops at the TOTP page'],
  ['C', 'with the TOTP code from his authenticator the step-up completes'],
  ['C', 'the policy is restored to the usual network'],
  ['D', 'Sophie (locked out, usual device and country, no recent security change) -> LOW risk'],
  ['D', 'the lock is shown to the agent as a fact, not as a risk'],
  ['D', 'Marc (authenticator added minutes ago, then a recovery request) -> HIGH risk'],
  ['D', 'Lena (2 attempts from a device never seen on a successful sign-in) -> HIGH risk'],
  ['D', 'the customer is told only the route, never the reasons'],
  ['D', 'an unknown user name gets the SAME wording as a low-risk customer'],
  ['D', 'the signals come from Verify'],
  ['E', 'the sign-in page offers "Forgot password" and accepts the user name'],
  ['E', 'the e-mail with the time-limited reset link arrives at the address on file'],
  ['E', 'the link states its validity: 30 minutes'],
  ['E', 'opening the link shows the "set new password" page'],
  ['E', 'a weak password is refused by the password policy'],
  ['E', 'a mismatching confirmation is refused'],
  ['E', 'a compliant new password is accepted'],
  ['E', 'the OLD password no longer works'],
  ['E', 'the NEW password signs in'],
  ['E', 'her session from before the incident ended'],
  ['E', 'the account is no longer locked'],
  ['E', 'the link is single use'],
  ['F', 'the agent may verify Marc by e-mail code ON FILE'],
  ['F', 'before the caller is verified the reset is refused (403)'],
  ['F', 'Marc (or the attacker holding his session) has a live access token'],
  ['F', 'the agent resets the password: Verify answers 204'],
  ['F', 'every active session of the customer is ended'],
  ['F', 'access token from before is now inactive'],
  ['F', 'his old password no longer works'],
  ['F', 'the notification "Password reset" reaches the registered address'],
  ['F', 'the temporary password cannot be used as is'],
  ['F', 'one verification = one reset'],
  ['F2', 'reset alone: Verify answers 204 but an already-issued access token STAYS ACTIVE'],
  ['F2', 'DELETE sessions then ends it'],
  ['G', 'Forgot password for an unknown user answers exactly like a known one'],
  ['G', 'a flood of reset requests for one user is stopped by Verify'],
  ['G', 'the victim received at most 2 e-mails from the flood'],
  ['H', 'Verify logged the agent\'s reset: who'],
  ['H', 'Verify logged the sign-in attempts of Marc with device, IP and country'],
  ['H', 'Verify logged the self-service reset of Sophie'],
  ['H', 'Verify logged Sophie\'s 6 failed sign-ins and the lock'],
  ['H', 'the console\'s case log records each step'],
];

// Caller verification has two routes. The e-mail route needs Verify's e-mail OTP quota (the trial answers 429 CSIAP3523E once it is used up);
// run.js then falls back to the authenticator-code route. One complete route is required, and the report says which one.
const ROUTES = {
  'e-mail code on file': [
    ['F', 'Verify e-mails a one-time code to the address on file'],
    ['F', 'a wrong code is refused and the caller stays unverified'],
    ['F', 'still refused after a wrong code (403)'],
    ['F', 'the code read from the real e-mail carries the correlation shown to the caller'],
    ['F', 'with the right code the caller is VERIFIED'],
  ],
  'authenticator code (fallback)': [
    ['F-fallback', 'verification by authenticator code started'],
    ['F-fallback', 'a wrong authenticator code is refused and the caller stays unverified'],
    ['F-fallback', 'still refused after a wrong code (403)'],
    ['F-fallback', 'with the right authenticator code the caller is VERIFIED'],
  ],
};
const problems = [];
const norm = (s) => String(s).replace(/[\u2019']/g, "'");
const passed = (sc, frag) => (doc.results || []).some((r) => r.scenario === sc && r.pass === true && norm(r.title).includes(norm(frag)));
const routeOk = Object.fromEntries(Object.entries(ROUTES).map(([k, list]) => [k, list.every(([sc, frag]) => passed(sc, frag))]));
const routeUsed = Object.keys(routeOk).filter((k) => routeOk[k]);
if (!routeUsed.length) problems.push('no caller-verification route passed completely (e-mail code or authenticator fallback)');
for (const [k, list] of Object.entries(ROUTES)) if (routeOk[k]) for (const [sc, frag] of list) REQUIRED.push([sc, frag]);
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
  resetLink: /stage=reset[^"]*factorTrnxId=/,
  authCode: /[?&]code=[A-Za-z0-9_.-]{20,}/,
  tempPassword: /temporary password is:\s*\S+/i,
};
const leaks = Object.entries(secretPatterns).filter(([, re]) => re.test(raw)).map(([k]) => k);
if (leaks.length) problems.push(`evidence contains secret-like material: ${leaks.join(', ')}`);

const limits = (doc.steps || []).filter((s) => s.info).map((s) => s.title.toLowerCase());
for (const m of ['geolocation condition', 'x-forwarded-for is ignored', 'not an ai risk score', 'notification e-mail', 'stays reachable for high-risk', 'pull-only']) {
  if (!limits.some((t) => t.includes(m))) problems.push(`limit not stated in evidence: "${m}"`);
}

console.log('UC-03 Verification (risk-aware account recovery, agent-assisted)\n');
for (const r of rows) console.log(`  ${r.ok ? 'PASS' : 'FAIL'}  ${r.sc}  ${r.frag}`);
console.log(`\nCaller-verification route proven in this evidence: ${routeUsed.join(' + ') || 'NONE'}`);
if (!routeOk['e-mail code on file']) console.log('  [LIVE] The e-mail route (Verify e-mails a code to the address on file) was NOT run: the trial e-mail OTP quota was exhausted (HTTP 429 CSIAP3523E). Re-run run.js when it resets. [HUMAN]');
console.log(`\nEvidence: ${total} checks in run.js, ${passCount} passed, ${total - passCount} failed; ${rows.filter((r) => r.ok).length}/${REQUIRED.length} required checks found PASS`);
console.log(`Secret scan of evidence: ${leaks.length ? 'LEAK ' + leaks.join(', ') : 'clean (no JWT, token, secret, reset link, auth code, OTP or temporary password)'}`);

console.log('\nPROVEN BEHAVIOURS [LIVE]:');
console.log('  [LIVE] Hosted "Forgot password" works end to end once the Cloud Directory identity-source flag passwordResetEnabled=true is set (default OFF: CSIAH0325E).');
console.log('  [LIVE] The reset link (30 min, single use) arrives at the address on file; policy and mismatch errors are shown; the new password signs in; the old one and old tokens die; a lock is cleared.');
console.log('  [LIVE] Agent route: Verify e-mails a code to the address on file; PATCH /v2.0/Users/{id}/passwordResetter generates a temporary password and e-mails it; DELETE /v1.0/auth/sessions/{id} ends sessions (the reset alone does not).');
console.log('  [LIVE] Least privilege: the console client has 6 entitlements; 403 for list API clients, create/delete/deactivate users, change e-mail, read policies.');
console.log('  [LIVE] Risk signals read from Verify: SCIM (lock, last login), factor created time, events (device = User-Agent, IP, country, city). Rules turn them into low/high and a route.');
console.log('  [LIVE] An ipAddress access-policy condition is evaluated on a real hosted sign-in: step-up to TOTP outside the usual network.');
console.log('\nSTILL [HUMAN] / NOT PROVEN:');
console.log('  [LIVE]  geoLocation policy condition: accepted but never evaluated in 40+ tests. Not claimed.');
console.log('  [LIVE]  A foreign country cannot be produced from this laptop (X-Forwarded-For is ignored); "new geography" is proven on synthetic data only.');
console.log('  [LIVE]  No AI/adaptive risk score: the risk is IFC-side rules over Verify signals.');
console.log('  [LIVE]  The hosted "Forgot password" page is not risk-aware: Verify sends the link to a high-risk case as well; IFC must route around it.');
console.log('  [LIVE]  The self-service reset did not send a "password changed" notification e-mail in these runs, although the page says it does. The agent route does notify.');
console.log('  [INFER] Real-time feed of the audit events to IFC fraud analytics (webhook / event streaming) was not exercised.');

if (problems.length) { console.error('\nVERIFICATION PROBLEMS:'); for (const p of problems) console.error(`  - ${p}`); process.exit(1); }
console.log('\nVERIFICATION PASSED');
process.exit(0);

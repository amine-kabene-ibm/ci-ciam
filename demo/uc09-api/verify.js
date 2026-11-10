'use strict';
// UC-09 verification: reads the evidence written by run.js (demo/out/uc09.json) and checks it.
// It does not call the tenant, so it is safe to run any time after run.js.
//   node demo/uc09-api/verify.js
// Exit 0 only if every required check passed, the evidence holds no secret material, and the limits section is present.
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'out', 'uc09.json');
if (!fs.existsSync(file)) { console.error(`No evidence at ${file}. Run: node demo/uc09-api/run.js`); process.exit(2); }
const raw = fs.readFileSync(file, 'utf8');
const doc = JSON.parse(raw);

// Each entry: [scenario, title fragment that must appear in a PASS result]. Missing or failed = FAIL.
const REQUIRED = [
  ['A', 'client assertion signed with the registered key'],
  ['A', 'the API accepts the token'],
  ['B', 'assertion signed with another key'],
  ['C', 'the client asks for ifc.policy.write'],
  ['C', 'the API refuses a token without ifc.policy.read'],
  ['D', 'no Authorization header'],
  ['D', 'a garbage token'],
  ['D', 'wrong authorization scheme'],
  ['D', 'a registered machine client that is NOT an IFC partner gets a token'],
  ['D', 'the API refuses the unlisted client'],
  ['E', 'token issued with DPoP proof'],
  ['E', 'API call with the token AND a proof'],
  ['E', 'same token with NO proof'],
  ['E', 'same token with a proof signed by a DIFFERENT key'],
  ['F', 'step 1: JWKS updated'],
  ['F', 'overlap: the OLD key still gets a token'],
  ['F', 'step 2: old key removed'],
  ['F', 'after retirement: the OLD key is refused'],
  ['G', 'policyholder signs in (password grant)'],
  ['G', 'partner exchanges the policyholder token'],
  ['G', 'the exchanged token is FOR the policyholder'],
  ['G', "the API accepts the delegated token for the policyholder's OWN policy"],
  ['G', 'the same delegated token is refused for ANOTHER policyholder'],
  ['H', 'exchange without an actor_token -> 400 CSIAQ5242E'],
  ['J', 'TLS handshake observed, and the edge sends NO CertificateRequest'],
];

const problems = [];
const passed = (sc, frag) => (doc.results || []).some((r) => r.scenario === sc && r.pass === true && r.title.includes(frag));
const rows = [];
for (const [sc, frag] of REQUIRED) {
  const ok = passed(sc, frag);
  rows.push({ sc, frag, ok });
  if (!ok) problems.push(`${sc}: not passed: "${frag}"`);
}

// Evidence must be complete and internally consistent.
const total = (doc.results || []).length;
const passCount = (doc.results || []).filter((r) => r.pass).length;
if (doc.total !== total || doc.passed !== passCount || doc.failed !== total - passCount) problems.push('summary counts do not match the results');
if (doc.failed !== 0) problems.push(`evidence reports ${doc.failed} failed check(s)`);
if (doc.tenant !== (process.env.OIDC_CI_BASE_URI || doc.tenant).replace(/\/+$/, '')) problems.push('evidence tenant differs from .env');

// Secret scan: no JWT, no private key, no token or secret field in the evidence. Counts only, values are never printed.
const secretPatterns = {
  jwt: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  privateKeyPem: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  tokenField: /"access_token"\s*:/,
  secretField: /"(client_?secret|secret|password)"\s*:/i,
};
const leaks = Object.entries(secretPatterns).filter(([, re]) => re.test(raw)).map(([k]) => k);
if (leaks.length) problems.push(`evidence contains secret-like material: ${leaks.join(', ')}`);

// Limits are part of the deliverable: they must be stated in the evidence, not silently dropped.
const limits = (doc.steps || []).filter((s) => s.info).map((s) => s.title);
const mustState = ['carries no `act` claim', 'actorcriteria', 'mtls client authentication is not demonstrated'];
for (const m of mustState) if (!limits.some((t) => t.toLowerCase().includes(m))) problems.push(`limit not stated in evidence: "${m}"`);

console.log('UC-09 verification (API security)\n');
for (const r of rows) console.log(`  ${r.ok ? 'PASS' : 'FAIL'}  ${r.sc}  ${r.frag}`);
console.log(`\nEvidence: ${total} checks in run.js, ${passCount} passed, ${total - passCount} failed; ${rows.filter((r) => r.ok).length}/${REQUIRED.length} required checks found PASS`);
console.log(`Secret scan of evidence: ${leaks.length ? 'LEAK ' + leaks.join(', ') : 'clean (no JWT, private key, token or secret fields)'}`);

console.log('\nLIMITS (stated, not failures):');
console.log('  [LIVE] The exchanged token has no `act` claim: the demo does not claim the actor is recorded in the token.');
console.log('  [LIVE] actorCriteria (CEL) on the STS client is not enforced: a disallowed actor still gets a token.');
console.log('  [LIVE] mTLS client authentication is not possible on this host: no CertificateRequest in the TLS handshake.');
console.log('  [LIVE] Scope on a delegated token comes only from the exchange request (scope=ifc.policy.read).');

if (problems.length) {
  console.log('\nVERIFY FAILED:');
  for (const p of problems) console.log(`  - ${p}`);
  process.exit(1);
}
console.log('\nVERIFY PASSED');
process.exit(0);

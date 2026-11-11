'use strict';
// UC-11 verification: checks the tenant state, runs the scenarios, inspects the evidence file.
//   node demo/uc11-migration/verify.js
// Result per check: PASS, FAIL, or HUMAN (cannot be proven without a person/browser/IBM enablement; never counted as a pass).
// Exit code 1 only if a FAIL exists.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const H = require('../../stubs/legacy-auth-store/hashes');
const c = require('./common');

const rows = [];
const add = (status, title, detail = '') => { rows.push({ status, title, detail }); console.log(`${status.padEnd(5)} ${title}${detail ? '  -- ' + detail : ''}`); };

(async () => {
  console.log('UC-11 verification\n');
  const st = c.state.read();
  if (!st || !st.migrator) { add('FAIL', 'setup state present (demo/out/uc11.state.json)', 'run: node demo/uc11-migration/setup.js'); process.exit(1); }

  // --- stub unit checks (offline) ---
  const sample = ['SSHA256', 'SHA256', 'SSHA384', 'SHA384', 'SSHA512', 'SHA512', 'SSHA', 'SHA', 'MD5', 'SMD5', 'SHA1', 'PBKDF2'];
  add(sample.every((s) => H.check(H.make(s, 'Pw-é-9!'), 'Pw-é-9!') && !H.check(H.make(s, 'Pw-é-9!'), 'Pw-é-8!')) ? 'PASS' : 'FAIL', `legacy stub verifies and rejects correctly for all ${sample.length} hash formats (incl. a non-ASCII password)`);
  add(H.make('SSHA256', 'x1').startsWith('{SSHA256}') && H.make('SSHA256', 'x1') !== H.make('SSHA256', 'x1') ? 'PASS' : 'FAIL', 'salted hashes differ between two runs for the same password');

  // --- tenant state ---
  const m = await idem.findApiClient(c.MIGRATOR);
  add(m && JSON.stringify([...m.entitlements].sort()) === JSON.stringify([...c.MIGRATOR_ENTITLEMENTS].sort()) ? 'PASS' : 'FAIL', `API client ${c.MIGRATOR} exists with exactly ${c.MIGRATOR_ENTITLEMENTS.length} entitlements (${c.MIGRATOR_ENTITLEMENTS.join(', ')})`, m ? `${m.entitlements.length} found` : 'missing');
  const apps = await idem.listApplications();
  for (const [name, grant] of [[c.LOGIN_APP, 'ropc'], [c.PORTAL_APP, 'authorizationCode']]) {
    const x = apps.find((a) => a.name === name);
    const g = x && await api('GET', x._links.self.href);
    const oc = g && g.status === 200 ? g.data.providers.oidc.properties : null;
    add(oc && String(oc.grantTypes[grant]) === 'true' ? 'PASS' : 'FAIL', `application ${name} exists with the ${grant === 'ropc' ? 'password (ropc)' : grant} grant`);
  }
  const users = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${c.P}"`, attributes: 'id', count: 5 } });
  add(users.data.totalResults === 0 ? 'PASS' : 'FAIL', 'the new platform is empty before cut-over (no ifc-demo-uc11 user)', `found ${users.data.totalResults}`);

  // --- scenarios ---
  console.log('\nRunning scenarios (demo/uc11-migration/run.js) ...');
  const run = spawnSync('node', [path.join(__dirname, 'run.js')], { encoding: 'utf8', timeout: 265000 });
  const lines = (run.stdout || '').split('\n');
  const fails = lines.filter((l) => /^\s+FAIL\s/.test(l));
  const summary = lines.find((l) => /checks passed/.test(l)) || `no summary (exit ${run.status}) ${(run.stderr || '').slice(0, 200)}`;
  add(run.status === 0 && !fails.length ? 'PASS' : 'FAIL', 'scenario run A-K (bulk import, hosted password change, just-in-time, rollback, least privilege; real tenant)', summary.trim());
  fails.forEach((l) => console.log('      ' + l.trim()));

  // --- evidence ---
  const evFile = path.join(__dirname, '..', 'out', 'uc11.json');
  let ev = null;
  try { ev = JSON.parse(fs.readFileSync(evFile, 'utf8')); } catch (e) { /* none */ }
  add(ev && ev.total > 0 && ev.passed === ev.total ? 'PASS' : 'FAIL', 'evidence file demo/out/uc11.json written', ev ? `${ev.passed}/${ev.total}` : 'missing');
  if (ev) {
    const raw = fs.readFileSync(evFile, 'utf8');
    const secrets = [...Object.values(st.users).map((u) => u.password), process.env.API_SECRET, st.migrator.clientSecret, st.login.clientSecret, st.login.registrationToken,
      st.portal.clientSecret, st.portal.registrationToken].filter(Boolean);
    const leaked = secrets.some((s) => raw.includes(s)) || /eyJ[A-Za-z0-9_-]{20,}\./.test(raw) || /\{S?SHA\d*\}[A-Za-z0-9+/=]{20,}/.test(raw);
    add(leaked ? 'FAIL' : 'PASS', 'evidence contains no passwords, secrets, JWTs or password hashes');
    const matrix = (ev.steps.find((s) => s.matrix) || {}).matrix || {};
    add(Object.keys(matrix).length === 12 ? 'PASS' : 'FAIL', 'the hash-format matrix is in the evidence (12 formats, tested live)', JSON.stringify(matrix));
  }
  const left = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${c.P}"`, attributes: 'id' } });
  add(left.data.totalResults === 0 ? 'PASS' : 'FAIL', 'the run leaves the tenant in the pre-cutover state (no migrated user left)', `found ${left.data.totalResults}`);

  // --- things only a human / IBM can prove ---
  add('HUMAN', 'what the audience sees in a real browser at http://localhost:4051 (gateway sign-in page) and the hosted Verify change-password page', 'scripted browser proves the protocol, not the pixels; see demo/uc11-migration/README.md');
  add('HUMAN', 'IFC\'s real legacy hash algorithm', 'the stub speaks 6 formats; IFC must name theirs. Verify imports 9 LDAP-style prefixes [LIVE]; anything else needs just-in-time. Ask IBM for the official supported list');
  add('HUMAN', 'native just-in-time migration inside Verify (Flow designer, or the Verify Bridge external-authentication agent)', 'Flow designer is off (403 CSIBZ0098E); Bridge is not provisioned (404 CSIBS0035E, create 401 CSIBS0033E): IBM must enable it, then build it with IBM');
  add('HUMAN', 'prior financial-services migration of comparable scale (the PDF asks for a reference architecture walkthrough and a customer reference)', 'IBM sales / client reference team; not something a script can show');
  add('HUMAN', 'scale: throughput of the bulk import for IFC\'s real volume', 'only tested at 11 records (1.4 to 7 s per job); ask IBM for limits and sizing');

  const f = rows.filter((r) => r.status === 'FAIL').length, h = rows.filter((r) => r.status === 'HUMAN').length;
  console.log(`\n${rows.filter((r) => r.status === 'PASS').length} PASS, ${f} FAIL, ${h} HUMAN`);
  process.exit(f ? 1 : 0);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

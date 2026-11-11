'use strict';
// UC-11 bulk migration tool: legacy extract -> CSV with pre-hashed passwords -> POST /v2.0/CSV/importUsers (async job) -> report.
//   node demo/uc11-migration/bulk.js [--reset login1,login2]     (needs serve.js running: it holds the legacy store)
// What it does, and why:
//   - reads /export from the legacy store (login, hash, profile + linkage attributes)
//   - SAFETY: only hashes in a format Verify's import understands go into the CSV. A hash Verify cannot read is NOT rejected by the
//     import: it is stored as the literal password string [LIVE, run.js scenario B]. Those users are left for just-in-time migration.
//   - two batches: "no forced reset" (the legacy password keeps working) and "forced reset" (the customer must choose a new password at
//     the first login). The reset list is the migration plan; default = the seed cohort "reset".
//   - reports what the job did, row by row for failures; imported logins are marked as migrated in the legacy store (cut-over tracking)
//   - runs with the least-privilege migrator API client (readUsers + manageUsers), never the admin client
const axios = require('axios');
const H = require('../../stubs/legacy-auth-store/hashes');
const c = require('./common');

async function migrateBulk({ legacyUrl, client, resetLogins, log = () => {} }) {
  const ex = await axios.get(`${legacyUrl}/export`, { validateStatus: () => true, timeout: 10000 });
  if (ex.status !== 200) throw new Error(`legacy export failed: HTTP ${ex.status}`);
  const rows = ex.data.map((r) => ({ login: r.login, hash: r.hash, scheme: r.schemeName, attrs: r.attrs }));
  const importable = rows.filter((r) => H.isVerifyImportable(r.scheme));
  const leftForJit = rows.filter((r) => !H.isVerifyImportable(r.scheme)).map((r) => ({ login: r.login, scheme: r.scheme }));
  const reset = new Set(resetLogins || []);
  const batches = [];
  for (const [label, noReset, list] of [['no forced reset', true, importable.filter((r) => !reset.has(r.login))], ['forced reset at first login', false, importable.filter((r) => reset.has(r.login))]]) {
    if (!list.length) continue;
    const res = await c.importUsersCsv(client, c.buildCsv(list), { noReset });
    batches.push({ label, noReset, logins: list.map((r) => r.login), ...res });
    log(`  batch "${label}": ${res.accepted ? `job ${res.state}, ${res.processed}/${res.total} imported, ${(res.errors || []).length} error(s), ${res.ms} ms` : `NOT ACCEPTED (HTTP ${res.status})`}`);
    for (const e of res.errors || []) log(`    row failed: ${e.id}: ${e.reason}`);
    const failed = new Set((res.errors || []).map((e) => e.id));
    for (const r of list) if (!failed.has(r.login)) await axios.post(`${legacyUrl}/migrated`, { username: r.login }, { validateStatus: () => true });
  }
  return { extracted: rows.length, importable: importable.length, leftForJit, batches };
}

module.exports = { migrateBulk };

if (require.main === module) {
  (async () => {
    const st = c.state.read();
    if (!st || !st.migrator) { console.error('Run setup first: node demo/uc11-migration/setup.js'); process.exit(1); }
    const arg = process.argv.indexOf('--reset');
    const reset = arg > 0 ? process.argv[arg + 1].split(',') : c.cohort('reset').map(c.userNameOf);
    const rep = await migrateBulk({ legacyUrl: c.LEGACY_URL, client: c.migratorClient(st), resetLogins: reset, log: console.log });
    console.log(`\nextracted ${rep.extracted}, imported by bulk ${rep.batches.reduce((n, b) => n + (b.processed || 0), 0)}, left for just-in-time: ${rep.leftForJit.map((x) => `${x.login.replace(c.P, '')} (${x.scheme})`).join(', ') || 'none'}`);
  })().catch((e) => { console.error(e.message || e); process.exit(2); });
}

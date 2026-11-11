'use strict';
// UC-11 helper for the live demo: shows the state of the migration in one table (legacy store vs. Verify).
//   node demo/uc11-migration/show.js           (needs serve.js running)
// Per person: the legacy hash format, whether the user exists in Verify, and the linkage attributes there. Never prints passwords or hashes.
const axios = require('axios');
const c = require('./common');

(async () => {
  const st = c.state.read();
  if (!st || !st.migrator) { console.error('Run setup first: node demo/uc11-migration/setup.js'); process.exit(1); }
  const mig = c.migratorClient(st);
  const ex = await axios.get(`${c.LEGACY_URL}/export`, { validateStatus: () => true }).catch(() => null);
  if (!ex || ex.status !== 200) { console.error('The legacy store is not reachable. Start it: node demo/uc11-migration/serve.js'); process.exit(1); }
  console.log('person'.padEnd(10), 'legacy hash'.padEnd(10), 'in Verify'.padEnd(10), 'policy / brokerage', ' ', 'legacy id');
  for (const s of c.SEED) {
    const u = await c.verifyUser(c.userNameOf(s), mig);
    const l = c.linkageOf(u) || {};
    const rec = ex.data.find((r) => r.login === c.userNameOf(s));
    console.log(s.key.padEnd(10), `{${rec.schemeName}}`.padEnd(10), (u ? 'yes' : 'no').padEnd(10), `${l.accountId || l.department || '-'}${l.employeeNumber ? ' / ' + l.employeeNumber : ''}`.padEnd(22), l.externalId || '-', rec.migratedAt ? '(marked migrated)' : '');
  }
  const stats = (await axios.get(`${c.LEGACY_URL}/_stats`)).data;
  console.log(`\nlegacy store: ${stats.verifyCalls} password-verify call(s), ${stats.migrated} record(s) marked migrated`);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

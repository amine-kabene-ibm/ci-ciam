'use strict';
// UC-11 rollback: undo a migration without touching the legacy store.
//   node demo/uc11-migration/rollback.js              (needs serve.js running)
// The legacy store stays authoritative until cut-over is declared final: it is never written except for the "migrated" marker.
// Rolling back = delete the migrated users from Verify (DELETE /v2.0/Users/{id}, with the migrator client) and clear the markers.
// Customers can still sign in with the legacy password at the legacy system, and a later bulk run or just-in-time login migrates them again.
const axios = require('axios');
const c = require('./common');

async function rollback({ legacyUrl, client, logins }) {
  const out = { deleted: [], absent: [], failed: [] };
  for (const login of logins) {
    const u = await c.verifyUser(login, client);
    if (!u) out.absent.push(login);
    else {
      const d = await client.api('DELETE', `/v2.0/Users/${u.id}`, { quiet: true });
      (d.status === 204 ? out.deleted : out.failed).push(login);
    }
    await axios.post(`${legacyUrl}/migrated`, { username: login, clear: true }, { validateStatus: () => true });
  }
  return out;
}

module.exports = { rollback };

if (require.main === module) {
  (async () => {
    const st = c.state.read();
    if (!st || !st.migrator) { console.error('Run setup first: node demo/uc11-migration/setup.js'); process.exit(1); }
    const r = await rollback({ legacyUrl: c.LEGACY_URL, client: c.migratorClient(st), logins: c.SEED.map(c.userNameOf) });
    console.log(`rolled back: ${r.deleted.length} deleted from Verify, ${r.absent.length} were not there, ${r.failed.length} failed`);
    process.exit(r.failed.length ? 1 : 0);
  })().catch((e) => { console.error(e.message || e); process.exit(2); });
}

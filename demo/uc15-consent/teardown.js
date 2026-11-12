'use strict';
// UC-15 teardown.js — removes all ifc-demo-uc15-* objects from the tenant.
// Also disables ropc on TrustMeInsurance (re-enabled only when UC-15 setup runs).
// Run: node demo/uc15-consent/teardown.js

const { api, stateFile } = require('../lib/verify');
const {
  PURPOSES, CLIENTS, APP_ID,
  listPurposesByPrefix, deletePurpose, deleteUsersByPrefix, deleteApplicationsByPrefix,
  deleteConsentsForUser,
} = require('./common');

const sf = stateFile('uc15');

async function main() {
  console.log('UC-15 teardown');

  // ── 1. Consent records ────────────────────────────────────────────────────
  const st = sf.read();
  if (st && st.user && st.user.id) {
    const del = await deleteConsentsForUser(st.user.id);
    console.log(`  consent records: deleted=${del.deleted} status=${del.status}`);
  }

  // ── 2. Users ──────────────────────────────────────────────────────────────
  const users = await deleteUsersByPrefix('ifc-demo-uc15-');
  for (const u of users) console.log(`  user ${u.userName}  status=${u.status}`);
  if (!users.length) console.log('  users: none');

  // ── 3. DCR clients (applications) ─────────────────────────────────────────
  const apps = await deleteApplicationsByPrefix('ifc-demo-uc15-');
  for (const a of apps) console.log(`  app ${a.name}  status=${a.status}`);
  if (!apps.length) console.log('  applications: none');

  // ── 4. Purposes ───────────────────────────────────────────────────────────
  const purposes = await listPurposesByPrefix('ifc-demo-uc15-');
  for (const p of purposes) {
    const st2 = await deletePurpose(p.id);
    console.log(`  purpose ${p.id}  status=${st2}`);
  }
  if (!purposes.length) console.log('  purposes: none');

  // ── 5. Disable ropc on TrustMeInsurance ───────────────────────────────────
  const r = await api('GET', `/appaccess/v1.0/applications/${APP_ID}`);
  if (r.status === 200) {
    const doc = r.data;
    if (doc.providers.oidc.properties.grantTypes.ropc === 'true') {
      delete doc.customIcon;
      doc.providers.oidc.properties.grantTypes.ropc = 'false';
      const p2 = await api('PUT', `/appaccess/v1.0/applications/${APP_ID}`, { body: doc });
      console.log(`  ropc on TrustMeInsurance disabled  status=${p2.status}`);
    } else {
      console.log('  ropc on TrustMeInsurance: already off');
    }
  }

  // ── 6. Remove state file ──────────────────────────────────────────────────
  sf.remove();
  console.log('  state file removed');

  console.log('\nUC-15 teardown complete.');
}

main().catch((e) => { console.error('[TEARDOWN ERROR]', e.message); process.exit(1); });

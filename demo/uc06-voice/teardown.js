'use strict';
// UC-06 teardown: removes everything UC-06 created on the tenant, plus local state/evidence artefacts.
//   node demo/uc06-voice/teardown.js
// Removes: user ifc-demo-uc06-* (this also deletes the TOTP enrolment; IBM Verify app registrations are deleted first),
//          API client ifc-demo-uc06-ccaas, demo/out/uc06.state.json, the QR image.
// Keeps:   demo/out/uc06.json (evidence). For the full tenant sweep use: node demo/teardown-all.js
const fs = require('fs');
const path = require('path');
const { api, PREFIX, OUT_DIR } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { state } = require('./common');

(async () => {
  const users = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${PREFIX}uc06-"`, attributes: 'id,userName', count: 100 } });
  for (const u of (users.data && users.data.Resources) || []) {
    const t = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${u.id}"` }, quiet: true });
    for (const e of (t.data && t.data.totp) || []) await api('DELETE', `/v2.0/factors/totp/${e.id}`, { quiet: true });
    console.log(`  delete user ${u.userName}`.padEnd(46), (await idem.deleteUser(u.id)).status);
  }
  for (const c of await idem.deleteApiClientsByPrefix(`${PREFIX}uc06-`)) console.log(`  delete API client ${c.clientName}`.padEnd(46), c.status);
  state.remove();
  try { fs.unlinkSync(path.join(OUT_DIR, 'uc06-enroll-qr.png')); } catch (e) { /* none */ }

  const left = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${PREFIX}uc06-"`, attributes: 'id' } });
  const cl = await idem.findApiClient(`${PREFIX}uc06-ccaas`);
  const ok = left.data.totalResults === 0 && !cl;
  console.log(ok ? '\nUC-06 teardown complete: nothing named ifc-demo-uc06-* is left.' : '\nTEARDOWN INCOMPLETE');
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(2); });

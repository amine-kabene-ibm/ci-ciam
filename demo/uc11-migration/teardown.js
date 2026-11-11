'use strict';
// UC-11 teardown: removes everything UC-11 created on the tenant, plus local state.
//   node demo/uc11-migration/teardown.js
// Removes: users ifc-demo-uc11-*, applications ifc-demo-uc11-*, API client ifc-demo-uc11-migrator, demo/out/uc11.state.json.
// Keeps:   demo/out/uc11.json (evidence). For the full tenant sweep use: node demo/teardown-all.js
const { api, PREFIX } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { state } = require('./common');

(async () => {
  const P = `${PREFIX}uc11-`;
  const users = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id,userName', count: 200 } });
  for (const u of (users.data && users.data.Resources) || []) {
    await api('DELETE', `/v1.0/auth/sessions/${u.id}`, { quiet: true });
    console.log(`  delete user ${u.userName}`.padEnd(50), (await idem.deleteUser(u.id)).status);
  }
  for (const x of await idem.deleteApplicationsByPrefix(P)) console.log(`  delete application ${x.name}`.padEnd(50), x.status);
  for (const x of await idem.deleteApiClientsByPrefix(P)) console.log(`  delete api client ${x.clientName}`.padEnd(50), x.status);
  state.remove();

  const left = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id' } });
  const nApp = (await idem.listApplications()).filter((x) => x.name.startsWith(P)).length;
  const nCli = (((await api('GET', '/v1.0/apiclients')).data || {}).apiClients || []).filter((x) => x.clientName.startsWith(P)).length;
  const ok = left.data.totalResults === 0 && !nApp && !nCli;
  console.log(ok ? `\nUC-11 teardown complete: nothing named ${P}* is left.` : `\nTEARDOWN INCOMPLETE (users ${left.data.totalResults}, apps ${nApp}, api clients ${nCli})`);
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

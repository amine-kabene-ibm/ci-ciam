'use strict';
// UC-12 teardown: removes everything UC-12 created on the tenant, plus local state.
//   node demo/uc12-rebac/teardown.js
// Removes: users ifc-demo-uc12-*, application ifc-demo-uc12-login, STS client ifc-demo-uc12-gateway, API client ifc-demo-uc12-sync,
//          demo/out/uc12.state.json, and any engine / gateway process this demo left running.
// Keeps:   demo/out/uc12.json (evidence) and demo/out/bin/openfga (the downloaded binary). Full tenant sweep: node demo/teardown-all.js
const { execSync } = require('child_process');
const { api, PREFIX } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { state } = require('./common');

(async () => {
  const P = `${PREFIX}uc12-`;
  for (const pat of ['uc12-rebac/serve.js', 'demo/out/bin/openfga run']) { try { execSync(`pkill -f "${pat}"`); console.log(`  stopped process: ${pat}`); } catch (e) { /* none running */ }}
  const users = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id,userName', count: 200 } });
  for (const u of (users.data && users.data.Resources) || []) {
    await api('DELETE', `/v1.0/auth/sessions/${u.id}`, { quiet: true });
    console.log(`  delete user ${u.userName}`.padEnd(50), (await idem.deleteUser(u.id)).status);
  }
  for (const x of await idem.deleteApplicationsByPrefix(P)) console.log(`  delete application ${x.name}`.padEnd(50), x.status);
  for (const x of await idem.deleteStsClientsByPrefix(P)) console.log(`  delete sts client ${x.clientName}`.padEnd(50), x.status);
  for (const x of await idem.deleteApiClientsByPrefix(P)) console.log(`  delete api client ${x.clientName}`.padEnd(50), x.status);
  state.remove();

  const left = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id' } });
  const nApp = (await idem.listApplications()).filter((x) => x.name.startsWith(P)).length;
  const nSts = (((await api('GET', '/v1.0/sts/oauth/clients')).data || {}).clients || []).filter((x) => x.clientName.startsWith(P)).length;
  const nCli = (((await api('GET', '/v1.0/apiclients')).data || {}).apiClients || []).filter((x) => x.clientName.startsWith(P)).length;
  const ok = left.data.totalResults === 0 && !nApp && !nSts && !nCli;
  console.log(ok ? `\nUC-12 teardown complete: nothing named ${P}* is left.` : `\nTEARDOWN INCOMPLETE (users ${left.data.totalResults}, apps ${nApp}, sts ${nSts}, api clients ${nCli})`);
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

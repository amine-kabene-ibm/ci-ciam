'use strict';
// UC-07 teardown: removes everything UC-07 created on the tenant, plus local state.
//   node demo/uc07-handoff/teardown.js
// Removes: user ifc-demo-uc07-* (this also deletes the TOTP enrolment), API client ifc-demo-uc07-ccaas,
//          STS client ifc-demo-uc07-ccaas-sts, application ifc-demo-uc07-mobile-app, demo/out/uc07.state.json.
// Keeps:   demo/out/uc07.json (evidence). For the full tenant sweep use: node demo/teardown-all.js
const { api, PREFIX } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { state } = require('./common');

(async () => {
  const P = `${PREFIX}uc07-`;
  const users = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id,userName', count: 100 } });
  for (const u of (users.data && users.data.Resources) || []) {
    const t = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${u.id}"` }, quiet: true });
    for (const e of (t.data && t.data.totp) || []) await api('DELETE', `/v2.0/factors/totp/${e.id}`, { quiet: true });
    console.log(`  delete user ${u.userName}`.padEnd(50), (await idem.deleteUser(u.id)).status);
  }
  for (const x of await idem.deleteApiClientsByPrefix(P)) console.log(`  delete API client ${x.clientName}`.padEnd(50), x.status);
  for (const x of await idem.deleteStsClientsByPrefix(P)) console.log(`  delete STS client ${x.clientName}`.padEnd(50), x.status);
  for (const x of await idem.deleteApplicationsByPrefix(P)) console.log(`  delete application ${x.name}`.padEnd(50), x.status);
  state.remove();

  const left = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id' } });
  const nApi = (await api('GET', '/v1.0/apiclients')).data.apiClients.filter((x) => x.clientName.startsWith(P)).length;
  const nSts = ((await api('GET', '/v1.0/sts/oauth/clients')).data.clients || []).filter((x) => x.clientName.startsWith(P)).length;
  const nApp = (await idem.listApplications()).filter((x) => x.name.startsWith(P)).length;
  const ok = left.data.totalResults === 0 && !nApi && !nSts && !nApp;
  console.log(ok ? `\nUC-07 teardown complete: nothing named ${P}* is left.` : '\nTEARDOWN INCOMPLETE');
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

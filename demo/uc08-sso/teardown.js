'use strict';
// UC-08 teardown: removes everything UC-08 created on the tenant, plus local state.
//   node demo/uc08-sso/teardown.js
// Removes: users ifc-demo-uc08-* (this also deletes the TOTP enrolment), groups, access policies, applications ifc-demo-uc08-*, demo/out/uc08.state.json.
// Keeps:   demo/out/uc08.json (evidence). For the full tenant sweep use: node demo/teardown-all.js
const { api, PREFIX } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { state } = require('./common');

(async () => {
  const P = `${PREFIX}uc08-`;
  const users = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id,userName', count: 100 } });
  for (const u of (users.data && users.data.Resources) || []) {
    await api('DELETE', `/v1.0/auth/sessions/${u.id}`, { quiet: true });
    const t = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${u.id}"` }, quiet: true });
    for (const e of (t.data && t.data.totp) || []) await api('DELETE', `/v2.0/factors/totp/${e.id}`, { quiet: true });
    console.log(`  delete user ${u.userName}`.padEnd(50), (await idem.deleteUser(u.id)).status);
  }
  for (const x of await idem.deleteApplicationsByPrefix(P)) console.log(`  delete application ${x.name}`.padEnd(50), x.status);
  for (const x of await idem.deletePoliciesByPrefix(P)) console.log(`  delete policy ${x.name}`.padEnd(50), x.status);
  for (const x of await idem.deleteGroupsByPrefix(P)) console.log(`  delete group ${x.displayName}`.padEnd(50), x.status);
  state.remove();

  const left = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id' } });
  const nApp = (await idem.listApplications()).filter((x) => x.name.startsWith(P)).length;
  const nPol = (((await api('GET', '/v5.0/policyvault/accesspolicy', { query: { search: `name contains "${P}"` } })).data || {}).policies || []).filter((p) => p.name.startsWith(P)).length;
  const nGrp = (((await api('GET', '/v2.0/Groups', { query: { filter: `displayName sw "${P}"` } })).data || {}).Resources || []).length;
  const ok = left.data.totalResults === 0 && !nApp && !nPol && !nGrp;
  console.log(ok ? `\nUC-08 teardown complete: nothing named ${P}* is left.` : `\nTEARDOWN INCOMPLETE (users ${left.data.totalResults}, apps ${nApp}, policies ${nPol}, groups ${nGrp})`);
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

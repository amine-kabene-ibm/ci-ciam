'use strict';
// UC-09 teardown: removes everything UC-09 created on the tenant, plus local state (keys and secrets).
//   node demo/uc09-api/teardown.js
// Removes: applications ifc-demo-uc09-* (the DCR machine clients and the password-grant client; their secrets go with them),
//          the STS client ifc-demo-uc09-partner, the user ifc-demo-uc09-policyholder, and demo/out/uc09.state.json.
// Keeps:   demo/out/uc09.json (evidence). For the full tenant sweep use: node demo/teardown-all.js
const { api, PREFIX } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { state } = require('./common');

(async () => {
  const P = `${PREFIX}uc09-`;
  const users = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id,userName', count: 100 } });
  for (const u of (users.data && users.data.Resources) || []) {
    console.log(`  delete user ${u.userName}`.padEnd(56), (await idem.deleteUser(u.id)).status);
  }
  for (const x of await idem.deleteApplicationsByPrefix(P)) console.log(`  delete application ${x.name}`.padEnd(56), x.status);
  for (const x of await idem.deleteStsClientsByPrefix(P)) console.log(`  delete sts client ${x.clientName}`.padEnd(56), x.status);
  state.remove();

  const left = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id' } });
  const nApp = (await idem.listApplications()).filter((x) => x.name.startsWith(P)).length;
  const nSts = (((await api('GET', '/v1.0/sts/oauth/clients')).data || {}).clients || []).filter((x) => x.clientName.startsWith(P)).length;
  const ok = left.data.totalResults === 0 && !nApp && !nSts;
  console.log(ok ? `\nUC-09 teardown complete: nothing named ${P}* is left.` : `\nTEARDOWN INCOMPLETE (users ${left.data.totalResults}, apps ${nApp}, sts clients ${nSts})`);
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

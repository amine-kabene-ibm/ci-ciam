'use strict';
// UC-10 teardown: removes everything UC-10 created on the tenant, plus local state.
//   node demo/uc10-brands/teardown.js
// Removes: users ifc-demo-uc10-* (this also deletes the TOTP enrolment and the administrators' role grants), applications ifc-demo-uc10-*
//          (this also removes their entitlements), access policies, branding themes (none exist on the trial), demo/out/uc10.state.json.
// Keeps:   demo/out/uc10.json (evidence), demo/out/themes/ (built ZIPs). For the full tenant sweep use: node demo/teardown-all.js
const { api, PREFIX } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { state } = require('./common');

(async () => {
  const P = `${PREFIX}uc10-`;
  const users = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id,userName', count: 100 } });
  for (const u of (users.data && users.data.Resources) || []) {
    await api('DELETE', `/v1.0/auth/sessions/${u.id}`, { quiet: true });
    const t = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${u.id}"` }, quiet: true });
    for (const e of (t.data && t.data.totp) || []) await api('DELETE', `/v2.0/factors/totp/${e.id}`, { quiet: true });
    console.log(`  delete user ${u.userName}`.padEnd(50), (await idem.deleteUser(u.id)).status);
  }
  for (const x of await idem.deleteApplicationsByPrefix(P)) console.log(`  delete application ${x.name}`.padEnd(50), x.status);
  for (const x of await idem.deletePoliciesByPrefix(P)) console.log(`  delete policy ${x.name}`.padEnd(50), x.status);
  const th = await api('GET', '/v1.0/branding/themes', { quiet: true });
  for (const x of ((th.data && th.data.themeRegistrations) || []).filter((y) => y.name.startsWith(P))) console.log(`  delete theme ${x.name}`.padEnd(50), (await api('DELETE', `/v1.0/branding/themes/${x.id}`, { quiet: true })).status);
  state.remove();

  const left = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id' } });
  const nApp = (await idem.listApplications()).filter((x) => x.name.startsWith(P)).length;
  const nPol = (((await api('GET', '/v5.0/policyvault/accesspolicy', { query: { search: `name contains "${P}"` } })).data || {}).policies || []).filter((p) => p.name.startsWith(P)).length;
  const th2 = await api('GET', '/v1.0/branding/themes', { quiet: true });
  const nTh = ((th2.data && th2.data.themeRegistrations) || []).filter((y) => y.name.startsWith(P)).length;
  const ok = left.data.totalResults === 0 && !nApp && !nPol && !nTh;
  console.log(ok ? `\nUC-10 teardown complete: nothing named ${P}* is left.` : `\nTEARDOWN INCOMPLETE (users ${left.data.totalResults}, apps ${nApp}, policies ${nPol}, themes ${nTh})`);
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

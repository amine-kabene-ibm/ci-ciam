'use strict';
// UC-02 teardown: removes everything UC-02 created on the tenant, plus local state.
//   node demo/uc02-passkeys/teardown.js
// Removes: SMS provider then its webhook, users ifc-demo-uc02-* (this also deletes their passkeys and TOTP enrolments), applications, access policies,
//          demo/out/uc02.state.json.  Keeps: demo/out/uc02.json (evidence). Never touches the tenant's default FIDO2 relying party.
// For the full tenant sweep (all use cases) use: node demo/teardown-all.js
const { api, PREFIX } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { state } = require('./common');

(async () => {
  const P = `${PREFIX}uc02-`;
  for (const x of await idem.deleteSmsGatewaysByPrefix(P)) console.log(`  delete sms ${x.kind} ${x.name}`.padEnd(50), x.status);
  const users = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id,userName', count: 100 } });
  for (const u of (users.data && users.data.Resources) || []) {
    await api('DELETE', `/v1.0/auth/sessions/${u.id}`, { quiet: true });
    const n = await idem.deleteFidoRegistrations(u.id);
    const t = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${u.id}"` }, quiet: true });
    for (const e of (t.data && t.data.totp) || []) await api('DELETE', `/v2.0/factors/totp/${e.id}`, { quiet: true });
    console.log(`  delete user ${u.userName}`.padEnd(50), (await idem.deleteUser(u.id)).status, n ? `(${n} passkey(s) removed first)` : '');
  }
  for (const x of await idem.deleteApplicationsByPrefix(P)) console.log(`  delete application ${x.name}`.padEnd(50), x.status);
  for (const x of await idem.deletePoliciesByPrefix(P)) console.log(`  delete policy ${x.name}`.padEnd(50), x.status);
  state.remove();

  const left = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${P}"`, attributes: 'id' } });
  const nApp = (await idem.listApplications()).filter((x) => x.name.startsWith(P)).length;
  const nPol = (((await api('GET', '/v5.0/policyvault/accesspolicy', { query: { search: `name contains "${P}"` } })).data || {}).policies || []).filter((p) => p.name.startsWith(P)).length;
  const nSms = (await idem.listSmsProviders()).filter((x) => x.name.startsWith(P)).length + (await idem.listWebhooks()).filter((x) => x.name.startsWith(P)).length;
  const nKeys = (((await api('GET', '/v2.0/factors/fido2/registrations', { quiet: true })).data || {}).fido2 || []).length;
  const ok = left.data.totalResults === 0 && !nApp && !nPol && !nSms;
  console.log(ok ? `\nUC-02 teardown complete: nothing named ${P}* is left (passkey registrations on the tenant: ${nKeys}).` : `\nTEARDOWN INCOMPLETE (users ${left.data.totalResults}, apps ${nApp}, policies ${nPol}, sms objects ${nSms})`);
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

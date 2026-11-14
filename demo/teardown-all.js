'use strict';
// Deletes every tenant object whose name starts with "ifc-demo-". Safe to re-run.
//   node demo/teardown-all.js            delete everything and list what is left
//   node demo/teardown-all.js --list     only list (dry run)
// Covers: users, groups, API clients, applications (includes DCR clients), access policies, STS clients, branding themes, SMS providers, webhooks, privacy purposes, custom attributes,
// authenticator clients (UC-04: the "own branded app" registration profile).
// FIDO2 registrations and IBM Verify device registrations (UC-04) go with their user.
// Not covered on purpose: objects the base app creates in /setup (TrustMeInsurance, MFAGroup, ...).
const { api, PREFIX } = require('./lib/verify');
const idem = require('./lib/idempotent');

const listOnly = process.argv.includes('--list');

async function inventory() {
  const inv = { users: [], groups: [], apiClients: [], applications: [], policies: [], stsClients: [], themes: [], smsProviders: [], webhooks: [], purposes: [], attributes: [], authClients: [] };

  const u = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${PREFIX}"`, attributes: 'id,userName', count: 200 } });
  inv.users = ((u.data && u.data.Resources) || []).map((x) => ({ id: x.id, name: x.userName }));

  const g = await api('GET', '/v2.0/Groups', { query: { filter: `displayName sw "${PREFIX}"` } });
  inv.groups = ((g.data && g.data.Resources) || []).map((x) => ({ id: x.id, name: x.displayName }));

  // Members of an ifc-demo-* group are demo users too, even when their user name is a real e-mail address (UC-01: a person
  // who registers in the portal with their own mailbox is added to ifc-demo-uc01-customers).
  for (const grp of inv.groups) {
    const gd = await api('GET', `/v2.0/Groups/${grp.id}`, { quiet: true });
    for (const m of (gd.data && gd.data.members) || []) {
      if (m.type !== 'user' && m.type !== undefined) continue;
      if (!inv.users.some((x) => x.id === m.value)) inv.users.push({ id: m.value, name: m.display || m.value });
    }
  }

  const c = await api('GET', '/v1.0/apiclients');
  inv.apiClients = ((c.data && c.data.apiClients) || []).filter((x) => x.clientName.startsWith(PREFIX)).map((x) => ({ id: x.id, name: x.clientName }));

  const a = await api('GET', '/v1.0/applications');
  inv.applications = (((a.data && a.data._embedded) || {}).applications || [])
    .filter((x) => x.name.startsWith(PREFIX)).map((x) => ({ id: x._links.self.href, name: x.name }));

  const p = await api('GET', '/v5.0/policyvault/accesspolicy');
  inv.policies = ((p.data && p.data.policies) || []).filter((x) => x.name.startsWith(PREFIX)).map((x) => ({ id: x.id, name: x.name }));

  const s = await api('GET', '/v1.0/sts/oauth/clients');
  inv.stsClients = ((s.data && s.data.clients) || []).filter((x) => x.clientName.startsWith(PREFIX)).map((x) => ({ id: x.clientId, name: x.clientName }));

  const t = await api('GET', '/v1.0/branding/themes');
  inv.themes = ((t.data && t.data.themeRegistrations) || []).filter((x) => x.name.startsWith(PREFIX)).map((x) => ({ id: x.id, name: x.name }));

  inv.smsProviders = (await idem.listSmsProviders()).filter((x) => x.name.startsWith(PREFIX)).map((x) => ({ id: x.id, name: x.name }));

  const w = await api('GET', '/config/v1.0/webhooks/', { quiet: true });
  inv.webhooks = ((w.data && w.data.webhooks) || []).filter((x) => x.name.startsWith(PREFIX)).map((x) => ({ id: x.id, name: x.name }));

  const pur = await api('GET', '/dpcm-mgmt/config/v1.0/privacy/purposes', { quiet: true });
  inv.purposes = ((pur.data && pur.data.purposes) || []).filter((x) => x.id.startsWith(PREFIX)).map((x) => ({ id: x.id, name: x.id }));

  inv.attributes = (await idem.listTenantAttributes()).filter((x) => x.name.startsWith(PREFIX)).map((x) => ({ id: x.id, name: x.name }));

  const ac = await api('GET', '/v1.0/authenticators/clients', { quiet: true });
  inv.authClients = ((ac.data && ac.data.clients) || []).filter((x) => (x.name || '').startsWith(PREFIX)).map((x) => ({ id: x.id, name: x.name }));
  return inv;
}

const count = (inv) => Object.values(inv).reduce((n, l) => n + l.length, 0);

async function main() {
  let inv = await inventory();
  if (!listOnly) {
    for (const x of inv.users) console.log('  delete user       ', x.name, (await idem.deleteUser(x.id)).status);
    for (const x of inv.groups) console.log('  delete group      ', x.name, (await api('DELETE', `/v2.0/Groups/${x.id}`, { quiet: true })).status);
    for (const x of inv.apiClients) console.log('  delete api client ', x.name, (await api('DELETE', `/v1.0/apiclients/${x.id}`, { quiet: true })).status);
    for (const x of inv.applications) console.log('  delete application', x.name, (await api('DELETE', x.id, { quiet: true })).status);
    for (const x of inv.policies) console.log('  delete policy     ', x.name, (await api('DELETE', `/v5.0/policyvault/accesspolicy/${x.id}`, { quiet: true })).status);
    for (const x of inv.stsClients) console.log('  delete sts client ', x.name, (await api('DELETE', `/v1.0/sts/oauth/clients/${x.id}`, { quiet: true })).status);
    for (const x of inv.themes) console.log('  delete theme      ', x.name, (await api('DELETE', `/v1.0/branding/themes/${x.id}`, { quiet: true })).status);
    for (const x of inv.smsProviders) console.log('  delete sms provider', x.name, (await api('DELETE', `/config/v1.0/smsproviders/${x.id}`, { quiet: true })).status); // before its webhook
    for (const x of inv.webhooks) console.log('  delete webhook    ', x.name, (await api('DELETE', `/config/v1.0/webhooks/${x.id}`, { quiet: true })).status);
    for (const x of inv.purposes) {
      // Must dissociate from any app before deleting [LIVE 2026-11-12: CSIBT0012E otherwise]
      await api('PATCH', '/dpcm-mgmt/config/v1.0/privacy/purpose-relationships', {
        body: [{ op: 'remove', value: { extCategory: 'app', extId: '3258669560154975753', purposeId: x.id } }], quiet: true,
      });
      console.log('  delete purpose    ', x.name, (await api('DELETE', `/dpcm-mgmt/config/v1.0/privacy/purposes/${encodeURIComponent(x.id)}`, { quiet: true })).status);
    }
    for (const x of inv.attributes) console.log('  delete attribute  ', x.name, (await api('DELETE', `/v1.0/attributes/${x.id}`, { quiet: true })).status);
    for (const x of inv.authClients) console.log('  delete authenticator client', x.name, (await api('DELETE', `/v1.0/authenticators/clients/${x.id}`, { quiet: true })).status);
    // UC-03 switched the hosted "Forgot password" on for the whole tenant (not an ifc-demo-* object): switch it back off.
    if (await idem.hostedPasswordResetEnabled()) console.log('  restore tenant setting: hosted Forgot password OFF (UC-03)', JSON.stringify(await idem.setHostedPasswordReset(false)));
    inv = await inventory();
  }
  console.log(`\nObjects named "${PREFIX}*" on the tenant now: ${count(inv)}`);
  for (const [k, list] of Object.entries(inv)) console.log(`  ${k.padEnd(13)} ${list.length}${list.length ? '  ' + list.map((x) => x.name).join(', ') : ''}`);
  console.log(`  tenant setting: hosted Forgot password ${(await idem.hostedPasswordResetEnabled()) ? 'ON (UC-03 setup left it on)' : 'OFF (default)'}`);
  process.exit(!listOnly && count(inv) > 0 ? 1 : 0);
}

main().catch((e) => { console.error(e.message); process.exit(2); });

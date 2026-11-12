'use strict';
// UC-01 setup (self-service registration + progressive profiling). Idempotent.
//   node demo/uc01-registration/setup.js
// Creates on the tenant:
//   - custom attributes  ifc-demo-uc01-client360-id, -policy-number (unique), -has-vehicle   (SCIM names client360Id, policyNumber, hasVehicle)
//   - group              ifc-demo-uc01-customers   (every self-registered customer is added)
//   - api client         ifc-demo-uc01-registration (readUsers, manageUsers, authnAnyUser, manageGroupMembers): the registration service's identity
//   - application        ifc-demo-uc01-portal       (DCR: authorization code + PKCE for the portal, password grant for scripted sign-in)
// No customer is created here: customers register themselves (that is the use case). Secrets stay in demo/out/uc01.state.json (gitignored, 0600).
const idem = require('../lib/idempotent');
const c = require('./common');

async function main() {
  const prev = c.state.read() || {};
  const out = {};
  console.log('UC-01 Setup (self-service registration, progressive profiling)\n');

  out.attributes = {};
  for (const a of c.ATTRIBUTES) {
    const r = await idem.ensureCustomAttribute(a);
    out.attributes[a.scim] = { id: r.id, slot: r.slot };
    console.log(`Attribute    ${a.name.padEnd(34)} ${r.created ? 'created' : 'exists '}  scim=${a.scim} slot=${r.slot}${a.unique ? '  unique' : ''}`);
  }

  const g = await idem.ensureGroup(c.GROUP);
  out.group = { id: g.group.id, displayName: c.GROUP };
  console.log(`Group        ${c.GROUP.padEnd(34)} ${g.created ? 'created' : 'exists '}  id=${g.group.id}`);

  const reg = await idem.ensureApiClient(c.REG_CLIENT, c.REG_ENTITLEMENTS);
  out.registration = { id: reg.id, clientId: reg.clientId, clientSecret: reg.clientSecret };
  console.log(`API client   ${c.REG_CLIENT.padEnd(34)} ${reg.created ? 'created' : 'exists '}  entitlements=${reg.entitlements.join(',')}`);

  const portal = await idem.ensureDcrClient(c.PORTAL_APP, {
    grant_types: ['authorization_code', 'password'], response_types: ['code'], all_users_entitled: true, enforce_pkce: true,
    scope: 'openid profile email', redirect_uris: [`http://localhost:${c.PORTS.portal}/callback`], consent_action: 'never_prompt',
  }, prev.portal || null);
  out.portal = { clientId: portal.clientId, clientSecret: portal.clientSecret, registrationUri: portal.registrationUri, registrationToken: portal.registrationToken };
  // Without this the ID token carries no enterprise attribute: employeeNumber (the Client 360 id) reaches the token as employee_id only with it [LIVE]
  await idem.updateApplication(c.PORTAL_APP, (a) => { a.providers.oidc.properties.sendAllKnownUserAttributes = 'true'; });
  console.log(`Application  ${c.PORTAL_APP.padEnd(34)} ${portal.created ? 'created' : 'exists '}  clientId=${portal.clientId}`);

  c.state.write(out);
  console.log(`\nState saved (secrets kept local, mode 0600): ${c.state.file}`);
  console.log('Next: node demo/uc01-registration/run.js     (automated checks, reads real Verify e-mails from a disposable inbox)');
  console.log('      node demo/uc01-registration/serve.js   (portal on http://localhost:' + c.PORTS.portal + ' for the live demo)');
}

if (require.main === module) {
  main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });
}

module.exports = { main };

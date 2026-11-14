'use strict';
// UC-04 setup (trusted devices, push, self-service revoke). Idempotent.
//   node demo/uc04-devices/setup.js
// Creates on the tenant (everything named ifc-demo-uc04-*):
//   - users         marie (the customer who registers two trusted devices) and olivier (another customer, for the isolation check)
//   - api client    -device-service   readAuthenticatorsAnyUser, manageAuthenticatorsAnyUser, readEnrollMFAMethodAnyUser, authnAnyUser, readReports
//   - authenticator client -ifc-mobile-app   the registration profile of IFC's own branded app (IBM Verify app = "Verify Profile", built in)
//   - policy        -policy-push      password + approval on a registered device (ACTION_MFA_ALWAYS, method "signatures")
//   - applications  -app-console (password grant: the script acts as the signed-in customer)  -app-login (code + PKCE, bound to the push policy)
// No device is registered here: that is what run.js does (simulated phone) or enroll-phone.js (real phone, [HUMAN]).
// Secrets and customer passwords stay local in demo/out/uc04.state.json (gitignored, mode 0600).
const { api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const c = require('./common');

async function ensureAuthClient(name) {
  const list = async () => ((await api('GET', '/v1.0/authenticators/clients')).data.clients || []).find((x) => x.name === name);
  let cl = await list();
  if (cl) return { id: cl.id, created: false };
  const r = await api('POST', '/v1.0/authenticators/clients', { body: { name } });
  if (r.status !== 201) throw new Error(`create authenticator client ${name}: HTTP ${r.status} cid=${r.cid}`);
  cl = await list();
  return { id: cl.id, created: true };
}

async function main() {
  const prev = c.state.read() || {};
  const out = { users: {} };
  console.log('UC-04 Setup (trusted devices, push, self-service revoke)\n');

  for (const [k, u] of Object.entries(c.USERS)) {
    const p = (prev.users || {})[k];
    let existing = await idem.findUser(u.userName);
    if (existing && !(p && p.id === existing.id && p.password)) { await idem.deleteUser(existing.id); existing = null; console.log(`User         ${u.userName}  password unknown (no state): recreating`); }
    const password = existing ? p.password : c.newPassword();
    const { user, created } = await idem.ensureUser({ userName: u.userName, email: `uc04.${k}@ifc-demo.invalid`, given: u.given, family: u.family, password });
    out.users[k] = { id: user.id, userName: u.userName, password };
    console.log(`User         ${u.userName.padEnd(30)} ${created ? 'created' : 'exists '} id=${user.id}`);
  }

  const svc = await idem.ensureApiClient(c.SERVICE_CLIENT, c.SERVICE_ENTITLEMENTS);
  out.service = { id: svc.id, clientId: svc.clientId, clientSecret: svc.clientSecret };
  console.log(`API client   ${c.SERVICE_CLIENT.padEnd(30)} ${svc.created ? 'created' : 'exists '} entitlements=${svc.entitlements.join(',')}`);

  const mob = await ensureAuthClient(c.MOBILE_CLIENT);
  out.mobileClient = { id: mob.id };
  console.log(`Auth. client ${c.MOBILE_CLIENT.padEnd(30)} ${mob.created ? 'created' : 'exists '} id=${mob.id}  (registration profile of IFC's own app)`);

  const pol = await idem.ensurePolicy(c.PUSH_POLICY, 'UC-04: password + approval on a registered device', [{ name: 'all customers', action: 'ACTION_MFA_ALWAYS', authnMethods: ['signatures'], conditions: [] }]);
  out.policy = { id: pol.id };
  console.log(`Policy       ${c.PUSH_POLICY.padEnd(30)} ${pol.created ? 'created' : pol.updated ? 'updated' : 'exists '} id=${pol.id}  (ACTION_MFA_ALWAYS, signatures)`);

  const con = await idem.ensureDcrClient(c.CONSOLE_APP, { grant_types: ['password'], response_types: ['code'], all_users_entitled: true, scope: 'openid', redirect_uris: [c.callbackUrl] }, prev.console);
  out.console = { clientId: con.clientId, clientSecret: con.clientSecret, registrationUri: con.registrationUri, registrationToken: con.registrationToken };
  console.log(`Application  ${c.CONSOLE_APP.padEnd(30)} ${con.created ? 'created' : 'exists '} clientId=${con.clientId}  (password grant: acts as the signed-in customer)`);

  const login = await idem.ensureDcrClient(c.LOGIN_APP, {
    redirect_uris: [c.callbackUrl], grant_types: ['authorization_code'], response_types: ['code'], all_users_entitled: true,
    enforce_pkce: true, consent_action: 'never_prompt', scope: 'openid', access_policy: pol.id,
  }, prev.login);
  await idem.updateApplication(c.LOGIN_APP, (a) => { a.authPolicy = { id: pol.id }; a.description = 'UC-04: sign in, then approve on a trusted device'; });
  out.login = { clientId: login.clientId, clientSecret: login.clientSecret, registrationUri: login.registrationUri, registrationToken: login.registrationToken };
  console.log(`Application  ${c.LOGIN_APP.padEnd(30)} ${login.created ? 'created' : 'exists '} clientId=${login.clientId}  policy=${c.PUSH_POLICY}`);

  c.state.write(out);
  console.log(`\nState saved (secrets kept local, mode 0600): ${c.state.file}`);
  console.log('Next: node demo/uc04-devices/run.js            (automated checks; simulated IBM Verify app)');
  console.log('      node demo/uc04-devices/serve.js          (portal "My trusted devices" on http://localhost:4041)');
  console.log('      node demo/uc04-devices/enroll-phone.js   ([HUMAN] register a REAL phone)');
}

if (require.main === module) {
  main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });
}

module.exports = { main };

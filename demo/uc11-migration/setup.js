'use strict';
// UC-11 setup. Idempotent: safe to run any number of times. It puts the tenant in the state "the day before cut-over":
//   node demo/uc11-migration/setup.js
// Creates on the tenant (everything named ifc-demo-uc11-*):
//   - API client   -migrator       least-privilege (readUsers + manageUsers): the identity of the migration tooling
//   - application  -login-gateway  password-grant client: how the JIT gateway signs a verified user in
//   - application  -portal         authorization-code client (PKCE): the standard Verify hosted login page, for migrated users
// Removes any migrated users left from an earlier run (the new platform starts EMPTY; the legacy store is in serve.js / run.js memory).
// Private state (passwords the customers "already know", client secrets) goes to demo/out/uc11.state.json, gitignored.
const idem = require('../lib/idempotent');
const c = require('./common');

async function main() {
  const prev = c.state.read() || {};
  const out = { users: {} };

  for (const s of c.SEED) {
    out.users[s.key] = { password: (prev.users && prev.users[s.key] && prev.users[s.key].password) || (s.weak ? c.WEAK_PASSWORD : c.newPassword()) };
  }

  const m = await idem.ensureApiClient(c.MIGRATOR, c.MIGRATOR_ENTITLEMENTS);
  out.migrator = { clientId: m.clientId, clientSecret: m.clientSecret, entitlements: m.entitlements };
  console.log(`API client   ${c.MIGRATOR}  ${m.created ? 'created' : 'exists'}  (${m.entitlements.length} entitlements: ${m.entitlements.join(', ')})`);

  const login = await idem.ensureDcrClient(c.LOGIN_APP, {
    grant_types: ['password'], response_types: ['code'], all_users_entitled: true, scope: 'openid profile email', redirect_uris: ['http://localhost:4199/unused'],
  }, prev.login);
  out.login = { clientId: login.clientId, clientSecret: login.clientSecret, registrationUri: login.registrationUri, registrationToken: login.registrationToken };
  console.log(`Application  ${c.LOGIN_APP}  ${login.created ? 'created' : 'exists'}  (password grant)`);

  const portal = await idem.ensureDcrClient(c.PORTAL_APP, {
    redirect_uris: [`${c.GATEWAY_ORIGIN}/callback`], grant_types: ['authorization_code'], response_types: ['code'], all_users_entitled: true,
    enforce_pkce: true, consent_action: 'never_prompt', scope: 'openid profile email',
  }, prev.portal);
  out.portal = { clientId: portal.clientId, clientSecret: portal.clientSecret, registrationUri: portal.registrationUri, registrationToken: portal.registrationToken };
  console.log(`Application  ${c.PORTAL_APP}  ${portal.created ? 'created' : 'exists'}  (authorization code + PKCE)`);

  const gone = await c.purgeUsers();
  console.log(`Users        ${gone} migrated user(s) removed: the new platform is empty (pre-cutover)`);

  c.state.write(out);
  console.log(`\nState saved (secrets stay local): ${c.state.file}`);
  console.log('Next: node demo/uc11-migration/run.js   |   live demo: node demo/uc11-migration/serve.js, then bulk.js and the gateway (see README)');
}

main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });

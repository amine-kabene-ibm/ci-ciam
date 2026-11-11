'use strict';
// UC-12 setup. Idempotent: safe to run any number of times.
//   node demo/uc12-rebac/setup.js
// Creates on the tenant (everything named ifc-demo-uc12-*):
//   - 5 users        -anna -ben -maya -noor -zoe   brokers and brokerage managers (fictional); department = brokerage, employee number = broker id
//   - application    -login     password-grant client (sendAllKnownUserAttributes) : how the demo signs a broker in
//   - sts client     -gateway   the gateway introspects tokens with this, not with the admin client
//   - API client     -sync      readUsers + manageUsers: the job that mirrors source-system changes into the Verify directory
// Downloads the OpenFGA binary into demo/out/bin if it is missing (checksum verified). The engine itself starts in serve.js / run.js.
// Private state (passwords, client secrets) goes to demo/out/uc12.state.json (gitignored, mode 0600).
const idem = require('../lib/idempotent');
const E = require('../../stubs/rules-engine/openfga');
const c = require('./common');

async function main() {
  const prev = c.state.read() || {};
  const source = c.createSource();
  const out = { users: {} };

  const bin = await E.ensureBinary();
  console.log(`Engine       OpenFGA v${bin.version}  ${bin.downloaded ? 'downloaded (sha256 verified)' : 'present'}  ${bin.path.replace(process.env.HOME, '~')}`);

  const sync = await idem.ensureApiClient(c.SYNC_CLIENT, c.SYNC_ENTITLEMENTS);
  out.sync = { clientId: sync.clientId, clientSecret: sync.clientSecret };
  console.log(`API client   ${c.SYNC_CLIENT}  ${sync.created ? 'created' : 'exists'}  (${sync.entitlements.join(', ')})`);

  const stsSecret = (prev.gateway && prev.gateway.secret) || c.randomSecret(24);
  const sts = await idem.ensureStsClient(c.GATEWAY_STS, { secret: stsSecret, accessTokenLifetime: 900 });
  out.gateway = { clientId: sts.clientId, secret: stsSecret };
  console.log(`STS client   ${c.GATEWAY_STS}  ${sts.created ? 'created' : 'exists'}  (token introspection for the gateway)`);

  const login = await idem.ensureDcrClient(c.LOGIN_APP, {
    grant_types: ['password'], response_types: ['code'], all_users_entitled: true, scope: 'openid profile email', redirect_uris: ['http://localhost:4199/unused'],
  }, prev.login);
  out.login = { clientId: login.clientId, clientSecret: login.clientSecret, registrationUri: login.registrationUri, registrationToken: login.registrationToken };
  await idem.updateApplication(c.LOGIN_APP, (a) => { a.providers.oidc.properties.sendAllKnownUserAttributes = 'true'; });
  console.log(`Application  ${c.LOGIN_APP}  ${login.created ? 'created' : 'exists'}  (password grant; ID token carries department, job_title)`);

  for (const [key, b] of Object.entries(source.brokers)) {
    const known = prev.users && prev.users[key];
    const existing = await idem.findUser(c.userNameOf(key));
    const keep = existing && known && known.id === existing.id && known.password; // an existing user is only reused when we still hold its password
    if (existing && !keep) await idem.deleteUser(existing.id);
    const password = keep ? known.password : c.newPassword();
    const u = await idem.ensureUser({ userName: c.userNameOf(key), email: c.emailOf(key), given: b.given, family: b.family, password });
    out.users[key] = { id: u.user.id, password };
    console.log(`User         ${c.userNameOf(key)}  ${u.created ? 'created' : 'exists'}  id=${u.user.id}  ${b.role} @ ${b.brokerage || '(no brokerage)'}`);
  }
  c.state.write(out);

  // Directory = the source system's view, written by the least-privilege sync client.
  for (const key of Object.keys(source.brokers)) {
    const r = await c.syncDirectory(out, source, key);
    if (r.status !== 204) throw new Error(`directory sync of ${key}: HTTP ${r.status} cid=${r.cid}`);
  }
  console.log('Directory    department / employee number / title written for all 5 users by the sync client (HTTP 204)');

  console.log(`\nState saved (secrets stay local, mode 0600): ${c.state.file}`);
  console.log('Next: node demo/uc12-rebac/run.js   |   live demo: node demo/uc12-rebac/serve.js, then open http://127.0.0.1:4170');
}

main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });

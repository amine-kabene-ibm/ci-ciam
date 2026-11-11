'use strict';
// Runs the UC-11 stubs for the live demo (terminal + browser):
//   node demo/uc11-migration/serve.js
//   legacy credential store   http://127.0.0.1:4050   (/export, /password-verify, /migrated, /_stats, /_admin/offline)
//   JIT migration gateway     http://localhost:4051   (sign-in page with the legacy password; /portal-login = Verify hosted page)
// Then, in other shells:  node demo/uc11-migration/bulk.js   |   node demo/uc11-migration/rollback.js   |   node demo/uc11-migration/show.js
const { createLegacyStore, listen: listenLegacy } = require('../../stubs/legacy-auth-store/server');
const { createGateway, listen: listenGateway } = require('../../stubs/migration-gateway/server');
const c = require('./common');

const st = c.state.read();
if (!st || !st.migrator) { console.error('Run setup first: node demo/uc11-migration/setup.js'); process.exit(1); }

(async () => {
  const store = createLegacyStore(c.legacyRecords(st));
  await listenLegacy(store, c.LEGACY_PORT);
  const gw = createGateway({ legacyUrl: c.LEGACY_URL, migrator: c.migratorClient(st), login: st.login, portal: st.portal, origin: c.GATEWAY_ORIGIN });
  await listenGateway(gw, c.GATEWAY_PORT);
  console.log('UC-11 stubs up:');
  console.log(`  legacy credential store   ${c.LEGACY_URL}`);
  console.log(`  JIT migration gateway     ${c.GATEWAY_ORIGIN}`);
  console.log('\nPeople in the legacy store (user name, hash format, how they migrate). Passwords: demo/out/uc11.state.json, key users.<name>.password');
  const how = { jit: 'just in time (first login at the gateway)', reset: 'bulk, forced password change', bad: 'bulk: bad data, reported', bulk: 'bulk, same password keeps working' };
  for (const s of c.SEED) console.log(`  ${c.userNameOf(s).padEnd(26)} ${('{' + s.scheme + '}').padEnd(10)} ${how[s.cohort]}`);
  console.log('\nThe new platform (Verify) is EMPTY until you run bulk.js or sign in through the gateway.');
})().catch((e) => { console.error(e.message); process.exit(1); });

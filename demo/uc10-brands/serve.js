'use strict';
// Runs the two UC-10 brand portals for the browser demo:
//   node demo/uc10-brands/serve.js
//   Aurora Insurance  http://aurora.localhost:4101   (English first, password only)
//   Boréal Assurance  http://boreal.localhost:4102   (French first, passkey / authenticator-app second factor)
// *.localhost resolves to the loopback address on this laptop and Chrome/Safari/Firefox accept it as a secure context [LIVE: DCR accepts these redirect URIs].
const { createBrandPortal, listen } = require('../../stubs/brand-portal/server');
const c = require('./common');

const st = c.state.read();
if (!st || !st.apps) { console.error('Run setup first: node demo/uc10-brands/setup.js'); process.exit(1); }

(async () => {
  for (const b of c.BRAND_LIST) {
    await listen(createBrandPortal({ brand: b, clientId: st.apps[b.key].clientId, clientSecret: st.apps[b.key].clientSecret }));
  }
  console.log('UC-10 brand portals up:');
  for (const b of c.BRAND_LIST) console.log(`  ${b.name.padEnd(20)} ${c.origin(b)}   (default language ${b.defaultLocale})`);
  console.log('Sign in as ifc-demo-uc10-customer (password in demo/out/uc10.state.json, key users.customer.password; TOTP secret in key totp.secret).');
  console.log('Aurora-only customer: ifc-demo-uc10-aurora-only (refused at Boréal).');
})().catch((e) => { console.error(e.message); process.exit(1); });

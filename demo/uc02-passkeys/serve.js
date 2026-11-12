'use strict';
// Runs the three UC-02 assurance-level portals for the browser demo:
//   node demo/uc02-passkeys/serve.js
//   AAL1 http://localhost:4021   password only
//   AAL2 http://localhost:4022   password + passkey, authenticator app or e-mail code
//   AAL3 http://localhost:4023   password + passkey only
// Each portal also has /settings (passkey list + nudge), /api/nudge, /api/methods?username=.
const { createPortal, listen } = require('../../stubs/passkey-portal/server');
const c = require('./common');

const st = c.state.read();
if (!st || !st.apps) { console.error('Run setup first: node demo/uc02-passkeys/setup.js'); process.exit(1); }

(async () => {
  for (const l of c.LEVEL_LIST) {
    await listen(createPortal({ key: l.key, title: l.title, colour: l.colour, port: l.port, clientId: st.apps[l.key].clientId, clientSecret: st.apps[l.key].clientSecret, log: (x) => console.log(x) }));
  }
  console.log('UC-02 portals up:');
  for (const l of c.LEVEL_LIST) console.log(`  ${l.title.padEnd(70)} ${c.origin(l)}`);
  console.log('Customers: ifc-demo-uc02-alice (passkey customer) and ifc-demo-uc02-bob (no passkey). Passwords and TOTP secrets: demo/out/uc02.state.json');
  console.log('Add a passkey in a real browser at https://<tenant>/usc/ (IBM Verify self-care), signed in as alice.');
})().catch((e) => { console.error(e.message); process.exit(1); });

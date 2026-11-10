'use strict';
// Runs the three UC-08 relying-party stubs for the browser demo:
//   node demo/uc08-sso/serve.js
//   portal  http://localhost:4001   claims  http://localhost:4002 (brokers only)   quote  http://localhost:4003 (second factor at every sign-in)
// Back-channel logout: tunnel to :4001 (cloudflared tunnel --url http://localhost:4001), run
//   node demo/uc08-sso/setup.js --backchannel https://<public host>     (the tenant then POSTs to <public host>/bc/portal|claims|quote)
const { createRp, listen } = require('../../stubs/rp-sso/server');
const c = require('./common');

const st = c.state.read();
if (!st || !st.apps) { console.error('Run setup first: node demo/uc08-sso/setup.js'); process.exit(1); }

(async () => {
  const registry = {};
  for (const a of c.APPS) {
    registry[a.key] = createRp({
      key: a.key, title: a.title, colour: a.colour, port: a.port, clientId: st.apps[a.key].clientId, clientSecret: st.apps[a.key].clientSecret,
      requireGroup: a.requireGroup, introspectEachRequest: a.introspectEachRequest, registry, log: (l) => console.log(l),
    });
  }
  for (const rp of Object.values(registry)) await listen(rp);
  console.log(`UC-08 relying parties up (logout mode: ${st.mode === 'back' ? `back-channel via ${st.backchannelBase}` : 'front-channel'}):`);
  for (const a of c.APPS) console.log(`  ${a.title.padEnd(36)} ${c.origin(a)}`);
  console.log('Sign in as the broker (password in demo/out/uc08.state.json, key users.broker.password; TOTP secret in key totp.secret).');
})().catch((e) => { console.error(e.message); process.exit(1); });

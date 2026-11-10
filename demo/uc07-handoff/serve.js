'use strict';
// Runs the voicebot (CCaaS stub) with the app-to-voice hand-off enabled, for the browser path:
//   node demo/uc07-handoff/serve.js            listens on http://127.0.0.1:4030 (UC06_PORT overrides)
// The demo app (node ./bin/www, :3000) posts the signed-in customer's access token to it from /app/call-us.
// It trusts tokens issued to the demo app's OIDC client (OIDC_CLIENT_ID in .env) and to the scripted "mobile app" client.
const stub = require('../../stubs/voicebot-ccaas/server');
const c = require('./common');

const st = c.state.read();
if (!st) { console.error('Run setup first: node demo/uc07-handoff/setup.js'); process.exit(1); }
const port = Number(process.env.UC06_PORT || 4030);
const extra = process.env.OIDC_CLIENT_ID ? [process.env.OIDC_CLIENT_ID] : [];

stub.start(port, c.ccaasApi(st), c.handoffConfig(st, { extraClientIds: extra }))
  .then(() => console.log(`voicebot with app hand-off listening on http://127.0.0.1:${port} (trusts ${1 + extra.length} app client id(s))`))
  .catch((e) => { console.error(e.message); process.exit(1); });

'use strict';
// Starts the protected IFC policy API stub (stubs/ifc-api) on 127.0.0.1:4040, wired to this demo's tenant objects.
//   node demo/uc09-api/serve.js        (leave it running; then: node demo/uc09-api/run.js in another terminal)
// The stub introspects every token with the partner STS client (its own least-privilege credentials), never with the admin client.
const c = require('./common');
const { start } = require('../../stubs/ifc-api/server');

const st = c.state.read();
if (!st || !st.clients || !st.sts) { console.error('Run setup first: node demo/uc09-api/setup.js'); process.exit(1); }

const allowedClientIds = [st.clients.pkjwt.clientId, st.clients.dpop.clientId];
start(c.API_PORT, {
  introspectClient: { clientId: st.sts.clientId, secret: st.sts.secret },
  allowedClientIds,
  delegatedClientId: st.sts.clientId,
  policyholderSub: st.user.id,
  requiredScope: c.SCOPE_READ,
}).then(() => {
  console.log(`IFC policy API stub on ${c.API_BASE}  (scope ${c.SCOPE_READ}; partner clients: ${c.CLIENTS.pkjwt.name}, ${c.CLIENTS.dpop.name})`);
  console.log('Introspection runs with the partner STS client, not the admin client. Ctrl-C to stop.');
}).catch((e) => { console.error(e.message); process.exit(1); });

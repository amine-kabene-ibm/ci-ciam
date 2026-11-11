'use strict';
// Brings up the UC-12 runtime in this process: the relationship engine (OpenFGA, native binary), the source-system stub, and the policy
// gateway (stubs/policy-api). Used by serve.js (live demo) and run.js (scenarios).
const c = require('./common');
const gateway = require('../../stubs/policy-api/server');

const decode = (jwt) => JSON.parse(Buffer.from(String(jwt).split('.')[1], 'base64url').toString());

async function boot(st, { gatewayPort = c.GATEWAY_PORT, fgaPort = c.FGA_PORT, fgaGrpcPort = c.FGA_GRPC_PORT } = {}) {
  const source = c.createSource();
  const eng = await c.bootEngine(st, source, { port: fgaPort, grpcPort: fgaGrpcPort });
  const subs = Object.fromEntries(Object.entries(st.users).map(([k, u]) => [k, u.id]));
  const ropc = c.ropc(st);

  const signIn = async (key) => {
    const r = await ropc.passwordGrant(c.userNameOf(key), st.users[key].password);
    if (r.status !== 200) throw new Error(`sign-in of ${key} failed: HTTP ${r.status}`);
    const idClaims = decode(r.data.id_token); // the access token is opaque [LIVE]: only the ID token is a JWT
    return { token: r.data.access_token, sub: idClaims.sub, iat: idClaims.iat, exp: idClaims.iat + (r.data.expires_in || 0), idClaims, ms: r.ms };
  };

  const server = await gateway.start(gatewayPort, {
    introspectClient: { clientId: st.gateway.clientId, secret: st.gateway.secret },
    getFga: () => eng.fga, source, subs, signIn,
    applyChange: (mutate) => c.applyChange(st, source, eng.fga, mutate),
  });
  return {
    source, subs, signIn, fga: eng.fga, engine: eng.engine, boot: eng, server, url: `http://127.0.0.1:${gatewayPort}`,
    stop: async () => { await new Promise((r) => server.close(r)); eng.engine.stop(); },
  };
}

module.exports = { boot, decode };

'use strict';
// UC-09 setup (API security). Idempotent: safe to run any number of times.
//   node demo/uc09-api/setup.js
// Creates on the tenant:
//   - applications ifc-demo-uc09-m2m-pkjwt / -m2m-dpop   partner machine clients (dynamic registration), private_key_jwt,
//                                                       JWKS with the public key. -dpop also sender-constrains its tokens (DPoP).
//                                                       Private keys stay in demo/out/uc09.state.json (gitignored, mode 0600).
//   - sts client   ifc-demo-uc09-partner                 token exchange for "partner acts for a policyholder" (client_secret_basic:
//                                                       the tenant refuses private_key_jwt on STS clients [LIVE])
//   - application  ifc-demo-uc09-policyholder-app        password-grant client used only to obtain the policyholder's subject token
//   - user         ifc-demo-uc09-policyholder            the subject of the exchange
const crypto = require('crypto');
const idem = require('../lib/idempotent');
const c = require('./common');

async function main() {
  const prev = c.state.read() || {};
  const out = { keys: {}, clients: {}, sts: null, user: null, policyholderApp: null };

  // 1. Keys. Re-use the stored key pair if it exists, so a re-run does not rotate keys silently.
  for (const k of Object.keys(c.CLIENTS)) {
    const old = (prev.keys || {})[k];
    let pair;
    if (old && old.privatePem && old.publicPem) {
      pair = { privateKey: crypto.createPrivateKey(old.privatePem), publicKey: crypto.createPublicKey(old.publicPem), privatePem: old.privatePem, publicPem: old.publicPem };
    } else {
      const g = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      pair = {
        privateKey: g.privateKey, publicKey: g.publicKey,
        privatePem: g.privateKey.export({ type: 'pkcs8', format: 'pem' }), publicPem: g.publicKey.export({ type: 'spki', format: 'pem' }),
      };
    }
    out.keys[k] = { kid: c.kidOf(pair.publicKey), privatePem: pair.privatePem, publicPem: pair.publicPem };
    console.log(`Key          ${k.padEnd(6)} kid=${out.keys[k].kid}  (local, ${old ? 'kept' : 'generated'})`);
  }

  // 2. Machine clients (DCR). The JWKS holds only the public key. Scope is the one the API enforces.
  for (const [k, def] of Object.entries(c.CLIENTS)) {
    const pub = crypto.createPublicKey(out.keys[k].publicPem);
    const jwks = { keys: [c.publicJwk(pub, out.keys[k].kid)] };
    const reg = await idem.ensureDcrClient(def.name, {
      grant_types: ['client_credentials'], token_endpoint_auth_method: 'private_key_jwt', jwks,
      scope: `openid ${c.SCOPE_READ}`, ...(def.dpop ? { dpop_bound_access_tokens: true } : {}),
    }, (prev.clients || {})[k]);
    out.clients[k] = { clientId: reg.clientId, clientSecret: reg.clientSecret, registrationUri: reg.registrationUri, registrationToken: reg.registrationToken };
    console.log(`Application  ${def.name}  ${reg.created ? 'created' : 'exists'}  clientId=${reg.clientId}  ${def.label}`);
  }

  // 3. Partner STS client for the exchange. Secret is kept in state; ensureStsClient recreates it when the secret drifts.
  const stsSecret = (prev.sts && prev.sts.secret) || c.randomSecret(24);
  const sts = await idem.ensureStsClient(c.PARTNER_STS, { secret: stsSecret, accessTokenLifetime: 900, actorRequired: true });
  out.sts = { clientId: sts.clientId, secret: stsSecret };
  console.log(`STS client   ${c.PARTNER_STS}  ${sts.created ? 'created' : 'exists'}  clientId=${sts.clientId}  actorTokenRequired=true`);

  // 4. Policyholder user (subject of the exchange) and the password-grant client that logs them in for the demo.
  // A user is only reused when we still hold its password (needed for the password grant); otherwise it is recreated.
  const existing = await idem.findUser(c.POLICYHOLDER.userName);
  const kept = existing && prev.user && prev.user.id === existing.id && prev.user.password ? prev.user.password : null;
  if (existing && !kept) { await idem.deleteUser(existing.id); console.log('User         password unknown (no state): recreating'); }
  const password = kept || c.newUserCredential();
  const ensured = await idem.ensureUser({ userName: c.POLICYHOLDER.userName, email: c.POLICYHOLDER.email, given: c.POLICYHOLDER.given, family: c.POLICYHOLDER.family, password });
  out.user = { id: ensured.user.id, userName: c.POLICYHOLDER.userName, password };
  console.log(`User         ${c.POLICYHOLDER.userName}  ${ensured.created ? 'created' : 'exists'}  id=${ensured.user.id}`);

  const pwApp = await idem.ensureDcrClient(c.POLICYHOLDER_APP, {
    grant_types: ['password'], all_users_entitled: true, scope: 'openid', redirect_uris: ['http://localhost:9/cb'],
    response_types: ['code'], consent_action: 'never_prompt',
  }, (prev.policyholderApp) || null);
  out.policyholderApp = { clientId: pwApp.clientId, clientSecret: pwApp.clientSecret, registrationUri: pwApp.registrationUri, registrationToken: pwApp.registrationToken };
  console.log(`Application  ${c.POLICYHOLDER_APP}  ${pwApp.created ? 'created' : 'exists'}  clientId=${pwApp.clientId}  (password grant, subject-token source)`);

  c.state.write(out);
  console.log(`\nState saved (keys and secrets stay local, mode 0600): ${c.state.file}`);
  console.log('Next: start the protected API   node demo/uc09-api/serve.js   then   node demo/uc09-api/run.js');
}

main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });

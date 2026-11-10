'use strict';
// UC-09 scenario runner: API security against the REAL Verify tenant.
//   node demo/uc09-api/run.js          (needs setup.js, and the protected API: node demo/uc09-api/serve.js)
// Each scenario prints PASS/FAIL. Evidence (status codes, ids, timings; never keys, secrets or tokens): demo/out/uc09.json
const crypto = require('crypto');
const { evidence, api, send, BASE, oauthClient, getToken } = require('../lib/verify');
const idem = require('../lib/idempotent');
const J = require('./jwt');
const c = require('./common');

const ev = evidence('uc09');
const results = [];
const TOK = 'urn:ietf:params:oauth:token-type:access_token';
const ASSERT_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const check = (scenario, title, pass, extra = {}) => {
  results.push({ scenario, title, pass });
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${title}`);
  ev.step(`${scenario}: ${title}`, { pass, ...extra });
};
const info = (scenario, title, extra = {}) => {
  console.log(`  INFO  ${title}`);
  ev.step(`${scenario}: ${title}`, { info: true, ...extra });
};

// Token request for private_key_jwt. `assertionKey` may differ from the registered key (wrong-key test).
async function tokenWithAssertion({ clientId, privateKey, kid, scope, dpopKey }) {
  const form = {
    grant_type: 'client_credentials', client_assertion_type: ASSERT_TYPE, client_id: clientId,
    client_assertion: J.clientAssertion({ privateKey, kid, clientId }), ...(scope ? { scope } : {}),
  };
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' };
  if (dpopKey) headers.DPoP = J.dpopProof({ privateKey: dpopKey.privateKey, publicKey: dpopKey.publicKey, htm: 'POST', htu: J.TOKEN_AUD });
  const r = await send({
    method: 'post', url: `${BASE}/v1.0/endpoint/default/token`, validateStatus: () => true, transformResponse: (x) => x,
    headers, data: new URLSearchParams(form).toString(),
  });
  let data = r.data; try { data = JSON.parse(r.data); } catch (e) { /* keep raw */ }
  return { status: r.status, data, cid: r.headers['x-correlation-id'] || null };
}

// Call the protected API. `proof` (optional) is a DPoP proof object {privateKey, publicKey}.
async function callApi(policy, token, { scheme = 'Bearer', proof, path } = {}) {
  const url = `${c.API_BASE}/policies/${policy}`;
  const headers = { Accept: 'application/json' };
  if (token) headers.Authorization = `${scheme} ${token}`;
  if (proof) headers.DPoP = J.dpopProof({ privateKey: proof.privateKey, publicKey: proof.publicKey, htm: 'GET', htu: url, ...(token ? { ath: J.athOf(token) } : {}) });
  const r = await send({ method: 'get', url: path || url, validateStatus: () => true, transformResponse: (x) => x, headers });
  let data = r.data; try { data = JSON.parse(r.data); } catch (e) { /* keep raw */ }
  return { status: r.status, data };
}

(async () => {
  const st = c.state.read();
  if (!st || !st.clients || !st.keys) { console.error('Run setup first: node demo/uc09-api/setup.js'); process.exit(1); }
  const health = await send({ method: 'get', url: `${c.API_BASE}/health`, validateStatus: () => true, transformResponse: (x) => x }).catch(() => ({ status: 0 }));
  if (health.status !== 200) { console.error(`The protected API is not running on ${c.API_BASE}. Start it: node demo/uc09-api/serve.js`); process.exit(1); }
  await send({ method: 'post', url: `${c.API_BASE}/reset`, validateStatus: () => true });
  const pk = st.clients.pkjwt; const dp = st.clients.dpop;
  const kp = st.keys.pkjwt; const kd = st.keys.dpop;
  const privKey = (k) => crypto.createPrivateKey(k.privatePem);
  const pubKey = (k) => crypto.createPublicKey(k.publicPem);
  const keyPair = (k) => ({ privateKey: privKey(k), publicKey: pubKey(k) });
  ev.doc.apiBase = c.API_BASE;

  console.log('\nA. Machine client with private_key_jwt gets a scoped token and calls the API');
  const a = await tokenWithAssertion({ clientId: pk.clientId, privateKey: privKey(kp), kid: kp.kid, scope: c.SCOPE_READ });
  check('A', 'client assertion signed with the registered key -> token issued (HTTP 200, bearer)', a.status === 200 && a.data.token_type === 'bearer', { httpStatus: a.status, cid: a.cid, tokenType: a.data.token_type, expiresIn: a.data.expires_in });
  const aCall = await callApi('IFC-100001', a.data.access_token);
  check('A', 'the API accepts the token: 200, policy returned, scope ifc.policy.read seen by the API', aCall.status === 200 && aCall.data.servedTo && aCall.data.servedTo.scopes.includes(c.SCOPE_READ), { httpStatus: aCall.status, servedTo: aCall.data && aCall.data.servedTo });

  console.log('\nB. Wrong key is refused at the token endpoint and never reaches the API');
  const wrong = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const b = await tokenWithAssertion({ clientId: pk.clientId, privateKey: wrong.privateKey, kid: kp.kid, scope: c.SCOPE_READ });
  check('B', 'assertion signed with another key (same kid) -> 401 invalid_client (CSIAQ5064E)', b.status === 401 && b.data.error === 'invalid_client', { httpStatus: b.status, error: b.data.error, cid: b.cid });

  console.log('\nC. Scope is granted by registration, not by the request');
  const cs = await tokenWithAssertion({ clientId: pk.clientId, privateKey: privKey(kp), kid: kp.kid, scope: c.SCOPE_WRITE });
  const cTok = cs.data.access_token;
  check('C', `the client asks for ${c.SCOPE_WRITE}, which it was never registered for: the token carries no scope`, cs.status === 200 && !cs.data.scope, { httpStatus: cs.status, scopeInResponse: cs.data.scope || null });
  const cCall = await callApi('IFC-100001', cTok);
  check('C', 'the API refuses a token without ifc.policy.read: 403 insufficient_scope', cCall.status === 403, { httpStatus: cCall.status, error: cCall.data && cCall.data.error });

  console.log('\nD. The API refuses calls without a valid token');
  const d1 = await callApi('IFC-100001', null);
  check('D', 'no Authorization header -> 401', d1.status === 401, { httpStatus: d1.status });
  const d2 = await callApi('IFC-100001', 'not-a-real-token');
  check('D', 'a garbage token -> 401 (Verify introspection: active:false)', d2.status === 401, { httpStatus: d2.status });
  const d3 = await callApi('IFC-100001', a.data.access_token, { scheme: 'Basic' });
  check('D', 'wrong authorization scheme -> 401', d3.status === 401, { httpStatus: d3.status });
  // An unlisted client can still obtain a token from Verify (it is registered); the API allow-list is what refuses it.
  const rg = await tokenWithAssertion({ clientId: st.clients.rogue.clientId, privateKey: privKey(st.keys.rogue), kid: st.keys.rogue.kid, scope: c.SCOPE_READ });
  check('D', 'a registered machine client that is NOT an IFC partner gets a token from Verify (HTTP 200): the API must still refuse it', rg.status === 200 && !!rg.data.access_token, { httpStatus: rg.status });
  const rgCall = await callApi('IFC-100001', rg.data.access_token);
  check('D', 'the API refuses the unlisted client: 403 (token not issued to an allowed partner client)', rgCall.status === 403, { httpStatus: rgCall.status, error: rgCall.data && rgCall.data.error });

  console.log('\nE. Sender-constrained token (DPoP): a stolen bearer is useless without the key');
  const dpopKey = keyPair(kd);
  const e = await tokenWithAssertion({ clientId: dp.clientId, privateKey: privKey(kd), kid: kd.kid, scope: c.SCOPE_READ, dpopKey });
  const eTok = e.data.access_token;
  check('E', 'token issued with DPoP proof: token_type DPoP (HTTP 200)', e.status === 200 && e.data.token_type === 'DPoP', { httpStatus: e.status, tokenType: e.data.token_type });
  const e1 = await callApi('IFC-100001', eTok, { scheme: 'DPoP', proof: dpopKey });
  check('E', 'API call with the token AND a proof from the bound key: 200 (sender-constrained)', e1.status === 200 && e1.data.servedTo && e1.data.servedTo.senderConstrained === true, { httpStatus: e1.status });
  const e2 = await callApi('IFC-100001', eTok, { scheme: 'DPoP' });
  check('E', 'same token with NO proof (a stolen token replayed as plain bearer): 401', e2.status === 401, { httpStatus: e2.status, reason: e2.data && e2.data.reason });
  const e3 = await callApi('IFC-100001', eTok, { scheme: 'DPoP', proof: keyPair(kp) });
  check('E', 'same token with a proof signed by a DIFFERENT key (the partner key): 401', e3.status === 401, { httpStatus: e3.status, reason: e3.data && e3.data.reason });

  console.log('\nF. Key rotation: zero-downtime overlap, then the old key is retired (admin client updates the JWKS)');
  const newPair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const newKid = c.kidOf(newPair.publicKey);
  const putJwks = async (keys) => send({
    method: 'put', url: `${BASE}/oauth2/register/${pk.clientId}`, validateStatus: () => true, transformResponse: (x) => x,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${await getToken()}` },
    data: JSON.stringify({ client_id: pk.clientId, client_name: c.CLIENTS.pkjwt.name, grant_types: ['client_credentials'], token_endpoint_auth_method: 'private_key_jwt', jwks: { keys }, scope: `openid ${c.SCOPE_READ}` }),
  });
  const oldJwk = c.publicJwk(pubKey(kp), kp.kid);
  const newJwk = c.publicJwk(newPair.publicKey, newKid);
  const f1 = await putJwks([oldJwk, newJwk]);
  check('F', 'step 1: JWKS updated to hold the old and the new key (admin PUT, HTTP 200)', f1.status === 200, { httpStatus: f1.status });
  const fOld = await tokenWithAssertion({ clientId: pk.clientId, privateKey: privKey(kp), kid: kp.kid, scope: c.SCOPE_READ });
  const fNew = await tokenWithAssertion({ clientId: pk.clientId, privateKey: newPair.privateKey, kid: newKid, scope: c.SCOPE_READ });
  check('F', 'overlap: the OLD key still gets a token (200) and the NEW key gets one too (200)', fOld.status === 200 && fNew.status === 200, { oldKey: fOld.status, newKey: fNew.status });
  const f2 = await putJwks([newJwk]);
  check('F', 'step 2: old key removed from the JWKS (admin PUT, HTTP 200)', f2.status === 200, { httpStatus: f2.status });
  const gOld = await tokenWithAssertion({ clientId: pk.clientId, privateKey: privKey(kp), kid: kp.kid, scope: c.SCOPE_READ });
  const gNew = await tokenWithAssertion({ clientId: pk.clientId, privateKey: newPair.privateKey, kid: newKid, scope: c.SCOPE_READ });
  check('F', 'after retirement: the OLD key is refused (401) and the NEW key still works (200)', gOld.status === 401 && gNew.status === 200, { oldKey: gOld.status, newKey: gNew.status });
  // Put the registration back to the stored key, so the other scenarios and the next setup.js run use the same key.
  await putJwks([oldJwk]);
  console.log('      (the JWKS is reset to the stored key, so the other scenarios and re-runs are unaffected)');

  console.log('\nG. On-behalf-of: a partner acts for a policyholder (RFC 8693 token exchange)');
  // Subject token: the policyholder logs in (password grant on the demo app). Actor token: the partner's own machine token.
  const pwApp = st.policyholderApp;
  const pwLogin = await send({ method: 'post', url: `${BASE}/oidc/endpoint/default/token`, validateStatus: () => true, transformResponse: (x) => x, headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', Authorization: `Basic ${Buffer.from(`${pwApp.clientId}:${pwApp.clientSecret}`).toString('base64')}` }, data: new URLSearchParams({ grant_type: 'password', username: c.POLICYHOLDER.userName, password: st.user.password, scope: 'openid' }).toString() });
  const subject = JSON.parse(pwLogin.data).access_token;
  check('G', 'policyholder signs in (password grant): subject token issued (HTTP 200)', pwLogin.status === 200 && !!subject, { httpStatus: pwLogin.status });
  const partnerActor = (await tokenWithAssertion({ clientId: pk.clientId, privateKey: privKey(kp), kid: kp.kid, scope: c.SCOPE_READ })).data.access_token;
  const sts = oauthClient(st.sts.clientId, st.sts.secret);
  const exchangeWithActor = await send({
    method: 'post', url: `${BASE}/oauth2/token`, validateStatus: () => true, transformResponse: (x) => x,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', Authorization: `Basic ${Buffer.from(`${st.sts.clientId}:${st.sts.secret}`).toString('base64')}` },
    data: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: subject, subject_token_type: TOK, actor_token: partnerActor, actor_token_type: TOK, requested_token_type: TOK, scope: c.SCOPE_READ }).toString(),
  });
  const exchanged = JSON.parse(exchangeWithActor.data);
  check('G', 'partner exchanges the policyholder token with its actor token, scope ifc.policy.read requested -> token issued (HTTP 200)', exchangeWithActor.status === 200 && !!exchanged.access_token, { httpStatus: exchangeWithActor.status, tokenType: exchanged.token_type, expiresIn: exchanged.expires_in });
  const intro = await sts.introspect(exchanged.access_token);
  const sameSubject = intro.data && intro.data.sub;
  const policyholderId = st.user.id;
  check('G', 'the exchanged token is FOR the policyholder (sub = policyholder user id) and carries ifc.policy.read', intro.status === 200 && intro.data.active === true && sameSubject === policyholderId && String(intro.data.scope || '').includes(c.SCOPE_READ), { httpStatus: intro.status, sameSubject: sameSubject === policyholderId, scope: intro.data.scope || null, clientIdIsSts: intro.data.client_id === st.sts.clientId });
  info('G', 'the exchanged token carries NO `act` claim (opaque token; introspection does not return the actor) [LIVE]: the demo does not claim it', { actClaimInIntrospection: !!(intro.data && intro.data.act) });
  const gOwn = await callApi('IFC-100001', exchanged.access_token, { scheme: 'Bearer' });
  check('G', "the API accepts the delegated token for the policyholder's OWN policy: 200", gOwn.status === 200 && !!(gOwn.data && gOwn.data.servedTo && gOwn.data.servedTo.delegated), { httpStatus: gOwn.status, delegated: gOwn.data && gOwn.data.servedTo && gOwn.data.servedTo.delegated });
  const gOther = await callApi('IFC-100002', exchanged.access_token, { scheme: 'Bearer' });
  check('G', "the same delegated token is refused for ANOTHER policyholder's policy: 403 not_the_policyholder", gOther.status === 403, { httpStatus: gOther.status, error: gOther.data && gOther.data.error });

  console.log('\nH. The exchange cannot run without an actor (actorTokenRequired)');
  const noActor = await send({
    method: 'post', url: `${BASE}/oauth2/token`, validateStatus: () => true, transformResponse: (x) => x,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', Authorization: `Basic ${Buffer.from(`${st.sts.clientId}:${st.sts.secret}`).toString('base64')}` },
    data: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: subject, subject_token_type: TOK, requested_token_type: TOK }).toString(),
  });
  check('H', 'exchange without an actor_token -> 400 CSIAQ5242E (the actor is mandatory)', noActor.status === 400 && String(noActor.data).includes('CSIAQ5242E'), { httpStatus: noActor.status, cid: noActor.headers['x-correlation-id'] || null });

  console.log('\nI. Known limit, stated (not a pass or a fail)');
  info('I', 'actorCriteria (CEL) on the STS client is stored as {} and NOT enforced: a disallowed actor still gets a token [LIVE, 2026-11-10]. The demo does not claim a partner allow-list on the exchange; the API scope is the control.');

  console.log('\nJ. mTLS (client certificate) on the SaaS edge: a handshake check, not a claim');
  const { spawnSync } = require('child_process');
  const host = new URL(BASE).host;
  const hs = spawnSync('openssl', ['s_client', '-connect', `${host}:443`, '-servername', host, '-msg', '-brief'], { input: '', timeout: 20000, encoding: 'utf8' });
  const hsText = `${hs.stdout || ''}${hs.stderr || ''}`;
  const handshakeSeen = /Handshake/.test(hsText);
  const certRequested = /\bCertificateRequest\b/.test(hsText);
  check('J', 'TLS handshake observed, and the edge sends NO CertificateRequest (so a client certificate cannot be presented on this host)', handshakeSeen && !certRequested, { handshakeSeen, certificateRequestSeen: certRequested, host });
  info('J', 'mTLS client authentication is NOT demonstrated: the handshake never asks for a client certificate on this host [LIVE]. The demo uses private_key_jwt and DPoP.');

  // ---- evidence ----
  const f = results.filter((r) => !r.pass).length;
  const p = results.filter((r) => r.pass).length;
  console.log(`\n${p} checks passed, ${f} failed`);
  ev.save({ total: results.length, passed: p, failed: f, results: results.map((r) => ({ scenario: r.scenario, title: r.title, pass: r.pass })) });
  console.log(`Evidence written: ${ev.file}`);
  process.exit(f ? 1 : 0);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

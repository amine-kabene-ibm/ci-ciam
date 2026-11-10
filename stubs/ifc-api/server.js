'use strict';
// STUB of IFC's protected policy API (UC-09). It is the resource server behind IFC's API gateway.
//   GET /policies/:policyNumber   needs a bearer token with scope ifc.policy.read
// Each request:
//   1. takes the bearer token (or DPoP token) from the Authorization header
//   2. introspects it with Verify (POST /oauth2/introspect, HTTP Basic with the resource's own STS client, NOT the admin client)
//   3. 401 if not active; 403 if the token's client is not an allowed partner client or the scope is missing
//   4. for a DPoP-bound token (introspection cnf.jkt): requires a DPoP proof whose key thumbprint equals cnf.jkt (RFC 9449 check
//      done HERE by the stub; the tenant's userinfo endpoint did not enforce it in our test, so we do not claim Verify does)
// The resource does not trust the request's own claims: scope and client come from introspection only.
const express = require('express');
const crypto = require('crypto');
const { oauthClient } = require('../../demo/lib/verify');
const J = require('../../demo/uc09-api/jwt');

// Each policy belongs to one policyholder (the Verify user id, `sub`). A delegated token (on-behalf-of, issued to the partner's
// STS client) may read only the policy of its own `sub`. The owner is passed in by the caller (setup state), not hard-coded.
const POLICIES = {
  'IFC-100001': { policyNumber: 'IFC-100001', product: 'Auto', premiumMonthly: 142.5, status: 'active', owner: 'policyholder' },
  'IFC-100002': { policyNumber: 'IFC-100002', product: 'Home', premiumMonthly: 88.0, status: 'active', owner: 'other' },
};

// opts: { introspectClient: {clientId, secret}, allowedClientIds: [partner machine client ids], delegatedClientId: partner STS client id,
//         policyholderSub: the policyholder's Verify user id, requiredScope }
function buildApp({ introspectClient, allowedClientIds, delegatedClientId, policyholderSub, requiredScope }) {
  const app = express();
  const introspect = oauthClient(introspectClient.clientId, introspectClient.secret);
  const log = [];
  const record = (entry) => { log.push({ at: new Date().toISOString(), ...entry }); };

  app.get('/health', (req, res) => res.json({ ok: true, service: 'ifc-api-stub' }));
  app.get('/log', (req, res) => res.json(log));
  app.post('/reset', (req, res) => { log.length = 0; res.json({ ok: true }); });

  app.get('/policies/:policyNumber', async (req, res) => {
    const auth = req.headers.authorization || '';
    const m = /^(Bearer|DPoP)\s+(.+)$/i.exec(auth);
    if (!m) { record({ path: req.path, decision: 'deny', reason: 'no_token', status: 401 }); return res.status(401).json({ error: 'invalid_token', reason: 'no bearer token' }); }
    const scheme = m[1].toLowerCase(); const token = m[2].trim();

    const i = await introspect.introspect(token);
    if (i.status !== 200 || !i.data || i.data.active !== true) {
      record({ path: req.path, decision: 'deny', reason: 'inactive_or_unknown_token', status: 401, introspectHttp: i.status });
      return res.status(401).json({ error: 'invalid_token', reason: 'token is not active' });
    }
    // Two kinds of token reach this API: a partner's own machine token, or a delegated token from the STS (on behalf of a policyholder).
    const delegated = i.data.client_id === delegatedClientId;
    if (!delegated && !allowedClientIds.includes(i.data.client_id)) {
      record({ path: req.path, decision: 'deny', reason: 'client_not_allowed', status: 403 });
      return res.status(403).json({ error: 'insufficient_scope', reason: 'token was not issued to an allowed partner client' });
    }
    const scopes = String(i.data.scope || '').split(' ').filter(Boolean);
    if (!scopes.includes(requiredScope)) {
      record({ path: req.path, decision: 'deny', reason: 'scope_missing', status: 403, scopes });
      return res.status(403).json({ error: 'insufficient_scope', reason: `scope ${requiredScope} is required`, scopes });
    }

    // Sender-constrained (DPoP) tokens: the proof must be signed by the key the token is bound to.
    const jkt = i.data.cnf && i.data.cnf.jkt;
    if (jkt) {
      if (scheme !== 'dpop' || !req.headers.dpop) {
        record({ path: req.path, decision: 'deny', reason: 'dpop_proof_missing', status: 401 });
        return res.status(401).json({ error: 'invalid_token', reason: 'this token is DPoP-bound: send a DPoP proof' });
      }
      const ok = verifyDpop(req.headers.dpop, { htm: req.method, htu: `${req.protocol}://${req.get('host')}${req.originalUrl.split('?')[0]}`, token, jkt });
      if (!ok.valid) {
        record({ path: req.path, decision: 'deny', reason: `dpop_${ok.reason}`, status: 401 });
        return res.status(401).json({ error: 'invalid_dpop_proof', reason: ok.reason });
      }
    }

    const p = POLICIES[req.params.policyNumber];
    if (!p) { record({ path: req.path, decision: 'allow', reason: 'not_found', status: 404, clientId: i.data.client_id, scopes }); return res.status(404).json({ error: 'not_found' }); }
    // A delegated token acts for ONE policyholder: it may read only that policyholder's policies.
    if (delegated && (!policyholderSub || i.data.sub !== policyholderSub || p.owner !== 'policyholder')) {
      record({ path: req.path, decision: 'deny', reason: 'not_the_policyholder', status: 403, clientId: i.data.client_id, scopes });
      return res.status(403).json({ error: 'insufficient_scope', reason: 'delegated token may read only its policyholder\'s policies' });
    }
    const { owner, ...publicPolicy } = p;
    record({ path: req.path, decision: 'allow', reason: 'ok', status: 200, clientId: i.data.client_id, scopes, sender: jkt ? 'dpop-bound' : 'bearer', delegated });
    res.json({ ...publicPolicy, servedTo: { clientId: i.data.client_id, scopes, senderConstrained: !!jkt, delegated, sub: delegated ? i.data.sub : undefined } });
  });

  return app;
}

// Checks a DPoP proof for this request. Only the checks the demo relies on: signature with the key in the proof header,
// htm/htu match, fresh iat, ath = hash of the access token, and the proof key's thumbprint equals the token's cnf.jkt.
function verifyDpop(proof, { htm, htu, token, jkt }) {
  const parts = String(proof).split('.');
  if (parts.length !== 3) return { valid: false, reason: 'malformed' };
  let header; let payload;
  try { header = JSON.parse(Buffer.from(parts[0], 'base64url').toString()); payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString()); } catch (e) { return { valid: false, reason: 'malformed' }; }
  if (header.typ !== 'dpop+jwt' || header.alg !== 'RS256' || !header.jwk) return { valid: false, reason: 'bad_header' };
  const pub = crypto.createPublicKey({ key: header.jwk, format: 'jwk' });
  const sigOk = crypto.verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), pub, Buffer.from(parts[2], 'base64url'));
  if (!sigOk) return { valid: false, reason: 'bad_signature' };
  if (payload.htm !== htm) return { valid: false, reason: 'htm_mismatch' };
  if (payload.htu !== htu) return { valid: false, reason: 'htu_mismatch' };
  if (Math.abs(Date.now() / 1000 - payload.iat) > 120) return { valid: false, reason: 'stale' };
  if (payload.ath !== J.athOf(token)) return { valid: false, reason: 'ath_mismatch' };
  if (J.jwkThumbprint(pub) !== jkt) return { valid: false, reason: 'key_not_bound_to_token' };
  return { valid: true };
}

function start(port, opts) {
  const app = buildApp(opts);
  return new Promise((resolve, reject) => {
    const server = app.listen(port, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

module.exports = { buildApp, start, verifyDpop, POLICIES };

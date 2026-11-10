'use strict';
// RS256 signing with Node's crypto (no extra dependency) for the two JWTs this demo makes:
//   client assertion (private_key_jwt, RFC 7523)  and  DPoP proof (RFC 9449).
// Live rules [LIVE 2026-11-10]:
//   - the assertion `aud` must be <tenant>/oauth2/token (the token endpoint also accepts its own URL; we use /oauth2/token)
//   - a DPoP proof `htu` must equal the same audience (<tenant>/oauth2/token), otherwise CSIAQ5176E
// Private keys are passed in and never written by this module.
const crypto = require('crypto');
const { BASE } = require('../lib/verify');

const b64u = (b) => Buffer.from(b).toString('base64url');
const TOKEN_AUD = `${BASE}/oauth2/token`;

function signRs256(privateKey, header, payload) {
  const h = b64u(JSON.stringify(header));
  const p = b64u(JSON.stringify(payload));
  const sig = crypto.sign('RSA-SHA256', Buffer.from(`${h}.${p}`), privateKey).toString('base64url');
  return `${h}.${p}.${sig}`;
}

// Client assertion for private_key_jwt. `kid` must name a key that is in the client's JWKS.
function clientAssertion({ privateKey, kid, clientId }) {
  const now = Math.floor(Date.now() / 1000);
  return signRs256(privateKey, { alg: 'RS256', typ: 'JWT', kid }, {
    iss: clientId, sub: clientId, aud: TOKEN_AUD, iat: now, exp: now + 120, jti: crypto.randomUUID(),
  });
}

// DPoP proof for one request. `ath` (hash of the access token) is only set for resource calls.
function dpopProof({ privateKey, publicKey, htm, htu, ath }) {
  const pub = publicKey.export({ format: 'jwk' });
  const header = { typ: 'dpop+jwt', alg: 'RS256', jwk: { kty: pub.kty, n: pub.n, e: pub.e } };
  const payload = { jti: crypto.randomUUID(), htm, htu, iat: Math.floor(Date.now() / 1000), ...(ath ? { ath } : {}) };
  return signRs256(privateKey, header, payload);
}

// DPoP key thumbprint (RFC 7638, RSA): base64url(SHA-256 of the canonical {e,kty,n} JSON). Compared with introspection's cnf.jkt.
function jwkThumbprint(publicKey) {
  const j = publicKey.export({ format: 'jwk' });
  return crypto.createHash('sha256').update(JSON.stringify({ e: j.e, kty: 'RSA', n: j.n })).digest('base64url');
}

// Access-token hash for DPoP `ath`: base64url(SHA-256(ascii(token))).
const athOf = (token) => crypto.createHash('sha256').update(token).digest('base64url');

module.exports = { TOKEN_AUD, clientAssertion, dpopProof, jwkThumbprint, athOf, signRs256 };

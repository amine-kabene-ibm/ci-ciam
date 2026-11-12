'use strict';
// A software WebAuthn authenticator (UC-02). It plays what a browser + authenticator do, so the server side of the passkey ceremony
// (Verify FIDO2 attestation and assertion APIs) can be exercised from a script without a human. ES256 (P-256) credentials, "none" attestation.
// It is NOT a platform authenticator (no Touch ID, no secure enclave): the real device ceremony stays [HUMAN].
// Nothing here logs private keys, credential ids or challenges.
const crypto = require('crypto');

const b64u = (b) => Buffer.from(b).toString('base64url');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();

// ---- minimal CBOR encoder: unsigned/negative ints, byte strings, text strings, maps (what a COSE key and an attestation object need) ----
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  throw new Error('cbor: value too large');
}
function cbor(v) {
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === 'string') { const s = Buffer.from(v); return Buffer.concat([head(3, s.length), s]); }
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error('cbor: unsupported type');
}

class VirtualAuthenticator {
  // origin / rpId are what the "browser" would put into clientDataJSON / hash. userHandle is stored with the credential (resident key).
  constructor({ aaguid } = {}) { this.creds = new Map(); this.aaguid = aaguid || Buffer.alloc(16); }

  create(options, origin) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const credId = crypto.randomBytes(32);
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    const idLen = Buffer.alloc(2); idLen.writeUInt16BE(credId.length);
    const flags = 0x01 | 0x04 | 0x40 | 0x08 | 0x10; // UP, UV, AT, BE, BS (a synced "passkey")
    const authData = Buffer.concat([sha256(options.rp.id), Buffer.from([flags]), Buffer.alloc(4), this.aaguid, idLen, credId, cose]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }));
    const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    this.creds.set(b64u(credId), { privateKey, rpId: options.rp.id, userHandle: options.user.id, signCount: 0 });
    return {
      id: b64u(credId), rawId: b64u(credId), type: 'public-key',
      response: { attestationObject: b64u(attestationObject), clientDataJSON: b64u(clientData), transports: ['internal'] },
      clientExtensionResults: {},
    };
  }

  // allowCredentialIds: restrict to these (if the server sent allowCredentials); otherwise any resident credential for the rp (usernameless).
  get(options, origin, { tamper } = {}) {
    const rpId = options.rpId;
    const ids = (options.allowCredentials || []).map((c) => c.id);
    const id = [...this.creds.keys()].find((k) => this.creds.get(k).rpId === rpId && (ids.length === 0 || ids.includes(k)));
    if (!id) return null; // no usable passkey on this "device"
    const c = this.creds.get(id);
    c.signCount += 1;
    const sc = Buffer.alloc(4); sc.writeUInt32BE(c.signCount);
    const authData = Buffer.concat([sha256(rpId), Buffer.from([0x01 | 0x04 | 0x08 | 0x10]), sc]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }));
    const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientData)]), c.privateKey);
    if (tamper) signature[signature.length - 1] ^= 0xff;
    return {
      id, rawId: id, type: 'public-key',
      response: { authenticatorData: b64u(authData), clientDataJSON: b64u(clientData), signature: b64u(signature), userHandle: c.userHandle },
      clientExtensionResults: {},
    };
  }
}

module.exports = { VirtualAuthenticator, b64u };

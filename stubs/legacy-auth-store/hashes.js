'use strict';
// Password hash formats of a STUB legacy credential store (UC-11). IFC has not named its legacy algorithm, so the store speaks several:
//   - LDAP-style "{SCHEME}base64" values: the formats IBM Verify's CSV import accepted in live tests (2026-11-11, DEMO-BUILD-GUIDE.md finding 38)
//   - $pbkdf2-sha256$...: a modern hash that Verify's import does NOT understand, so those users can only migrate just in time
//   - {SMD5} and {SHA1}: formats Verify refused in the same tests (used only by the hash-format matrix in run.js)
// Nothing here is a production password library: it exists to make realistic legacy records for a demo.
const crypto = require('crypto');

const sha = (alg, data) => crypto.createHash(alg).update(data).digest();
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);

// scheme -> hash function and digest size. salted = digest(password + salt) followed by the salt, as in LDAP {SSHA}.
const LDAP = {
  SSHA256: { alg: 'sha256', len: 32, salted: true },
  SHA256: { alg: 'sha256', len: 32, salted: false },
  SSHA384: { alg: 'sha384', len: 48, salted: true },
  SHA384: { alg: 'sha384', len: 48, salted: false },
  SSHA512: { alg: 'sha512', len: 64, salted: true },
  SHA512: { alg: 'sha512', len: 64, salted: false },
  SSHA: { alg: 'sha1', len: 20, salted: true },
  SHA: { alg: 'sha1', len: 20, salted: false },
  MD5: { alg: 'md5', len: 16, salted: false },
  SMD5: { alg: 'md5', len: 16, salted: true }, // refused by Verify's import [LIVE]
  SHA1: { alg: 'sha1', len: 20, salted: false }, // the "{SHA1}" spelling is refused by Verify's import [LIVE] ("{SHA}" is accepted)
};
const PBKDF2_ITERATIONS = 10000;

// Schemes the Verify CSV import turned into a working login in live tests.
const VERIFY_IMPORTABLE = ['SSHA256', 'SHA256', 'SSHA384', 'SHA384', 'SSHA512', 'SHA512', 'SSHA', 'SHA', 'MD5'];

function make(scheme, password) {
  if (scheme === 'PBKDF2') {
    const salt = crypto.randomBytes(16);
    const dk = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, 'sha256');
    return `$pbkdf2-sha256$i=${PBKDF2_ITERATIONS}$${salt.toString('base64')}$${dk.toString('base64')}`;
  }
  const s = LDAP[scheme];
  if (!s) throw new Error(`unknown scheme ${scheme}`);
  if (!s.salted) return `{${scheme}}${sha(s.alg, Buffer.from(password, 'utf8')).toString('base64')}`;
  const salt = crypto.randomBytes(8);
  return `{${scheme}}${Buffer.concat([sha(s.alg, Buffer.concat([Buffer.from(password, 'utf8'), salt])), salt]).toString('base64')}`;
}

function check(hash, password) {
  if (hash.startsWith('$pbkdf2-sha256$')) {
    const [, , params, salt, dk] = hash.split('$');
    const iterations = Number(params.replace('i=', ''));
    return eq(crypto.pbkdf2Sync(password, Buffer.from(salt, 'base64'), iterations, 32, 'sha256'), Buffer.from(dk, 'base64'));
  }
  const m = hash.match(/^\{([A-Z0-9]+)\}(.+)$/);
  const s = m && LDAP[m[1]];
  if (!s) return false;
  const raw = Buffer.from(m[2], 'base64');
  const pw = Buffer.from(password, 'utf8');
  if (!s.salted) return eq(sha(s.alg, pw), raw);
  return eq(sha(s.alg, Buffer.concat([pw, raw.subarray(s.len)])), raw.subarray(0, s.len));
}

const schemeOf = (hash) => (hash.startsWith('$pbkdf2-sha256$') ? 'PBKDF2' : (hash.match(/^\{([A-Z0-9]+)\}/) || [])[1] || 'UNKNOWN');
const isVerifyImportable = (scheme) => VERIFY_IMPORTABLE.includes(scheme);

module.exports = { make, check, schemeOf, isVerifyImportable, VERIFY_IMPORTABLE };

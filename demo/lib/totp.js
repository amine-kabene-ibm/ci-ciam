'use strict';
// RFC 6238 TOTP (SHA1, 6 digits, 30 s) so scripts can play the role of the user's authenticator app.
const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(s) {
  let bits = '';
  for (const ch of s.replace(/=+$/, '').toUpperCase()) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error('invalid base32 secret');
    bits += i.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

// key: base32 string, or Buffer when you already have raw bytes (used by the RFC test vector).
function totp(key, { windowOffset = 0, now = Date.now(), digits = 6, period = 30 } = {}) {
  const raw = Buffer.isBuffer(key) ? key : base32Decode(key);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(now / 1000 / period) + windowOffset));
  const h = crypto.createHmac('sha1', raw).update(counter).digest();
  const o = h[h.length - 1] & 15;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 10 ** digits).padStart(digits, '0');
}

// Milliseconds until the next 30 s boundary (plus a small margin).
const msToNextWindow = (now = Date.now(), period = 30) => period * 1000 - (now % (period * 1000)) + 1500;

module.exports = { totp, base32Decode, msToNextWindow };

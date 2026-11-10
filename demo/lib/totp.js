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

// Plays "the authenticator app" for scripts. `state` is a stateFile() object whose JSON holds {totp:{secret}}.
// Verify rejects a TOTP code that was already used (replay) and accepts windows -1/0/+1 around now [LIVE], so next() picks the
// lowest window newer than the last one used and sleeps to the next 30 s boundary only if none is left.
// The last used window is persisted in the state file (totpLastWindow) so re-runs stay valid.
function totpPlayer(state) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  async function next() {
    for (;;) {
      const st = state.read();
      const cur = Math.floor(Date.now() / 30000);
      const w = Math.max(cur - 1, (st.totpLastWindow || 0) + 1);
      if (w <= cur + 1) {
        st.totpLastWindow = w; state.write(st);
        return { code: totp(st.totp.secret, { windowOffset: w - cur }), window: w, offset: w - cur };
      }
      await sleep(msToNextWindow());
    }
  }
  // A well-formed code that is not the current one. Does NOT consume a TOTP window (a window is single-use at Verify).
  function wrong() {
    const right = totp(state.read().totp.secret, { windowOffset: 0 });
    return String((parseInt(right, 10) + 111111) % 1000000).padStart(6, '0');
  }
  return { next, wrong };
}

module.exports = { totp, base32Decode, msToNextWindow, totpPlayer };

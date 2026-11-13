'use strict';
// UC-01 shared constants (self-service registration + progressive profiling). Everything on the tenant starts with "ifc-demo-uc01-".
const crypto = require('crypto');
const axios = require('axios');
const { PREFIX: ROOT, stateFile, sleep } = require('../lib/verify');

const UC = 'uc01';
const PREFIX = `${ROOT}uc01-`;
const GROUP = `${PREFIX}customers`;            // every self-registered customer lands here (also how teardown finds them)
const PORTAL_APP = `${PREFIX}portal`;          // DCR app: the registration portal's sign-in (authorization code + PKCE) and scripted password grant
const REG_CLIENT = `${PREFIX}registration`;    // API client: the registration service's own least-privilege identity
// Measured [LIVE 2026-11-12]: SCIM create/patch/read = readUsers + manageUsers; the e-mail OTP create/verify needs authnAnyUser
// (generateOTP gives 403 CSIAK4300E); adding a user to a group needs manageGroupMembers (403 CSIAK4300E otherwise).
const REG_ENTITLEMENTS = ['readUsers', 'manageUsers', 'authnAnyUser', 'manageGroupMembers'];
const ATTRIBUTES = [
  { name: `${PREFIX}client360-id`, scim: 'client360Id', unique: false },
  { name: `${PREFIX}policy-number`, scim: 'policyNumber', unique: true }, // unique: the backstop for "one account per policy"
  { name: `${PREFIX}has-vehicle`, scim: 'hasVehicle', unique: false },
];
const PORTS = { client360: 4010, portal: 4011 };

const state = stateFile(UC);
const randomPart = (n) => crypto.randomBytes(n).toString('hex');
// Meets the tenant password policy (upper, lower, digit, symbol) without a fixed literal.
const newPassword = () => `IfcDemo!${randomPart(5)}A1#`;

// ---- disposable inbox (mail.tm) so the script can read the REAL Verify e-mail itself [LIVE 2026-11-12] ----
const MAILTM = 'https://api.mail.tm';
async function mt(method, p, { body, token } = {}) {
  try {
    return await axios({ method, url: MAILTM + p, data: body, headers: token ? { Authorization: `Bearer ${token}` } : {}, validateStatus: () => true, timeout: 15000 });
  } catch (e) { throw new Error(`mail.tm unreachable (${e.code || 'error'})`); }
}
// mail.tm answers 429 when accounts are created in a burst: wait and retry (up to about 1 minute).
async function mtRetry(...args) {
  for (let i = 0; ; i++) {
    const r = await mt(...args);
    if (r.status !== 429 || i >= 8) return r;
    await sleep(4000 + i * 2000);
  }
}
// UC-03 reuses this inbox for its own customers: `prefix` names the address, and `password` is returned so a person can open the same
// mailbox at https://mail.tm during the demo (the token alone cannot be used in the web UI).
async function createInbox(prefix = 'ifc-demo-uc01-') {
  const d = await mtRetry('get', '/domains');
  const domain = d.data['hydra:member'][0].domain;
  const address = `${prefix}${randomPart(4)}@${domain}`;
  const password = newPassword();
  const a = await mtRetry('post', '/accounts', { body: { address, password } });
  if (a.status !== 201) throw new Error(`mail.tm account: HTTP ${a.status}`);
  const t = await mtRetry('post', '/token', { body: { address, password } });
  if (t.status !== 200) throw new Error(`mail.tm token: HTTP ${t.status}`);
  return { address, password, token: t.data.token };
}
// Re-login of a stored inbox (the token of an old inbox may have expired). Returns a fresh {address, password, token} or null.
async function inboxLogin(inbox) {
  const t = await mtRetry('post', '/token', { body: { address: inbox.address, password: inbox.password } });
  return t.status === 200 ? { ...inbox, token: t.data.token } : null;
}
// All messages of an inbox, newest first, with full text: [{id, subject, text, at (ms)}]. Returns null if the token is refused.
async function readMessages(inbox) {
  const l = await mtRetry('get', '/messages', { token: inbox.token });
  if (l.status !== 200) return null;
  const out = [];
  for (const m of (l.data && l.data['hydra:member']) || []) {
    const full = await mtRetry('get', `/messages/${m.id}`, { token: inbox.token });
    out.push({ id: m.id, subject: String((full.data && full.data.subject) || '').trim(), text: String((full.data && full.data.text) || ''), at: Date.parse(full.data && full.data.createdAt) });
  }
  return out;
}
// The Verify e-mail reads "... 7920-511189 ...": the first 4 digits are the correlation shown on screen, the person types the rest.
async function waitForOtp(inbox, { correlation, timeoutMs = 170000 } = {}) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const l = await mt('get', '/messages', { token: inbox.token });
    for (const m of (l.data && l.data['hydra:member']) || []) {
      const full = await mt('get', `/messages/${m.id}`, { token: inbox.token });
      const hit = String((full.data && full.data.text) || '').match(/\b(\d{4})-(\d{6})\b/);
      if (hit && (!correlation || hit[1] === String(correlation))) return { code: hit[2], ms: Date.now() - t0 };
    }
    await sleep(3000);
  }
  throw new Error('no Verify e-mail arrived in time');
}

module.exports = {
  UC, PREFIX, GROUP, PORTAL_APP, REG_CLIENT, REG_ENTITLEMENTS, ATTRIBUTES, PORTS, state, newPassword, createInbox, waitForOtp, inboxLogin, readMessages,
};

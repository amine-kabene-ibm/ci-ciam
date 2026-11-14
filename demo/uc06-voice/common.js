'use strict';
// Names and constants shared by all UC-06 scripts. Everything on the tenant starts with "ifc-demo-uc06-".
const { PREFIX, stateFile, api } = require('../lib/verify');
const be = require('../../stubs/voicebot-ccaas/backends');

const UC = 'uc06';
const CCAAS_CLIENT = `${PREFIX}uc06-ccaas`;
// Least privilege for the CCaaS/voicebot. Measured [LIVE] with 403 probes:
//   readUsers (SCIM lookup), authnAnyUser (create/attempt OTP), readEnrollMFAMethodAnyUser (list TOTP + push enrolments).
// readAuthenticatorsAnyUser + mfaPush are included for the push step-up. UC-04 measured [LIVE 2026-11-13] with a software device:
// creating a push needs authnAnyUser (already listed), and mfaPush alone does NOT enable it, so mfaPush is harmless but not needed.
// Compare: the admin client holds 165 entitlements.
const CCAAS_ENTITLEMENTS = ['readUsers', 'authnAnyUser', 'readEnrollMFAMethodAnyUser', 'readAuthenticatorsAnyUser', 'mfaPush'];
const VERIFY_PROFILE_CLIENT_ID = '5280f51a-9699-4d96-9dd9-bcc0fdfdf9dd'; // "Verify Profile" authenticator client [LIVE]
const state = stateFile(UC);
const customer = be.customers[0];

// The mailbox that receives the e-mail OTP. Override with UC06_MAILBOX; default = the tenant admin's e-mail (the presenter).
async function resolveMailbox() {
  if (process.env.UC06_MAILBOX) return process.env.UC06_MAILBOX;
  const r = await api('GET', '/v2.0/Users', { query: { count: 100, attributes: 'userName,emails' } });
  const admin = ((r.data && r.data.Resources) || []).find((u) => !u.userName.startsWith(PREFIX) && u.emails && u.emails[0]);
  if (!admin) throw new Error('No mailbox found. Set UC06_MAILBOX=you@example.com');
  return admin.emails[0].value;
}

// Plays "the authenticator app" for scripts (shared with UC-07): see totpPlayer in ../lib/totp.js.
const player = require('../lib/totp').totpPlayer(state);
const nextTotpCode = player.next;
const wrongTotp = player.wrong;

module.exports = { nextTotpCode, wrongTotp, UC, CCAAS_CLIENT, CCAAS_ENTITLEMENTS, VERIFY_PROFILE_CLIENT_ID, state, customer, resolveMailbox };

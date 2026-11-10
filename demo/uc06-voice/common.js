'use strict';
// Names and constants shared by all UC-06 scripts. Everything on the tenant starts with "ifc-demo-uc06-".
const { PREFIX, stateFile, api } = require('../lib/verify');
const be = require('../../stubs/voicebot-ccaas/backends');

const UC = 'uc06';
const CCAAS_CLIENT = `${PREFIX}uc06-ccaas`;
// Least privilege for the CCaaS/voicebot. Measured [LIVE] with 403 probes:
//   readUsers (SCIM lookup), authnAnyUser (create/attempt OTP), readEnrollMFAMethodAnyUser (list TOTP + push enrolments).
// readAuthenticatorsAnyUser + mfaPush are included for the push step-up [INFER]: the push call cannot be exercised
// without a registered phone, so these two are not proven necessary. Compare: the admin client holds 165 entitlements.
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

// Plays "the authenticator app" for scripts. Verify rejects a TOTP code that was already used (replay) [LIVE] and accepts
// windows -1/0/+1 around now [LIVE], so each call picks the lowest window that is newer than the last one used, and
// sleeps to the next 30 s boundary only if none is left. The last used window is persisted so re-runs stay valid.
const { totp, msToNextWindow } = require('../lib/totp');
const { sleep } = require('../lib/verify');
async function nextTotpCode() {
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
function wrongTotp() {
  const st = state.read();
  const right = totp(st.totp.secret, { windowOffset: 0 });
  return String((parseInt(right, 10) + 111111) % 1000000).padStart(6, '0');
}

module.exports = { nextTotpCode, wrongTotp, UC, CCAAS_CLIENT, CCAAS_ENTITLEMENTS, VERIFY_PROFILE_CLIENT_ID, state, customer, resolveMailbox };

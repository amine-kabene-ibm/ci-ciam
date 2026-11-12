'use strict';
// Names and constants shared by all UC-02 scripts. Everything on the tenant starts with "ifc-demo-uc02-".
const crypto = require('crypto');
const { PREFIX, BASE, stateFile } = require('../lib/verify');
const { createInbox, waitForOtp } = require('../uc01-registration/common');
const { decode } = require('../uc08-sso/browser');

const UC = 'uc02';
const state = stateFile(UC);
const P = `${PREFIX}uc02-`;
const randomSecret = (n) => crypto.randomBytes(n).toString('base64url');
// Meets the tenant password policy (upper, lower, digit, symbol) without a fixed literal.
const newUserCredential = () => ['Ifc', randomSecret(9), '8b'].join('-') + '!';

// Three applications = three required assurance levels (AAL). The level is an ACCESS POLICY bound to the application, not code.
//   aal1: password only.   aal2: password + any of passkey / authenticator app (TOTP) / e-mail OTP.   aal3: password + passkey only.
// The methods are the v5 policy names [LIVE]: fido2, totp, emailotp (smsotp exists but SMS is blocked on the trial, see SMS below).
const LEVELS = {
  aal1: { key: 'aal1', policy: `${P}policy-aal1-password`, app: `${P}app-aal1`, port: 4021, title: 'AAL1 - everyday (password only)', colour: '#198038', action: 'ACTION_ALLOW', authnMethods: ['totp'], description: 'UC-02 AAL1: password only' },
  aal2: { key: 'aal2', policy: `${P}policy-aal2-otp`, app: `${P}app-aal2`, port: 4022, title: 'AAL2 - account changes (passkey, authenticator app or e-mail code)', colour: '#0f62fe', action: 'ACTION_MFA_ALWAYS', authnMethods: ['fido2', 'totp', 'emailotp'], description: 'UC-02 AAL2: password + passkey, authenticator app or e-mail OTP' },
  aal3: { key: 'aal3', policy: `${P}policy-aal3-passkey`, app: `${P}app-aal3`, port: 4023, title: 'AAL3 - payments and claims (passkey only)', colour: '#6929c4', action: 'ACTION_MFA_ALWAYS', authnMethods: ['fido2'], description: 'UC-02 AAL3: password + passkey only (phishing-resistant)' },
};
const LEVEL_LIST = Object.values(LEVELS);
const origin = (l) => `http://localhost:${l.port}`;
const policyRules = (l) => [{ name: 'all customers', action: l.action, authnMethods: l.authnMethods, conditions: [] }];

// alice: a customer who later enrolls a passkey (run.js does it: "register from account settings"). bob: no passkey-capable device: fallback customer.
// Both have a validated authenticator app (TOTP) and a REAL mailbox (mail.tm) so the e-mail OTP is the real Verify e-mail.
const USERS = {
  alice: { userName: `${P}alice`, given: 'Alice', family: 'Passkey' },
  bob: { userName: `${P}bob`, given: 'Bob', family: 'Fallback' },
};

// Password-grant client: lets a script act as the signed-in customer (self-service calls with the customer's own token).
const CONSOLE_APP = `${P}app-console`;
// BYO SMS gateway objects (provider first, then webhook on delete).
const SMS_NAME = `${P}sms-gateway`;

// totpPlayer() wants a state object holding {totp:{secret}, totpLastWindow}; adapt it to one user inside the UC-02 state file.
const userTotpState = (k) => ({
  read() { const s = state.read(); return { totp: s.users[k].totp, totpLastWindow: s.users[k].totpLastWindow }; },
  write(o) { const s = state.read(); s.users[k].totp = o.totp; s.users[k].totpLastWindow = o.totpLastWindow; state.write(s); },
});

// ---- driving the Verify-hosted second-factor pages (what a person's browser does) [LIVE] ----
const tagOf = (html) => (html.match(/Template File Name: ([^ ]*)/) || [])[1] || '';
const actionOf = (page) => { const m = page.html.match(/<meta name="action" content\s*=\s*"([^"]*)"/); return m ? new URL(decode(m[1]), page.url).href : null; };
// Method choice page: <meta name="otpMethod" content="<label>|<id>|<id>|||<type>"> per enrolled method; a single method skips this page.
const methodsOf = (page) => [...page.html.matchAll(/<meta name="otpMethod" content\s*=\s*"([^"]*)"/g)].map((m) => { const f = decode(m[1]).split('|'); return { label: f[0], id: f[1], type: f[f.length - 1] }; });
const pageKind = (page) => {
  const t = tagOf(page.html);
  if (/mfa_selection/.test(t)) return 'select';
  if (/fido2/.test(t)) return 'fido2';
  if (/time_based_otp/.test(t)) return 'totp';
  if (/otp_auth\/otp_submit/.test(t)) return 'emailotp';
  if (/mfa\/error|oidc\/error/.test(t)) return 'error';
  return /code=/.test(page.url) ? 'redirect' : 'other';
};
const selectMethod = (br, page, type) => {
  const m = methodsOf(page).find((x) => x.type === type);
  if (!m) throw new Error(`method ${type} not offered`);
  return br.post(actionOf(page), { operation: 'generate', 'otp.user.otp-method.id': m.id });
};
const useAnotherMethod = (br, page) => br.post(actionOf(page), { operation: 'restart' });
// The e-mail OTP page names its fields differently from the TOTP page: code in "otp.user.otp", the on-screen number in the hidden "otp.user.otp-hint" [LIVE].
const hintOf = (page) => (page.html.match(/name="otp\.user\.otp-hint"\s+value="(\d+)"/) || [])[1];
const submitEmailOtp = (br, page, code) => br.post(actionOf(page), { 'otp.user.otp': code, 'otp.user.otp-hint': hintOf(page) || '', operation: 'verify' });
const serverOptions = (page) => JSON.parse(decode(page.html.match(/<meta name="serverOptions" content='([^']*)'/)[1]));
// The passkey page's script posts the browser's assertion as JSON in "assertionResponse".
const answerPasskey = (br, page, device, { tamper = false, options } = {}) => {
  const a = device.get(options || serverOptions(page), BASE, { tamper });
  if (!a) return null;
  return br.post(actionOf(page), { operation: 'authenticate', assertionResponse: JSON.stringify({ id: a.id, rawId: a.rawId, type: 'public-key', response: { clientDataJSON: a.response.clientDataJSON, authenticatorData: a.response.authenticatorData, signature: a.response.signature, userHandle: a.response.userHandle } }) });
};

module.exports = { hintOf, submitEmailOtp, tagOf, actionOf, methodsOf, pageKind, selectMethod, useAnotherMethod, serverOptions, answerPasskey, userTotpState, UC, BASE, PREFIX, P, state, newUserCredential, LEVELS, LEVEL_LIST, origin, policyRules, USERS, CONSOLE_APP, SMS_NAME, createInbox, waitForOtp };

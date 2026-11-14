'use strict';
// UC-04 shared constants (trusted devices, push, self-service revoke). Everything on the tenant starts with "ifc-demo-uc04-".
const crypto = require('crypto');
const { PREFIX: ROOT, stateFile, BASE } = require('../lib/verify');
const { VERIFY_PROFILE_CLIENT_ID } = require('../lib/verifyDevice');
const { tagOf, actionOf, methodsOf, pageKind } = require('../uc02-passkeys/common');

const UC = 'uc04';
const P = `${ROOT}uc04-`;
const state = stateFile(UC);
const PORT = 4041;                       // the "My trusted devices" portal (stubs/device-portal)
const CALLBACK_PORT = 4042;              // throwaway listener that stops the scripted browser at the redirect_uri of the login app

const CONSOLE_APP = `${P}app-console`;   // password-grant client: lets a script act as the signed-in customer (the mobile app / portal)
const LOGIN_APP = `${P}app-login`;       // code + PKCE app bound to the push policy: "sign in, then approve on your trusted device"
const PUSH_POLICY = `${P}policy-push`;   // password + approve on a registered device (any signature method, i.e. push)
const SERVICE_CLIENT = `${P}device-service`; // API client: the back-end device service, least privilege
const MOBILE_CLIENT = `${P}ifc-mobile-app`;  // authenticator client = the registration profile of IFC's OWN branded app
// Measured [LIVE 2026-11-13] with a 403 matrix (run.js scenario A): initiation + delete need manageAuthenticatorsAnyUser, list needs
// readAuthenticatorsAnyUser, the push-method lookup needs readEnrollMFAMethodAnyUser, and creating/polling a push needs authnAnyUser
// (mfaPush alone did NOT enable it). readReports = the audit (events API). readUsers is not part of it, so SCIM reads are refused.
const SERVICE_ENTITLEMENTS = ['readAuthenticatorsAnyUser', 'manageAuthenticatorsAnyUser', 'readEnrollMFAMethodAnyUser', 'authnAnyUser', 'readReports'];

const USERS = {
  marie: { userName: `${P}marie`, given: 'Marie', family: 'Tremblay' },     // the customer with two trusted devices
  olivier: { userName: `${P}olivier`, given: 'Olivier', family: 'Lavoie' }, // another customer: proves one customer cannot touch another's devices
};

const randomSecret = (n) => crypto.randomBytes(n).toString('base64url');
// Meets the tenant password policy (upper, lower, digit, symbol) without a fixed literal.
const newPassword = () => ['Ifc', randomSecret(9), '8b'].join('-') + '!';

// Hosted login with two devices shows a method choice page; the ORDER of devices is not stable [LIVE], so pick by the device name in the label.
const pickDevice = (br, page, name) => {
  const m = methodsOf(page).find((x) => x.type === 'signature' && x.label.startsWith(name));
  if (!m) throw new Error(`device "${name}" not offered on the login page`);
  return br.post(actionOf(page), { operation: 'generate', 'otp.user.otp-method.id': m.id });
};
const errorCode = (page) => ((page.html.match(/<meta name="errorMessage" content="([^"]*)/) || [])[1] || '').slice(0, 120);
const callbackUrl = `http://localhost:${CALLBACK_PORT}/callback`;
const authorizeUrl = (clientId) => {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: callbackUrl, scope: 'openid', state: crypto.randomBytes(8).toString('hex'),
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
  });
  return `${BASE}/oidc/endpoint/default/authorize?${q}`;
};

module.exports = {
  UC, P, PREFIX: P, state, PORT, CALLBACK_PORT, CONSOLE_APP, LOGIN_APP, PUSH_POLICY, SERVICE_CLIENT, MOBILE_CLIENT, SERVICE_ENTITLEMENTS, USERS,
  newPassword, pickDevice, errorCode, authorizeUrl, callbackUrl, tagOf, pageKind, methodsOf, actionOf, VERIFY_PROFILE_CLIENT_ID,
};

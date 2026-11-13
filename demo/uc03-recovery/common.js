'use strict';
// UC-03 shared constants (risk-aware account recovery, agent-assisted). Everything on the tenant starts with "ifc-demo-uc03-".
const crypto = require('crypto');
const { PREFIX: ROOT, BASE, stateFile, send } = require('../lib/verify');

const UC = 'uc03';
const PREFIX = `${ROOT}uc03-`;
const PORTAL_APP = `${PREFIX}portal`;            // DCR client: stands in for the IFC customer portal (hosted sign-in + scripted password grant)
const AGENT_CLIENT = `${PREFIX}recovery-console`; // API client: the recovery console's own least-privilege identity (not the admin client)
// Measured [LIVE 2026-11-12], each one removed in turn gives 403 on the call it serves:
//   readUsers                  -> SCIM lookup of the caller (signals: lastLogin, pwdChangedTime, lock)
//   resetPasswordAnyUser       -> PATCH /v2.0/Users/{id}/passwordResetter (the agent's reset)
//   revokeAllSessions          -> DELETE /v1.0/auth/sessions/{id} (end active sessions after the reset)
//   readReports                -> GET /v1.0/events (audit trail + sign-in history used as risk signals)
//   readEnrollMFAMethodAnyUser -> GET /v2.0/factors/totp?search=userId=... (when was a factor added = "recent factor change")
//   authnAnyUser               -> e-mail OTP to the registered address, to verify the caller before the reset
const AGENT_ENTITLEMENTS = ['readUsers', 'resetPasswordAnyUser', 'revokeAllSessions', 'readReports', 'readEnrollMFAMethodAnyUser', 'authnAnyUser'];
const AGENT_LABEL = 'IFC agent 482';
const PORT = 4030;

// The device the customers "always use": its User-Agent string is what Verify records as `devicetype` on each sign-in event.
const KNOWN_UA = 'IFC-Portal/2.1 (Windows 11; Chrome 126) demo-known-device';
const NEW_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) demo-new-device';

const CUSTOMERS = {
  sophie: { userName: `${PREFIX}sophie`, given: 'Sophie', family: 'Gagnon', story: 'locked out after changing phones; no recent security change -> low risk' },
  marc: { userName: `${PREFIX}marc`, given: 'Marc', family: 'Bouchard', story: 'a new authenticator was added minutes ago, then a recovery request -> higher risk', totp: true },
  lena: { userName: `${PREFIX}lena`, given: 'Lena', family: 'Tremblay', story: 'sign-in attempts from a device never seen before (an attacker, or a new phone) -> higher risk' },
};

const state = stateFile(UC);
const randomPart = (n) => crypto.randomBytes(n).toString('hex');
// Meets the tenant password policy (upper, lower, digit, symbol) without a fixed literal.
const newPassword = () => `IfcDemo!${randomPart(5)}A1#`;

// Password sign-in as the customer portal would do it, with a chosen User-Agent (Verify stores it as `devicetype` in the sign-in event).
async function signIn(portal, userName, password, userAgent = KNOWN_UA, extraHeaders = {}) {
  const r = await send({
    method: 'post', url: `${BASE}/oidc/endpoint/default/token`, validateStatus: () => true, transformResponse: (x) => x,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', 'User-Agent': userAgent, ...extraHeaders,
      Authorization: `Basic ${Buffer.from(`${portal.clientId}:${portal.clientSecret}`).toString('base64')}`,
    },
    data: new URLSearchParams({ grant_type: 'password', username: userName, password, scope: 'openid' }).toString(),
  });
  let data = r.data;
  if (typeof data === 'string') { try { data = data.length ? JSON.parse(data) : null; } catch (e) { data = { error: 'non_json_response' }; } }
  return { status: r.status, data: data || {} };
}

module.exports = {
  UC, PREFIX, PORTAL_APP, AGENT_CLIENT, AGENT_ENTITLEMENTS, AGENT_LABEL, PORT, KNOWN_UA, NEW_UA, CUSTOMERS, state, newPassword, signIn,
};

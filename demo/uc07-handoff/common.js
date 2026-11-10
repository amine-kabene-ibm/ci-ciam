'use strict';
// Names and constants shared by all UC-07 scripts. Everything on the tenant starts with "ifc-demo-uc07-".
const crypto = require('crypto');
const { PREFIX, stateFile, oauthClient, createClient } = require('../lib/verify');
const be = require('../../stubs/voicebot-ccaas/backends');
// Same least-privilege set as the UC-06 voicebot (measured there with 403 probes): the hand-off adds one SCIM read by id, which
// `readUsers` already covers [LIVE]. Reused, not duplicated. resolveMailbox: UC06_MAILBOX overrides the default (tenant admin e-mail).
const { CCAAS_ENTITLEMENTS, resolveMailbox } = require('../uc06-voice/common');

const UC = 'uc07';
const USER_NAME = `${PREFIX}uc07-marie`;
const CCAAS_CLIENT = `${PREFIX}uc07-ccaas`;      // API client: the voicebot's least-privilege identity for SCIM / MFA calls
const STS_CLIENT = `${PREFIX}uc07-ccaas-sts`;    // STS client: introspects app tokens and performs the RFC 8693 exchange
const APP_CLIENT = `${PREFIX}uc07-mobile-app`;   // DCR client that plays the mobile app for scripted logins (password grant)
const VOICE_TOKEN_TTL_SEC = 300;                 // lifetime of the voice-channel token minted by the exchange
const MAX_APP_AUTH_AGE_SEC = 900;                // policy: an app login older than 15 min no longer skips the check [INFER: iat as auth time]
const state = stateFile(UC);
const customer = be.findByUserName(USER_NAME);
const player = require('../lib/totp').totpPlayer(state);
const randomSecret = (n) => crypto.randomBytes(n).toString('base64url');
// Meets the tenant password policy (upper, lower, digit, symbol) without a fixed literal.
const newUserCredential = () => ['Ifc', randomSecret(9), '7a'].join('-') + '!';

// The hand-off configuration the stub needs. extraClientIds = the real demo app's OIDC client id (browser login).
function handoffConfig(st, overrides = {}) {
  const allowed = [st.app.clientId].concat(overrides.extraClientIds || []);
  return { sts: oauthClient(st.sts.clientId, st.sts.secret), allowedClientIds: allowed, maxAppAuthAgeSec: MAX_APP_AUTH_AGE_SEC, ...overrides };
}
const ccaasApi = (st) => createClient(st.ccaas.clientId, st.ccaas.clientSecret).api;

// Scripted "customer signs in to the mobile app": password grant on the DCR client. Returns the access token and the login methods (amr).
async function appLogin(st) {
  const r = await oauthClient(st.app.clientId, st.app.clientSecret).passwordGrant(USER_NAME, st.user.password);
  let amr = null;
  if (r.status === 200 && r.data.id_token) {
    try { amr = JSON.parse(Buffer.from(r.data.id_token.split('.')[1], 'base64url').toString()).amr || null; } catch (e) { /* keep null */ }
  }
  return { status: r.status, accessToken: r.status === 200 ? r.data.access_token : null, amr, cid: r.cid, ms: r.ms, expiresIn: r.data && r.data.expires_in };
}

module.exports = {
  UC, USER_NAME, CCAAS_CLIENT, STS_CLIENT, APP_CLIENT, CCAAS_ENTITLEMENTS, VOICE_TOKEN_TTL_SEC, MAX_APP_AUTH_AGE_SEC,
  state, customer, player, randomSecret, newUserCredential, resolveMailbox, handoffConfig, ccaasApi, appLogin,
};

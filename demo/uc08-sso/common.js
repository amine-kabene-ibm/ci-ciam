'use strict';
// Names and constants shared by all UC-08 scripts. Everything on the tenant starts with "ifc-demo-uc08-".
const crypto = require('crypto');
const { PREFIX, BASE, stateFile } = require('../lib/verify');

const UC = 'uc08';
const state = stateFile(UC);
const randomSecret = (n) => crypto.randomBytes(n).toString('base64url');
// Meets the tenant password policy (upper, lower, digit, symbol) without a fixed literal.
const newUserCredential = () => ['Ifc', randomSecret(9), '8b'].join('-') + '!';

// Personas (B2B broker vs B2C policyholder), one group each. The id token's `groupIds` claim carries the group NAMES [LIVE].
const GROUP_BROKERS = `${PREFIX}uc08-brokers`;
const GROUP_CONSUMERS = `${PREFIX}uc08-consumers`;
const USERS = {
  broker: { userName: `${PREFIX}uc08-broker`, given: 'Brigitte', family: 'Broker', email: 'uc08.broker@ifc-demo.invalid', group: GROUP_BROKERS, totp: true },
  consumer: { userName: `${PREFIX}uc08-client`, given: 'Claude', family: 'Policyholder', email: 'uc08.client@ifc-demo.invalid', group: GROUP_CONSUMERS, totp: false },
};

// Two access policies = two assurance levels. Brokers get a second factor (TOTP), policyholders password only [LIVE].
//   standard: brokers -> second factor once per single-sign-on session (ACTION_MFA_PER_SESSION), everyone else allowed
//   high:     brokers -> second factor at EVERY sign-in to that app (ACTION_MFA_ALWAYS), everyone else allowed
const POLICIES = {
  standard: { name: `${PREFIX}uc08-policy-standard`, action: 'ACTION_MFA_PER_SESSION', description: 'UC-08: brokers need a second factor once per SSO session; policyholders password only' },
  high: { name: `${PREFIX}uc08-policy-high`, action: 'ACTION_MFA_ALWAYS', description: 'UC-08: brokers need a fresh second factor at every sign-in to this app; policyholders password only' },
};
const policyRules = (p) => [
  { name: 'brokers', action: p.action, authnMethods: ['totp'], conditions: [{ type: 'subjectAttributes', attributes: [{ name: 'groupIds', opCode: 'IN', values: [GROUP_BROKERS] }] }] },
  { name: 'everyone else', action: 'ACTION_ALLOW', authnMethods: ['totp'], conditions: [] },
];

// The relying applications. Per-app token lifetime (accessTokenExpiry, seconds) is the lever we have instead of a "session policy" [LIVE].
const APPS = [
  { key: 'portal', name: `${PREFIX}uc08-rp-portal`, title: 'IFC Customer & Broker Portal', port: 4001, colour: '#0f62fe', policy: 'standard', ttl: 7200, requireGroup: null, introspectEachRequest: false },
  { key: 'claims', name: `${PREFIX}uc08-rp-claims`, title: 'Claims System (brokers only)', port: 4002, colour: '#198038', policy: 'standard', ttl: 900, requireGroup: GROUP_BROKERS, introspectEachRequest: true },
  { key: 'quote', name: `${PREFIX}uc08-rp-quote`, title: 'Quoting Engine (high assurance)', port: 4003, colour: '#8a3ffc', policy: 'high', ttl: 1800, requireGroup: null, introspectEachRequest: false },
];
const appByKey = Object.fromEntries(APPS.map((a) => [a.key, a]));
const origin = (a) => `http://localhost:${a.port}`;

// Logout wiring for one app. mode 'front' (default, no tunnel needed) or 'back' (needs a public URL for the tenant to call).
const logoutConfig = (a, st) => (st.mode === 'back'
  ? { logoutOption: 'back_channel', logoutURI: `${st.backchannelBase.replace(/\/+$/, '')}/bc/${a.key}`, sessionRequired: true }
  : { logoutOption: 'front_channel', logoutURI: `${origin(a)}/frontchannel-logout`, sessionRequired: true });

module.exports = {
  UC, BASE, PREFIX, state, randomSecret, newUserCredential, GROUP_BROKERS, GROUP_CONSUMERS, USERS, POLICIES, policyRules, APPS, appByKey, origin, logoutConfig,
};

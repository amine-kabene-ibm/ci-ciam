'use strict';
// UC-14 shared constants (Policyholder authorizing a Call Center Agent via CIBA). Everything on the tenant starts with "ifc-demo-uc14-".
const crypto = require('crypto');
const { PREFIX: ROOT, stateFile } = require('../lib/verify');
const { resolveMailbox: resolveDefaultMailbox } = require('../uc06-voice/common');

const UC = 'uc14';
const PREFIX = `${ROOT}uc14-`;
const CIBA_APP = `${PREFIX}agent-ciba`;          // the agent console's OIDC client (grant CIBA, e-mail channel)
const PORTAL_APP = `${PREFIX}portal`;            // stands in for the customer portal: password grant, used to lock / test sign-in
const AGENT_CLIENT = `${PREFIX}agent-console`;   // API client: the console's own least-privilege identity (not the 165-entitlement admin client)
// Measured [LIVE 2026-11-12]: readUsers = read the caller + lock state, manageUsers = reset the password (the only way to clear a lock),
// readReports = the audit (events) API. With readUsers + manageUsers alone GET /v1.0/events is 403 CSIAK4300E.
const AGENT_ENTITLEMENTS = ['readUsers', 'manageUsers', 'readReports'];
const AGENT_LABEL = 'IFC agent 482';
const PORT = 4140;

const CUSTOMERS = {
  marie: {
    userName: `${PREFIX}marie`, given: 'Marie', family: 'Tremblay', entitled: true,
    // What "Client 360" would hold; the console shows it only after the caller approved [stub, not a Verify feature]
    client360: { policyNumber: 'AUTO-31877', product: 'Auto', vehicle: '2022 Mazda CX-5', postalCode: 'H2X 1Y4', renewalDate: '2027-02-03' },
  },
  outsider: { userName: `${PREFIX}outsider`, given: 'Olivier', family: 'Lavoie', entitled: false }, // not entitled to the CIBA app
};

const state = stateFile(UC);
const randomPart = (n) => crypto.randomBytes(n).toString('hex');
// Meets the tenant password policy (upper, lower, digit, symbol) without a fixed literal.
const newPassword = () => `IfcDemo!${randomPart(5)}A1#`;
const tempPassword = () => `Tmp!${randomPart(6)}Zq9`;

async function resolveMailbox() {
  return process.env.UC14_MAILBOX || resolveDefaultMailbox();
}

module.exports = {
  UC, PREFIX, CIBA_APP, PORTAL_APP, AGENT_CLIENT, AGENT_ENTITLEMENTS, AGENT_LABEL, PORT, CUSTOMERS,
  state, newPassword, tempPassword, resolveMailbox,
};

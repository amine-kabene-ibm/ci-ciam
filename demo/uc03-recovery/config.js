'use strict';
// Builds the recovery-console configuration from the UC-03 state file. One place, used by run.js and serve.js.
const c = require('./common');

function consoleConfig(st) {
  return {
    agentClientId: st.agent.clientId, agentClientSecret: st.agent.clientSecret, portalClientId: st.portal.clientId,
    redirectUri: `http://localhost:${c.PORT}/callback`, agentLabel: c.AGENT_LABEL,
    historyMs: 6 * 3600 * 1000,      // how far back sign-in history is read to learn "usual" devices and countries
    recentAttemptMs: 30 * 60 * 1000, // sign-in attempts inside this window are the ones judged
    recentFactorMs: 24 * 3600 * 1000, // an authenticator added inside this window is a risk signal
    verifiedTtlSec: 300,
  };
}

module.exports = { consoleConfig };

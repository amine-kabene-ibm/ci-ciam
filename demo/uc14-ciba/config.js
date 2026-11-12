'use strict';
// Builds the agent-console configuration from the UC-14 state file. One place, used by run.js, serve.js and lock.js.
const c = require('./common');

function agentConfig(st) {
  return {
    cibaClientId: st.app.clientId, cibaClientSecret: st.app.clientSecret, cibaApp: c.CIBA_APP,
    agentClientId: st.agent.clientId, agentClientSecret: st.agent.clientSecret,
    agentLabel: c.AGENT_LABEL, verifiedTtlSec: 300, requestedExpirySec: 900, tempPassword: c.tempPassword,
    client360: (userName) => {
      const e = Object.values(c.CUSTOMERS).find((x) => x.userName === userName);
      return e && e.client360 ? e.client360 : null;
    },
  };
}

module.exports = { agentConfig };

'use strict';
// UC-14 demo helper: lock the demo customer's account the way a real customer would, with 6 wrong passwords through the portal stand-in.
//   node demo/uc14-ciba/lock.js        then in the agent console: Verify customer -> Unlock account
const { api, oauthClient } = require('../lib/verify');
const c = require('./common');
const { IBM_EXT } = require('../../stubs/agent-console/agent');

async function lockCustomer(st, key = 'marie') {
  const u = st.users[key];
  const portal = oauthClient(st.portal.clientId, st.portal.clientSecret);
  for (let i = 0; i < 6; i++) await portal.passwordGrant(u.userName, `Wrong!Pass${i}x`);
  const g = await api('GET', `/v2.0/Users/${u.id}`, { quiet: true });
  return !!(g.data && g.data[IBM_EXT] && g.data[IBM_EXT].pwdAccountLockedTime);
}

async function main() {
  const st = c.state.read();
  if (!st) { console.error('Run setup first'); process.exit(2); }
  console.log(`${c.CUSTOMERS.marie.userName} locked: ${await lockCustomer(st)}`);
}

if (require.main === module) main().catch((e) => { console.error(e.message); process.exit(1); });
module.exports = { lockCustomer };

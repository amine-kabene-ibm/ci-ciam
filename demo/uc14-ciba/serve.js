'use strict';
// UC-14 live demo: the agent console on http://localhost:4140. The customer approves from their own mailbox.
//   node demo/uc14-ciba/serve.js
const { startServer } = require('../../stubs/agent-console/server');
const { agentConfig } = require('./config');
const c = require('./common');

async function main() {
  const st = c.state.read();
  if (!st || !st.app) { console.error('Run setup first: node demo/uc14-ciba/setup.js'); process.exit(2); }
  const port = parseInt(process.env.UC14_PORT || c.PORT, 10);
  const { url } = await startServer(port, agentConfig(st));
  console.log(`\nIFC agent console (UC-14): ${url}`);
  console.log(`Caller to type in: ${c.CUSTOMERS.marie.userName}   (approval e-mail goes to the presenter mailbox)`);
  console.log('To demo "unlock", lock her first:  node demo/uc14-ciba/lock.js');
  console.log('Customer password for the approval page: node -e "console.log(require(\'./demo/out/uc14.state.json\').users.marie.password)"\nCtrl+C to stop.');
}

if (require.main === module) {
  main().catch((e) => { console.error('Failed to start:', e.message); process.exit(1); });
}
module.exports = { main };

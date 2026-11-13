'use strict';
// UC-03 live demo: the recovery console on http://localhost:4030 (customer portal + agent console on one page).
//   node demo/uc03-recovery/serve.js
const { startServer } = require('../../stubs/recovery-console/server');
const { consoleConfig } = require('./config');
const c = require('./common');

async function main() {
  const st = c.state.read();
  if (!st || !st.agent) { console.error('Run setup first: node demo/uc03-recovery/setup.js'); process.exit(2); }
  const port = parseInt(process.env.UC03_PORT || c.PORT, 10);
  const { url } = await startServer(port, consoleConfig(st));
  console.log(`\nIFC recovery console (UC-03): ${url}`);
  console.log(`Low risk:  ${st.users.sophie.userName}  (no recent security change -> self-service e-mail link)`);
  console.log(`High risk: ${st.users.marc.userName}  (authenticator added at setup time -> assisted recovery; the code goes to a disposable mailbox)`);
  console.log('Read a customer mailbox:   node demo/uc03-recovery/mailbox.js <sophie|marc|lena>   (prints subjects; add --open to print the e-mail text)');
  console.log('Ctrl+C to stop.');
}

if (require.main === module) {
  main().catch((e) => { console.error('Failed to start:', e.message); process.exit(1); });
}
module.exports = { main };

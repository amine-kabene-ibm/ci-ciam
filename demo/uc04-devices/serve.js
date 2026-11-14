'use strict';
// UC-04 live demo: the "My trusted devices" portal on http://localhost:4041 (customer = ifc-demo-uc04-marie, signed in with her own token).
//   node demo/uc04-devices/serve.js
const { startServer } = require('../../stubs/device-portal/server');
const { createDeviceService } = require('../../stubs/device-portal/devices');
const c = require('./common');

async function main() {
  const st = c.state.read();
  if (!st || !st.console) { console.error('Run setup first: node demo/uc04-devices/setup.js'); process.exit(2); }
  const marie = st.users.marie;
  const svc = createDeviceService({ userName: marie.userName, password: marie.password, consoleClientId: st.console.clientId, consoleClientSecret: st.console.clientSecret });
  const port = parseInt(process.env.UC04_PORT || c.PORT, 10);
  const { url } = await startServer(port, svc, marie.userName);
  console.log(`\nIFC "My trusted devices" (UC-04): ${url}   customer: ${marie.userName}`);
  console.log('Register device: "Show QR code" (real phone, IBM Verify app) or "Simulate a phone scan". Push / Revoke from the table.');
  console.log('Ctrl+C to stop.');
}

if (require.main === module) {
  main().catch((e) => { console.error('Failed to start:', e.message); process.exit(1); });
}
module.exports = { main };

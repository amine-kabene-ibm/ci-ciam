'use strict';
// UC-01 live demo: Client 360 stub (4010) + registration portal (4011). The presenter registers with their own mailbox.
//   node demo/uc01-registration/serve.js
const { createClient } = require('../lib/verify');
const { startServer: startClient360 } = require('../../stubs/client360/server');
const { createPortal, listen } = require('../../stubs/registration-portal/server');
const c = require('./common');

async function main() {
  const st = c.state.read();
  if (!st || !st.registration) { console.error('Run setup first: node demo/uc01-registration/setup.js'); process.exit(2); }
  const c360 = await startClient360(parseInt(process.env.UC01_C360_PORT || c.PORTS.client360, 10));
  const port = parseInt(process.env.UC01_PORT || c.PORTS.portal, 10);
  const api = createClient(st.registration.clientId, st.registration.clientSecret).api; // least privilege, not the admin client
  const portal = createPortal({
    port, api, client360Url: c360.url, groupId: st.group.id, clientId: st.portal.clientId, clientSecret: st.portal.clientSecret,
    demoInbox: process.env.UC01_NO_TEST_INBOX ? undefined : { create: c.createInbox, waitForOtp: c.waitForOtp },
  });
  const { url } = await listen(portal, port);
  console.log(`\nIFC registration portal (UC-01): ${url}`);
  console.log(`Client 360 stand-in:             ${c360.url}   (policies AUTO-31877 / postal H2X 1Y4, HOME-40412 / M5V 2T6)`);
  console.log('Use your own mailbox for the real thing, or the "disposable test inbox" link on the page. Ctrl+C to stop.');
}

if (require.main === module) {
  main().catch((e) => { console.error('Failed to start:', e.message); process.exit(1); });
}
module.exports = { main };

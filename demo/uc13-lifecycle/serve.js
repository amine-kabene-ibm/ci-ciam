'use strict';
// UC-13 dashboard & ops-queue stub runner.
//   node demo/uc13-lifecycle/serve.js
const { startServer } = require('../../stubs/ops-queue/server');
const c = require('./common');

async function main() {
  const port = parseInt(process.env.OPS_QUEUE_PORT || c.OPS_QUEUE_PORT, 10);
  const server = await startServer(port);

  console.log(`
======================================================================
  IFC Broker Operations Queue & Lifecycle Hub (UC-13)
======================================================================
  Dashboard & Event Queue:  ${server.url}
  Webhook Endpoint:         ${server.url}/webhook
  REST Events API:          ${server.url}/api/events
  Health check:             ${server.url}/health
======================================================================
  Press Ctrl+C to stop the server.
`);
}

if (require.main === module) {
  main().catch((e) => {
    console.error('Failed to start server:', e.message);
    process.exit(1);
  });
}

module.exports = { main };

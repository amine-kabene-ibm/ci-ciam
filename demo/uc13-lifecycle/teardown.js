'use strict';
// UC-13 teardown: removes all tenant objects created for UC-13 (Broker Lifecycle & Immediate Revocation).
//   node demo/uc13-lifecycle/teardown.js
const fs = require('fs');
const { PREFIX } = require('../lib/verify');
const idem = require('../lib/idempotent');
const c = require('./common');

async function main() {
  console.log(`UC-13 Teardown (removing objects matching ${c.PREFIX}*)\n`);

  // 1. Users
  const users = await idem.deleteUsersByPrefix(c.PREFIX);
  console.log(`Deleted ${users.length} user(s):`, users.map((u) => u.userName).join(', ') || 'none');

  // 2. Applications (DCR clients)
  const apps = await idem.deleteApplicationsByPrefix(c.PREFIX);
  console.log(`Deleted ${apps.length} application(s):`, apps.map((a) => a.name).join(', ') || 'none');

  // 3. STS Clients
  const sts = await idem.deleteStsClientsByPrefix(c.PREFIX);
  console.log(`Deleted ${sts.length} STS client(s):`, sts.map((s) => s.clientName).join(', ') || 'none');

  // 4. Webhooks
  const webhooks = await idem.deleteWebhooksByPrefix(c.PREFIX);
  console.log(`Deleted ${webhooks.length} webhook(s):`, webhooks.map((w) => w.name).join(', ') || 'none');

  // 5. Clean local state file
  if (fs.existsSync(c.state.file)) {
    fs.unlinkSync(c.state.file);
    console.log(`Removed local state: ${c.state.file}`);
  }

  console.log('\nUC-13 Teardown complete.');
}

if (require.main === module) {
  main().catch((e) => {
    console.error('TEARDOWN FAILED:', e.message);
    process.exit(1);
  });
}

module.exports = { main };

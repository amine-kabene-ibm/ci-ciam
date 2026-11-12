'use strict';
// UC-14 teardown: removes every tenant object named ifc-demo-uc14-* and the local state file. Evidence (demo/out/uc14.json) is kept.
//   node demo/uc14-ciba/teardown.js
const idem = require('../lib/idempotent');
const c = require('./common');

async function main() {
  console.log(`UC-14 Teardown (removing objects named ${c.PREFIX}*)\n`);
  const users = await idem.deleteUsersByPrefix(c.PREFIX);
  console.log(`Deleted ${users.length} user(s):`, users.map((u) => u.userName).join(', ') || 'none');
  const apps = await idem.deleteApplicationsByPrefix(c.PREFIX);
  console.log(`Deleted ${apps.length} application(s):`, apps.map((a) => a.name).join(', ') || 'none');
  const clients = await idem.deleteApiClientsByPrefix(c.PREFIX);
  console.log(`Deleted ${clients.length} API client(s):`, clients.map((a) => a.clientName).join(', ') || 'none');
  c.state.remove();
  console.log('Removed local state file.\nUC-14 Teardown complete.');
}

if (require.main === module) {
  main().catch((e) => { console.error('TEARDOWN FAILED:', e.message); process.exit(1); });
}

module.exports = { main };

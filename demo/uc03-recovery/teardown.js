'use strict';
// UC-03 teardown: removes every tenant object named ifc-demo-uc03-*, RESTORES the tenant-wide "Forgot password" setting to its default (OFF),
// and removes the local state file. The customers' disposable mailboxes expire on their own. Evidence (demo/out/uc03.json) is kept.
//   node demo/uc03-recovery/teardown.js
const idem = require('../lib/idempotent');
const c = require('./common');

async function main() {
  console.log(`UC-03 Teardown (removing objects named ${c.PREFIX}*)\n`);
  const users = await idem.deleteUsersByPrefix(c.PREFIX);
  console.log(`Deleted ${users.length} user(s):`, users.map((u) => u.userName).join(', ') || 'none');
  const apps = await idem.deleteApplicationsByPrefix(c.PREFIX);
  console.log(`Deleted ${apps.length} application(s):`, apps.map((a) => a.name).join(', ') || 'none');
  const pols = await idem.deletePoliciesByPrefix(c.PREFIX);
  console.log(`Deleted ${pols.length} access policy(ies):`, pols.map((a) => a.name).join(', ') || 'none');
  const clients = await idem.deleteApiClientsByPrefix(c.PREFIX);
  console.log(`Deleted ${clients.length} API client(s):`, clients.map((a) => a.clientName).join(', ') || 'none');
  const sw = await idem.setHostedPasswordReset(false);
  console.log(`Tenant setting "Forgot password" (Cloud Directory identity source): ${sw.changed ? 'switched back OFF (default)' : 'already OFF'}`);
  c.state.remove();
  console.log('Removed local state file.\nUC-03 Teardown complete.');
}

if (require.main === module) {
  main().catch((e) => { console.error('TEARDOWN FAILED:', e.message); process.exit(1); });
}

module.exports = { main };

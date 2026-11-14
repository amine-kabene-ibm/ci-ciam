'use strict';
// UC-04 teardown: removes every tenant object named ifc-demo-uc04-* and the local state file. Evidence (demo/out/uc04.json) is kept.
//   node demo/uc04-devices/teardown.js
// Deleting a user also deletes that user's IBM Verify device registrations (idempotent.deleteUser).
const { api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const c = require('./common');

async function main() {
  console.log(`UC-04 Teardown (removing objects named ${c.PREFIX}*)\n`);
  const users = await idem.deleteUsersByPrefix(c.PREFIX);
  console.log(`Deleted ${users.length} user(s):`, users.map((u) => u.userName).join(', ') || 'none');
  const apps = await idem.deleteApplicationsByPrefix(c.PREFIX);
  console.log(`Deleted ${apps.length} application(s):`, apps.map((a) => a.name).join(', ') || 'none');
  const pols = await idem.deletePoliciesByPrefix(c.PREFIX);
  console.log(`Deleted ${pols.length} policy(ies):`, pols.map((a) => a.name).join(', ') || 'none');
  const clients = await idem.deleteApiClientsByPrefix(c.PREFIX);
  console.log(`Deleted ${clients.length} API client(s):`, clients.map((a) => a.clientName).join(', ') || 'none');
  const ac = ((await api('GET', '/v1.0/authenticators/clients')).data.clients || []).filter((x) => (x.name || '').startsWith(c.PREFIX));
  for (const x of ac) await api('DELETE', `/v1.0/authenticators/clients/${x.id}`, { quiet: true });
  console.log(`Deleted ${ac.length} authenticator client(s):`, ac.map((a) => a.name).join(', ') || 'none');
  c.state.remove();
  console.log('Removed local state file.\nUC-04 Teardown complete.');
}

if (require.main === module) {
  main().catch((e) => { console.error('TEARDOWN FAILED:', e.message); process.exit(1); });
}

module.exports = { main };

'use strict';
// UC-01 teardown: removes every tenant object named ifc-demo-uc01-* plus the customers who self-registered, and the local state file.
// Self-registered customers use their e-mail address as userName (not ifc-demo-*), so they are found as members of the ifc-demo-uc01-customers group.
//   node demo/uc01-registration/teardown.js          (evidence demo/out/uc01.json is kept)
const { api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const c = require('./common');

async function main() {
  console.log(`UC-01 Teardown (removing objects named ${c.PREFIX}* and the customers registered into ${c.GROUP})\n`);
  const g = await api('GET', '/v2.0/Groups', { query: { filter: `displayName eq "${c.GROUP}"` } });
  let members = 0;
  for (const grp of (g.data && g.data.Resources) || []) {
    const full = await api('GET', `/v2.0/Groups/${grp.id}`);
    for (const m of (full.data && full.data.members) || []) { await idem.deleteUser(m.value); members += 1; }
  }
  console.log(`Deleted ${members} self-registered customer(s) (group members)`);
  const users = await idem.deleteUsersByPrefix(c.PREFIX);
  console.log(`Deleted ${users.length} user(s) named ${c.PREFIX}*`);
  const groups = await idem.deleteGroupsByPrefix(c.PREFIX);
  console.log(`Deleted ${groups.length} group(s):`, groups.map((x) => x.displayName).join(', ') || 'none');
  const apps = await idem.deleteApplicationsByPrefix(c.PREFIX);
  console.log(`Deleted ${apps.length} application(s):`, apps.map((a) => a.name).join(', ') || 'none');
  const clients = await idem.deleteApiClientsByPrefix(c.PREFIX);
  console.log(`Deleted ${clients.length} API client(s):`, clients.map((a) => a.clientName).join(', ') || 'none');
  const attrs = await idem.deleteAttributesByPrefix(c.PREFIX);
  console.log(`Deleted ${attrs.length} custom attribute(s):`, attrs.map((a) => `${a.name}(${a.status})`).join(', ') || 'none');
  c.state.remove();
  console.log('Removed local state file.\nUC-01 Teardown complete.');
}

if (require.main === module) {
  main().catch((e) => { console.error('TEARDOWN FAILED:', e.message); process.exit(1); });
}

module.exports = { main };

'use strict';
// UC-03 demo helper: shows what a customer's mailbox received (the disposable mail.tm inbox created by setup.js).
//   node demo/uc03-recovery/mailbox.js marc            list subjects and arrival times
//   node demo/uc03-recovery/mailbox.js marc --open     also print the text of the newest message (links shortened, no passwords)
const uc01 = require('../uc01-registration/common');
const c = require('./common');

async function main() {
  const key = process.argv[2];
  const st = c.state.read();
  if (!st || !st.users[key]) { console.error(`Usage: node demo/uc03-recovery/mailbox.js <${Object.keys(c.CUSTOMERS).join('|')}> [--open]  (run setup first)`); process.exit(2); }
  const inbox = await uc01.inboxLogin(st.users[key].inbox);
  if (!inbox) { console.error('mailbox login failed'); process.exit(1); }
  const msgs = (await uc01.readMessages(inbox)) || [];
  console.log(`${st.users[key].userName} <${inbox.address}>: ${msgs.length} message(s)`);
  for (const m of msgs) console.log(`  ${new Date(m.at).toISOString().slice(11, 19)}  ${m.subject}`);
  if (process.argv.includes('--open') && msgs[0]) console.log('\n' + msgs[0].text.replace(/https?:\/\/\S+/g, '<link>').replace(/(temporary password is:)\s*\S+/i, '$1 ********').replace(/\n{3,}/g, '\n\n'));
}
main().catch((e) => { console.error(e.message); process.exit(1); });

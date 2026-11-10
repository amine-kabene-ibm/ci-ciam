'use strict';
// Interactive "caller" for the UC-06 voicebot. You play the policyholder; the bot talks to the real Verify tenant.
//   node demo/uc06-voice/caller.js
// Type a real code from the mailbox / IBM Verify app, or type  auto  to let this script act as Marie's authenticator app
// (it holds the TOTP secret created by setup.js). Voice is simulated by text. Set UC06_URL to use an already-running stub.
const readline = require('readline');
const axios = require('axios');
const stub = require('../../stubs/voicebot-ccaas/server');
const { state, customer, nextTotpCode } = require('./common');
const { sleep } = require('../lib/verify');

// Line queue instead of rl.question: also works when input is piped (scripted rehearsal) and not only on a TTY.
const rl = readline.createInterface({ input: process.stdin, terminal: false });
const queue = []; const waiters = [];
rl.on('line', (l) => (waiters.length ? waiters.shift()(l.trim()) : queue.push(l.trim())));
rl.on('close', () => { if (waiters.length) { console.log('\n(input ended: hanging up)'); process.exit(0); } });
const ask = (q) => { process.stdout.write(q); return new Promise((r) => (queue.length ? r(queue.shift()) : waiters.push(r))).then((a) => { if (!process.stdin.isTTY) console.log(a); return a; }); };
const MENU = [
  ['outstanding_bill', 'What is my outstanding bill amount?        (information query)'],
  ['renewal_date', 'When does my policy renew?                  (information query)'],
  ['proof_of_insurance', 'E-mail me a copy of my pink slip              (document request)'],
  ['storage', 'I would like to put my car in storage        (simple transaction)'],
  ['change_email', 'I need to change my e-mail address           (SENSITIVE)'],
  ['change_bank_account', 'I need to change my bank account              (SENSITIVE)'],
];

(async () => {
  if (!state.read()) { console.error('Run setup first: node demo/uc06-voice/setup.js'); process.exit(1); }
  let server = null; let base = process.env.UC06_URL;
  if (!base) { server = await stub.start(0); base = `http://127.0.0.1:${server.address().port}`; }
  const http = axios.create({ baseURL: base, validateStatus: () => true });
  const bot = (r) => { if (r.data && r.data.say) console.log(`\n  BOT:  ${r.data.say}`); return r; };
  const post = async (p, b) => bot(await http.post(p, b));
  const readCode = async (prompt) => { const a = await ask(prompt); return a.toLowerCase() === 'auto' ? (await nextTotpCode()).code : a; };

  console.log(`\n=== Intact Insurance voicebot (simulated call) ===   demo policy number: ${customer.policyNumber}`);
  await http.post('/reset');
  const callId = (await post('/call', {})).data.callId;

  // identify
  let id;
  for (;;) {
    id = await post('/identify', { callId, policyNumber: await ask('\n  YOU (policy number): ') });
    if (id.status === 200) break;
    if (id.status === 423) return finish();
  }
  // tier 1
  for (;;) {
    const m = await ask(`  YOU (1 = e-mail me a code${id.data.methods.includes('totp') ? ', 2 = authenticator-app code' : ''}): `);
    const method = m === '2' ? 'totp' : 'email_otp';
    const ch = await post('/challenge', { callId, method });
    if (ch.status !== 200) { if (ch.status === 423) return finish(); continue; }
    for (;;) {
      const v = await post('/verify', { callId, code: await readCode(method === 'totp' ? '  YOU (code, or "auto"): ' : '  YOU (digits after the dash): ') });
      if (v.status === 200) break;
      if (v.status === 423) return finish();
      if (v.status === 410) break; // expired: re-challenge
    }
    if ((await http.get(`/transcript/${callId}`)).data.verified) break;
  }
  // requests
  for (;;) {
    console.log('\n  What would you like to do?');
    MENU.forEach(([, label], i) => console.log(`    ${i + 1}. ${label}`));
    console.log('    0. Hang up');
    const pick = Number(await ask('  YOU: '));
    if (!pick) break;
    const [action] = MENU[pick - 1] || [];
    if (!action) continue;
    const body = { callId, action };
    if (action === 'change_email') body.newEmail = await ask('  YOU (new e-mail address): ');
    let r = await post('/transaction', body);
    if (r.status === 403 && r.data.error === 'step_up_required') {
      const opts = r.data.options;
      console.log(`  (step-up options available for this customer: ${opts.join(', ') || 'none'})`);
      if (!opts.length) { console.log('  No step-up factor available: the bot would transfer you to an agent.'); continue; }
      const choice = (await ask(`  YOU (${opts.map((o, i) => `${i + 1} = ${o}`).join(', ')}): `)) || '1';
      const method = opts[Number(choice) - 1] || opts[0];
      const su = await post('/stepup', { callId, method, action });
      if (method === 'push' && su.status === 202) {
        console.log('  >>> Approve the notification on the phone (waiting up to 2 min) <<<');
        let state2 = 'PENDING'; const t0 = Date.now();
        while (state2 === 'PENDING' && Date.now() - t0 < 125000) { await sleep(2000); state2 = (await http.get(`/stepup/status/${callId}`)).data.state; }
        console.log(`  Push result: ${state2}`);
      } else if (method === 'totp' && su.status === 200) {
        await post('/stepup/verify', { callId, code: await readCode('  YOU (NEW code from the app, or "auto"): ') });
      }
      r = await post('/transaction', body);
    }
    if (r.status === 200) console.log(`  [${r.data.kind}, tier ${r.data.tier}]  API result: ${JSON.stringify(r.data.result)}`);
  }
  await finish();

  async function finish() {
    const t = (await http.get(`/transcript/${callId}`)).data;
    console.log('\n=== Verify calls made by the CCaaS during this call ===');
    t.verifyCalls.forEach((c) => console.log(`  ${c.status}  ${c.method.padEnd(6)} ${c.path.replace(/[0-9a-f-]{36}/g, '{id}').padEnd(58)} ${String(c.ms).padStart(4)} ms  ${c.cid || ''}`));
    rl.close(); if (server) server.close(); process.exit(0);
  }
})().catch((e) => { console.error(e); process.exit(2); });

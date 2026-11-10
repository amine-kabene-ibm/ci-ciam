'use strict';
// The voice leg of UC-07, for the presenter. You play the customer who has just tapped "Speak with a Voicebot".
//   node demo/uc07-handoff/voice.js --app-login   terminal-only: this script signs Marie in to the "mobile app" (password grant),
//                                                 then hands the call off. No browser, no OTP.
//   node demo/uc07-handoff/voice.js               browser path: continue the call the demo app just handed off
//                                                 (needs: node demo/uc07-handoff/serve.js running, and the tap in the browser)
// Type  auto  where a code is asked to let the script act as the authenticator app. Voice is simulated by text.
const readline = require('readline');
const axios = require('axios');
const stub = require('../../stubs/voicebot-ccaas/server');
const c = require('./common');

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
  const st = c.state.read();
  if (!st) { console.error('Run setup first: node demo/uc07-handoff/setup.js'); process.exit(1); }
  const appLogin = process.argv.includes('--app-login');
  let server = null; let base = process.env.UC07_URL || 'http://127.0.0.1:4030';
  if (appLogin) { server = await stub.start(0, c.ccaasApi(st), c.handoffConfig(st)); base = `http://127.0.0.1:${server.address().port}`; }
  const http = axios.create({ baseURL: base, validateStatus: () => true });
  const bot = (r) => { if (r.data && r.data.say) console.log(`\n  BOT:  ${r.data.say}`); return r; };
  const post = async (p, b) => bot(await http.post(p, b));

  console.log('\n=== Intact Insurance voicebot (simulated call, handed off from the app) ===');
  let callId;
  if (appLogin) {
    const l = await c.appLogin(st);
    if (!l.accessToken) { console.error(`App sign-in failed: HTTP ${l.status}`); process.exit(1); }
    console.log(`\n  [APP]  Marie signed in to the Intact app (methods: ${JSON.stringify(l.amr)}). She taps "Speak with a Voicebot" under Help.`);
    const h = await post('/handoff', { accessToken: l.accessToken });
    if (!h.data.handedOff) return finish(null);
    callId = h.data.callId;
  } else {
    const latest = await http.get('/handoff/latest');
    if (latest.status !== 200) { console.error('No handed-off call yet. Tap "Speak with a Voicebot" in the app (http://localhost:3000/app/call-us), or use --app-login.'); process.exit(1); }
    callId = latest.data.callId;
    const a = (await http.get(`/agent/${callId}`)).data;
    console.log(`\n  Agent screen-pop: ${a.caller && a.caller.name} (${a.caller && a.caller.policyNumber}) - ${a.authentication.status} by ${a.authentication.by}`);
    console.log("  BOT:  Hello, I can see you are signed in to the Intact app, so I do not need to ask you any security questions. How can I help you today?");
  }
  const readCode = async (prompt) => { const a = await ask(prompt); return a.toLowerCase() === 'auto' ? (await c.player.next()).code : a; };

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
    if (r.status === 401 && r.data.error === 'app_session_ended') { console.log('  (the app session is gone: the bot would now ask for a code, as in UC-06)'); continue; }
    if (r.status === 403 && r.data.error === 'step_up_required') {
      const opts = r.data.options;
      console.log(`  (step-up options for this customer: ${opts.join(', ') || 'none'})`);
      if (!opts.length) { console.log('  No step-up factor available: the bot would transfer you to an agent.'); continue; }
      const method = opts.length === 1 ? opts[0] : opts[Number((await ask(`  YOU (${opts.map((o, i) => `${i + 1} = ${o}`).join(', ')}): `)) || '1') - 1] || opts[0];
      const su = await post('/stepup', { callId, method, action });
      if (method === 'totp' && su.status === 200) await post('/stepup/verify', { callId, code: await readCode('  YOU (NEW code from the app, or "auto"): ') });
      if (method === 'push' && su.status === 202) {
        console.log('  >>> Approve the notification on the phone (waiting up to 2 min) <<<');
        let s = 'PENDING'; const t0 = Date.now();
        while (s === 'PENDING' && Date.now() - t0 < 125000) { await new Promise((x) => setTimeout(x, 2000)); s = (await http.get(`/stepup/status/${callId}`)).data.state; }
        console.log(`  Push result: ${s}`);
      }
      r = await post('/transaction', body);
    }
    if (r.status === 200) console.log(`  [${r.data.kind}, tier ${r.data.tier}]  API result: ${JSON.stringify(r.data.result)}`);
  }
  await finish(callId);

  async function finish(id) {
    if (id) {
      const t = (await http.get(`/transcript/${id}`)).data;
      console.log('\n=== Verify calls made by the CCaaS during this call ===');
      t.verifyCalls.forEach((x) => console.log(`  ${x.status}  ${x.method.padEnd(6)} ${x.path.replace(/[0-9a-f-]{36}/g, '{id}').padEnd(40)} ${x.op.padEnd(52)} ${String(x.ms).padStart(4)} ms  ${x.cid || ''}`));
    }
    rl.close(); if (server) server.close(); process.exit(0);
  }
})().catch((e) => { console.error(e.message || e); process.exit(2); });

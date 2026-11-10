'use strict';
// UC-06 verification: checks the tenant state, runs the scenarios, inspects the evidence file.
//   node demo/uc06-voice/verify.js
// Result per check: PASS, FAIL, or HUMAN (cannot be proven without a person/phone; never counted as a pass).
// Exit code 1 only if a FAIL exists.
const fs = require('fs');
const { spawnSync } = require('child_process');
const path = require('path');
const { api, createClient } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { CCAAS_CLIENT, CCAAS_ENTITLEMENTS, state, customer } = require('./common');

const rows = [];
const add = (status, title, detail = '') => { rows.push({ status, title, detail }); console.log(`${status.padEnd(5)} ${title}${detail ? '  -- ' + detail : ''}`); };

(async () => {
  console.log('UC-06 verification\n');
  const st = state.read();
  if (!st) { add('FAIL', 'setup state present (demo/out/uc06.state.json)', 'run: node demo/uc06-voice/setup.js'); process.exit(1); }

  // --- tenant state ---
  const user = await idem.findUser(customer.userName);
  add(user ? 'PASS' : 'FAIL', `user ${customer.userName} exists on the tenant`, user ? `id ${user.id}, active=${user.active}` : '');
  const cc = await idem.findApiClient(CCAAS_CLIENT);
  const sameEnt = cc && JSON.stringify([...cc.entitlements].sort()) === JSON.stringify([...CCAAS_ENTITLEMENTS].sort());
  add(sameEnt ? 'PASS' : 'FAIL', `API client ${CCAAS_CLIENT} exists with exactly ${CCAAS_ENTITLEMENTS.length} entitlements`, cc ? `${cc.entitlements.length} found` : 'missing');
  if (user) {
    const t = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${user.id}"` } });
    add(t.status === 200 && t.data.total === 1 ? 'PASS' : 'FAIL', 'TOTP enrolment exists for the customer', `total=${t.data && t.data.total}`);
  }
  try {
    const ccaas = createClient(st.ccaas.clientId, st.ccaas.clientSecret).api;
    const r = await ccaas('GET', '/v2.0/Users', { query: { filter: `userName eq "${customer.userName}"`, attributes: 'id' }, quiet: true });
    add(r.status === 200 && r.data.totalResults === 1 ? 'PASS' : 'FAIL', 'CCaaS client can look the customer up (SCIM)', `HTTP ${r.status}`);
  } catch (e) { add('FAIL', 'CCaaS client can authenticate (client_credentials)', e.message); }

  // --- scenarios ---
  console.log('\nRunning scenarios (demo/uc06-voice/run.js) ...');
  const run = spawnSync('node', [path.join(__dirname, 'run.js')], { encoding: 'utf8', timeout: 240000 });
  const lines = (run.stdout || '').split('\n');
  const fails = lines.filter((l) => /^\s+FAIL\s/.test(l));
  const summary = lines.find((l) => /checks passed/.test(l)) || 'no summary';
  add(run.status === 0 && !fails.length ? 'PASS' : 'FAIL', 'scenario run A-G', summary.trim());
  fails.forEach((l) => console.log('      ' + l.trim()));

  // --- evidence ---
  const evFile = path.join(__dirname, '..', 'out', 'uc06.json');
  let ev = null;
  try { ev = JSON.parse(fs.readFileSync(evFile, 'utf8')); } catch (e) { /* none */ }
  add(ev && ev.total > 0 && ev.passed === ev.total ? 'PASS' : 'FAIL', 'evidence file demo/out/uc06.json written', ev ? `${ev.passed}/${ev.total}` : 'missing');
  if (ev) {
    const raw = fs.readFileSync(evFile, 'utf8');
    const secrets = [st.ccaas.clientSecret, st.totp.secret, process.env.API_SECRET].filter(Boolean);
    add(secrets.some((s) => raw.includes(s)) ? 'FAIL' : 'PASS', 'evidence contains no secrets');
    const verifyCalls = ev.steps.filter((s) => s.verifyCalls).flatMap((s) => s.verifyCalls);
    const withCid = verifyCalls.filter((c) => c.cid).length;
    add(verifyCalls.length && withCid === verifyCalls.length ? 'PASS' : 'FAIL', 'every Verify call in the evidence has an x-correlation-id', `${withCid}/${verifyCalls.length}`);
    const ops = new Set(verifyCalls.map((c) => c.op));
    ['SCIM lookup', 'TOTP attempt (tier 1)', 'TOTP attempt (step-up)', 'email OTP create', 'email OTP attempt'].forEach((o) => add(ops.has(o) ? 'PASS' : 'FAIL', `Verify operation exercised: ${o}`));
  }

  // --- things only a human can prove ---
  if (user) {
    const a = await api('GET', '/v1.0/authenticators', { query: { search: `owner="${user.id}"` } });
    const n = (a.data && a.data.total) || 0;
    const pushStep = ev && ev.steps.find((s) => s.title === 'D: push approval');
    if (pushStep && pushStep.pass) add('PASS', 'push step-up approved on a real phone', `${pushStep.seconds} s`);
    else add('HUMAN', 'push step-up approved on a real phone', n ? 'phone registered: run `node demo/uc06-voice/run.js --push`' : 'no phone registered: run `node demo/uc06-voice/enroll-phone.js`');
  }
  add('HUMAN', 'e-mail OTP read from the mailbox and accepted', 'OTP is sent for real in scenario E; entering it needs `node demo/uc06-voice/caller.js` and your mailbox');
  add('HUMAN', 'passkey step-up (option 3 in IFC wording)', 'not built: needs a browser WebAuthn ceremony and an HTTPS origin (see UC-02)');

  const f = rows.filter((r) => r.status === 'FAIL').length, h = rows.filter((r) => r.status === 'HUMAN').length;
  console.log(`\n${rows.filter((r) => r.status === 'PASS').length} PASS, ${f} FAIL, ${h} HUMAN`);
  process.exit(f ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });

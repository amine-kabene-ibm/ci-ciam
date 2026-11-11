'use strict';
// UC-12 verification: checks the tenant state, runs the scenarios, inspects the evidence file.
//   node demo/uc12-rebac/verify.js
// Result per check: PASS, FAIL, or HUMAN (cannot be proven without a person/browser/IBM enablement; never counted as a pass).
// Exit code 1 only if a FAIL exists.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { api, oauthClient } = require('../lib/verify');
const idem = require('../lib/idempotent');
const E = require('../../stubs/rules-engine/openfga');
const { createSource } = require('../../stubs/policy-api/source');
const c = require('./common');

const rows = [];
const add = (status, title, detail = '') => { rows.push({ status, title, detail }); console.log(`${status.padEnd(5)} ${title}${detail ? '  -- ' + detail : ''}`); };

(async () => {
  console.log('UC-12 verification\n');
  const st = c.state.read();
  if (!st || !st.users) { add('FAIL', 'setup state present (demo/out/uc12.state.json)', 'run: node demo/uc12-rebac/setup.js'); process.exit(1); }

  // --- engine binary ---
  const bin = await E.ensureBinary();
  add(bin.version === E.VERSION ? 'PASS' : 'FAIL', `OpenFGA binary v${E.VERSION} is present and runs`, bin.downloaded ? 'downloaded now, sha256 verified' : 'already there');

  // --- source stub, offline ---
  const s = createSource(); const subOf = (k) => `S_${k}`;
  const t = s.desiredTuples(subOf);
  add(t.length === 18 && new Set(t.map((x) => `${x.user}|${x.relation}|${x.object}`)).size === 18 ? 'PASS' : 'FAIL', 'source-system stub yields 18 distinct relationships for the seed data (5 people, 2 brokerages, 4 clients, 6 policies; Zoe has none)', `${t.length}`);
  s.moveBroker('anna', 'BRG-B');
  add(s.desiredTuples(subOf).some((x) => x.user === 'user:S_anna' && x.object === 'brokerage:BRG-B') && !s.desiredTuples(subOf).some((x) => x.user === 'user:S_anna' && x.object === 'brokerage:BRG-A') ? 'PASS' : 'FAIL', 'a broker move rewrites the membership tuple (old gone, new present)');

  // --- tenant state ---
  const names = Object.keys(createSource().brokers);
  const found = await Promise.all(names.map((k) => idem.findUser(c.userNameOf(k))));
  add(found.every(Boolean) ? 'PASS' : 'FAIL', `${names.length} tenant users ifc-demo-uc12-* exist`, `${found.filter(Boolean).length} found`);
  const ids = found.every(Boolean) && found.every((u, i) => u.id === st.users[names[i]].id);
  add(ids ? 'PASS' : 'FAIL', 'user ids on the tenant match the state file');
  const m = await idem.findApiClient(c.SYNC_CLIENT);
  add(m && JSON.stringify([...m.entitlements].sort()) === JSON.stringify([...c.SYNC_ENTITLEMENTS].sort()) ? 'PASS' : 'FAIL', `API client ${c.SYNC_CLIENT} exists with exactly ${c.SYNC_ENTITLEMENTS.length} entitlements (${c.SYNC_ENTITLEMENTS.join(', ')})`);
  const sts = await idem.findStsClient(c.GATEWAY_STS);
  add(sts ? 'PASS' : 'FAIL', `STS client ${c.GATEWAY_STS} exists (gateway introspection identity)`);
  const app = (await idem.listApplications()).find((a) => a.name === c.LOGIN_APP);
  const ad = app && await api('GET', app._links.self.href);
  const oc = ad && ad.status === 200 ? ad.data.providers.oidc.properties : null;
  add(oc && String(oc.grantTypes.ropc) === 'true' && String(oc.sendAllKnownUserAttributes) === 'true' ? 'PASS' : 'FAIL', `application ${c.LOGIN_APP} exists with the password grant and sendAllKnownUserAttributes`);
  const ro = oauthClient(st.login.clientId, st.login.clientSecret);
  const sign = await ro.passwordGrant(c.userNameOf('zoe'), st.users.zoe.password);
  add(sign.status === 200 ? 'PASS' : 'FAIL', 'a live broker can sign in against the tenant (password grant, Zoe)', `HTTP ${sign.status}`);

  // --- scenarios ---
  console.log('\nRunning scenarios (demo/uc12-rebac/run.js) ...');
  const run = spawnSync('node', [path.join(__dirname, 'run.js')], { encoding: 'utf8', timeout: 265000 });
  const lines = (run.stdout || '').split('\n');
  const fails = lines.filter((l) => /^\s+FAIL\s/.test(l));
  const summary = lines.find((l) => /checks passed/.test(l)) || `no summary (exit ${run.status}) ${(run.stderr || '').slice(0, 200)}`;
  add(run.status === 0 && !fails.length ? 'PASS' : 'FAIL', 'scenario run A-J (graph sync, inherited access, reassign, leave, deactivate, oracle cross-check, limits, scale; real tenant)', summary.trim());
  fails.forEach((l) => console.log('      ' + l.trim()));

  // --- evidence ---
  const evFile = path.join(__dirname, '..', 'out', 'uc12.json');
  let ev = null;
  try { ev = JSON.parse(fs.readFileSync(evFile, 'utf8')); } catch (e) { /* none */ }
  add(ev && ev.total > 0 && ev.passed === ev.total ? 'PASS' : 'FAIL', 'evidence file demo/out/uc12.json written', ev ? `${ev.passed}/${ev.total}` : 'missing');
  if (ev) {
    const raw = fs.readFileSync(evFile, 'utf8');
    const secrets = [...Object.values(st.users).map((u) => u.password), process.env.API_SECRET, st.sync.clientSecret, st.gateway.secret, st.login.clientSecret, st.login.registrationToken].filter(Boolean);
    const leaked = secrets.some((x) => raw.includes(x)) || /eyJ[A-Za-z0-9_-]{20,}\./.test(raw) || /Bearer [A-Za-z0-9._-]{20,}/.test(raw);
    add(leaked ? 'FAIL' : 'PASS', 'evidence contains no passwords, client secrets, JWTs or bearer tokens');
    const scen = new Set(ev.steps.map((x) => x.title[0]));
    add('ABCDEFGHIJ'.split('').every((x) => scen.has(x)) ? 'PASS' : 'FAIL', 'evidence covers scenarios A to J', [...scen].join(''));
    const dec = ev.steps.find((x) => /every decision above is in the gateway log/.test(x.title));
    add(dec && dec.pass && dec.sample && dec.sample.length ? 'PASS' : 'FAIL', 'the audit trail (who, action, policy, allow/deny, reason, check ms) is in the evidence');
  }

  // --- the tenant must be back in the seed state after the run, and nothing else may be left ---
  const left = [];
  for (const k of names) {
    const u = await idem.findUser(c.userNameOf(k));
    const full = (await api('GET', `/v2.0/Users/${u.id}`)).data;
    const want = createSource().brokers[k].brokerage || '';
    if (!full.active || ((full[c.ENT] || {}).department || '') !== want) left.push(k);
  }
  add(left.length === 0 ? 'PASS' : 'FAIL', 'the run leaves the directory in the seed state (all users active, department = seed brokerage)', left.length ? left.join(',') : '');
  const stray = await new Promise((r) => require('net').connect(c.GATEWAY_PORT, '127.0.0.1').on('connect', () => r(true)).on('error', () => r(false)));
  const strayFga = await E.isUp(`http://127.0.0.1:${c.FGA_PORT}`);
  add(!stray && !strayFga ? 'PASS' : 'FAIL', 'the run stopped its own gateway (:4170) and engine (:4171): no stray process');

  // --- things only a human / IBM can prove ---
  add('HUMAN', 'what the audience sees in a real browser at http://127.0.0.1:4170 (console) and in the terminal', 'the scripted run proves the API and the decisions, not the pixels; see demo/uc12-rebac/README.md');
  add('HUMAN', 'the PDF capability "IdP calls an external IFC rules engine DURING TOKEN MINTING to write claims into the token"', 'not possible on this tenant: attribute functions are built-ins only (no HTTP callout), scripted attribute sources are refused [LIVE]; external callouts are a paid-tier feature [DOCS]. IBM must confirm for IFC\'s contract tier');
  add('HUMAN', 'IFC\'s real relationship model and its source system (brokerage, broker, client, policy, other roles such as assistants, delegates, MGAs)', 'the model here is the PDF\'s hierarchy plus a manager role; IFC must provide theirs');
  add('HUMAN', 'engine choice and sizing at IFC volume', 'OpenFGA is open source and runs in memory here; IFC may use their own rules engine or a managed service. 8,120 relationships tested, not their real count');

  const f = rows.filter((r) => r.status === 'FAIL').length, h = rows.filter((r) => r.status === 'HUMAN').length;
  console.log(`\n${rows.filter((r) => r.status === 'PASS').length} PASS, ${f} FAIL, ${h} HUMAN`);
  process.exit(f ? 1 : 0);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

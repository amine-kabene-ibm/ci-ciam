'use strict';
// UC-07 verification: checks the tenant state, runs the scenarios, checks the app route, inspects the evidence file.
//   node demo/uc07-handoff/verify.js
// Result per check: PASS, FAIL, or HUMAN (cannot be proven without a person/browser; never counted as a pass).
// Exit code 1 only if a FAIL exists.
const fs = require('fs');
const path = require('path');
const http = require('http');
const { spawnSync } = require('child_process');
const express = require('express');
const axios = require('axios');
const { api, createClient, oauthClient } = require('../lib/verify');
const idem = require('../lib/idempotent');
const stub = require('../../stubs/voicebot-ccaas/server');
const c = require('./common');

const rows = [];
const add = (status, title, detail = '') => { rows.push({ status, title, detail }); console.log(`${status.padEnd(5)} ${title}${detail ? '  -- ' + detail : ''}`); };

(async () => {
  console.log('UC-07 verification\n');
  const st = c.state.read();
  if (!st) { add('FAIL', 'setup state present (demo/out/uc07.state.json)', 'run: node demo/uc07-handoff/setup.js'); process.exit(1); }

  // --- tenant state ---
  const user = await idem.findUser(c.USER_NAME);
  add(user && user.active ? 'PASS' : 'FAIL', `user ${c.USER_NAME} exists and is active`, user ? `id ${user.id}` : 'missing');
  const t = user && await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${user.id}"` } });
  add(t && t.status === 200 && t.data.total === 1 ? 'PASS' : 'FAIL', 'TOTP enrolment exists for the customer (step-up factor)');
  const cc = await idem.findApiClient(c.CCAAS_CLIENT);
  const sameEnt = cc && JSON.stringify([...cc.entitlements].sort()) === JSON.stringify([...c.CCAAS_ENTITLEMENTS].sort());
  add(sameEnt ? 'PASS' : 'FAIL', `API client ${c.CCAAS_CLIENT} has exactly ${c.CCAAS_ENTITLEMENTS.length} entitlements`, cc ? `${cc.entitlements.length} found` : 'missing');
  const sts = await idem.findStsClient(c.STS_CLIENT);
  add(sts && sts.enabled && sts.tokenExchangeSettings.subjectTokenTypes.length ? 'PASS' : 'FAIL', `STS client ${c.STS_CLIENT} enabled with token exchange`, sts ? sts.clientId : 'missing');
  const app = (await idem.listApplications()).find((x) => x.name === c.APP_CLIENT);
  add(app ? 'PASS' : 'FAIL', `application ${c.APP_CLIENT} registered`);
  try {
    const r = await createClient(st.ccaas.clientId, st.ccaas.clientSecret).api('GET', `/v2.0/Users/${user.id}`, { query: { attributes: 'id' }, quiet: true });
    add(r.status === 200 ? 'PASS' : 'FAIL', 'CCaaS API client can read the customer by id (SCIM)', `HTTP ${r.status}`);
  } catch (e) { add('FAIL', 'CCaaS API client authenticates (client_credentials)', e.message); }

  // --- scenarios ---
  console.log('\nRunning scenarios (demo/uc07-handoff/run.js) ...');
  const run = spawnSync('node', [path.join(__dirname, 'run.js')], { encoding: 'utf8', timeout: 240000 });
  const lines = (run.stdout || '').split('\n');
  const fails = lines.filter((l) => /^\s+FAIL\s/.test(l));
  const summary = lines.find((l) => /checks passed/.test(l)) || `no summary (exit ${run.status}) ${(run.stderr || '').slice(0, 200)}`;
  add(run.status === 0 && !fails.length ? 'PASS' : 'FAIL', 'scenario run A-H', summary.trim());
  fails.forEach((l) => console.log('      ' + l.trim()));

  // --- the demo-app route + view, mounted for real with a stand-in session (no browser login) ---
  console.log('\nDemo-app route /app/call-us (routes/ifc-handoff.js + views/insurance/call-us.hbs) ...');
  const voicebot = await stub.start(0, c.ccaasApi(st), c.handoffConfig(st));
  const login = await c.appLogin(st);
  const web = express();
  web.set('views', path.join(__dirname, '..', '..', 'views')); web.set('view engine', 'hbs');
  web.use((req, res, next) => { req.session = { accessToken: login.accessToken }; next(); });
  process.env.UC07_VOICEBOT_URL = `http://127.0.0.1:${voicebot.address().port}`;
  web.use('/app/call-us', require('../../routes/ifc-handoff'));
  const webSrv = await new Promise((r) => { const s = http.createServer(web).listen(0, '127.0.0.1', () => r(s)); });
  const wb = axios.create({ baseURL: `http://127.0.0.1:${webSrv.address().port}`, validateStatus: () => true });
  const page = await wb.get('/app/call-us', { headers: { Accept: 'text/html' } });
  add(page.status === 200 && /Speak with a Voicebot/.test(page.data) ? 'PASS' : 'FAIL', 'Help page renders the "Speak with a Voicebot" button', `HTTP ${page.status}`);
  const tap = await wb.post('/app/call-us/handoff', null, { headers: { Accept: 'application/json' } });
  add(tap.status === 200 && tap.data.result && tap.data.result.handedOff === true ? 'PASS' : 'FAIL', 'button posts the session token; voicebot hands off', `HTTP ${tap.status}`);
  add(tap.data.agent && tap.data.agent.authentication.status === 'AUTHENTICATED' ? 'PASS' : 'FAIL', 'agent screen-pop shows AUTHENTICATED');
  add(!JSON.stringify(tap.data).includes(login.accessToken) ? 'PASS' : 'FAIL', 'the access token is not echoed back to the browser');
  const html = await wb.post('/app/call-us/handoff', null, { headers: { Accept: 'text/html' } });
  add(html.status === 200 && /Marie Tremblay/.test(html.data) && /AUTO-77120/.test(html.data) && !html.data.includes(login.accessToken) ? 'PASS' : 'FAIL', 'result page shows what the contact centre knows, without the token');
  process.env.UC07_VOICEBOT_URL = 'http://127.0.0.1:1';
  const down = await wb.post('/app/call-us/handoff', null, { headers: { Accept: 'application/json' } });
  add(down.status === 503 ? 'PASS' : 'FAIL', 'voicebot not running: the page says so (503) instead of crashing');
  await oauthClient(st.app.clientId, st.app.clientSecret).revoke(login.accessToken);
  webSrv.close(); voicebot.close();

  // --- evidence ---
  const evFile = path.join(__dirname, '..', 'out', 'uc07.json');
  let ev = null;
  try { ev = JSON.parse(fs.readFileSync(evFile, 'utf8')); } catch (e) { /* none */ }
  add(ev && ev.total > 0 && ev.passed === ev.total ? 'PASS' : 'FAIL', 'evidence file demo/out/uc07.json written', ev ? `${ev.passed}/${ev.total}` : 'missing');
  if (ev) {
    const raw = fs.readFileSync(evFile, 'utf8');
    const secrets = [st.ccaas.clientSecret, st.totp.secret, st.sts.secret, st.app.clientSecret, st.user.password, st.app.registrationToken, process.env.API_SECRET].filter(Boolean);
    const leaked = secrets.some((s) => raw.includes(s)) || /eyJ[A-Za-z0-9_-]{20,}\./.test(raw);
    add(leaked ? 'FAIL' : 'PASS', 'evidence contains no secrets and no JWTs');
    const vcalls = ev.steps.filter((s) => s.verifyCalls).flatMap((s) => s.verifyCalls);
    const withCid = vcalls.filter((x) => x.cid).length;
    add(vcalls.length && withCid === vcalls.length ? 'PASS' : 'FAIL', 'every Verify call in the evidence has an x-correlation-id', `${withCid}/${vcalls.length}`);
    const ops = new Set(vcalls.map((x) => x.op));
    ['introspect app token', 'token exchange (app token -> voice-channel token)', 'introspect voice-channel token', 'introspect app token (bridge check)', 'SCIM lookup by id (sub)'].forEach((o) => add(ops.has(o) ? 'PASS' : 'FAIL', `Verify operation exercised: ${o}`));
  }

  // --- things only a human can prove ---
  add('HUMAN', 'real browser sign-in to TrustMeInsurance, then tap "Speak with a Voicebot"', 'the scripted app uses the password grant; the browser path needs an interactive Verify login and was not executed, see README');
  add('HUMAN', 'push step-up for a sensitive request on a real phone', 'no phone registered (same blocker as UC-06): TOTP step-up is what is proven');
  add('HUMAN', 'real telephony / CCaaS vendor (Genesys, Amazon Connect, ...) carrying the token', 'the CCaaS is a stub; the Verify side of the contract is what is proven');

  const f = rows.filter((r) => r.status === 'FAIL').length, h = rows.filter((r) => r.status === 'HUMAN').length;
  console.log(`\n${rows.filter((r) => r.status === 'PASS').length} PASS, ${f} FAIL, ${h} HUMAN`);
  process.exit(f ? 1 : 0);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

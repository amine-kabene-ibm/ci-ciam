'use strict';
// UC-08 verification: checks the tenant state, runs the scenarios, inspects the evidence file.
//   node demo/uc08-sso/verify.js
// Result per check: PASS, FAIL, or HUMAN (cannot be proven without a person/browser/tunnel; never counted as a pass).
// Exit code 1 only if a FAIL exists.
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const c = require('./common');

const rows = [];
const add = (status, title, detail = '') => { rows.push({ status, title, detail }); console.log(`${status.padEnd(5)} ${title}${detail ? '  -- ' + detail : ''}`); };

(async () => {
  console.log('UC-08 verification\n');
  const st = c.state.read();
  if (!st || !st.apps) { add('FAIL', 'setup state present (demo/out/uc08.state.json)', 'run: node demo/uc08-sso/setup.js'); process.exit(1); }

  // --- tenant state ---
  const mode = st.mode || 'front';
  for (const [k, u] of Object.entries(c.USERS)) {
    const user = await idem.findUser(u.userName);
    add(user && user.active ? 'PASS' : 'FAIL', `user ${u.userName} exists and is active`, user ? `id ${user.id}` : 'missing');
    const g = await api('GET', `/v2.0/Groups/${st.groups[u.group === c.GROUP_BROKERS ? 'brokers' : 'consumers'].id}`);
    add(g.status === 200 && (g.data.members || []).some((m) => user && m.value === user.id) ? 'PASS' : 'FAIL', `${u.userName} is a member of ${u.group}`);
    if (u.totp && user) {
      const t = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${user.id}"` } });
      const e = ((t.data && t.data.totp) || [])[0];
      add(e && e.validated ? 'PASS' : 'FAIL', `${u.userName} has a validated TOTP enrolment (usable at login)`);
    }
  }
  const polIds = {};
  for (const [k, p] of Object.entries(c.POLICIES)) {
    const l = await api('GET', '/v5.0/policyvault/accesspolicy', { query: { search: `name="${p.name}"` } });
    const f = ((l.data && l.data.policies) || []).find((x) => x.name === p.name);
    const g = f && await api('GET', `/v5.0/policyvault/accesspolicy/${f.id}`);
    const r = g && g.status === 200 ? g.data.rules || [] : [];
    const ok = r.length === 2 && r[0].result.action === p.action && r[0].conditions[0].attributes[0].values[0] === c.GROUP_BROKERS && r[1].result.action === 'ACTION_ALLOW';
    polIds[k] = f && String(f.id);
    add(ok ? 'PASS' : 'FAIL', `policy ${p.name}: brokers ${p.action}, everyone else ACTION_ALLOW`);
  }
  const apps = await idem.listApplications();
  for (const a of c.APPS) {
    const x = apps.find((y) => y.name === a.name);
    const g = x && await api('GET', x._links.self.href);
    const oc = g && g.status === 200 ? g.data.providers.oidc.properties : null;
    const lc = c.logoutConfig(a, st);
    const ok = oc && oc.accessTokenExpiry === a.ttl && oc.additionalConfig.logoutOption === lc.logoutOption && oc.additionalConfig.logoutURI === lc.logoutURI
      && oc.additionalConfig.sessionRequired === true && g.data.authPolicy && String(g.data.authPolicy.id) === polIds[a.policy];
    add(ok ? 'PASS' : 'FAIL', `application ${a.name}: ${a.policy} policy, token ${a.ttl} s, logout=${lc.logoutOption} (session required)`);
  }
  const disc = await api('GET', '/oidc/endpoint/default/.well-known/openid-configuration', { noAuth: true, quiet: true });
  add(disc.status === 200 && disc.data.frontchannel_logout_supported && disc.data.backchannel_logout_supported && disc.data.end_session_endpoint ? 'PASS' : 'FAIL',
    'discovery advertises front-channel, back-channel logout and an end_session_endpoint');

  // --- scenarios ---
  console.log('\nRunning scenarios (demo/uc08-sso/run.js) ...');
  const run = spawnSync('node', [path.join(__dirname, 'run.js')], { encoding: 'utf8', timeout: 260000 });
  const lines = (run.stdout || '').split('\n');
  const fails = lines.filter((l) => /^\s+FAIL\s/.test(l));
  const summary = lines.find((l) => /checks passed/.test(l)) || `no summary (exit ${run.status}) ${(run.stderr || '').slice(0, 200)}`;
  add(run.status === 0 && !fails.length ? 'PASS' : 'FAIL', 'scenario run A-H (scripted browser, 3 relying parties, real tenant)', summary.trim());
  fails.forEach((l) => console.log('      ' + l.trim()));

  // --- evidence ---
  const evFile = path.join(__dirname, '..', 'out', 'uc08.json');
  let ev = null;
  try { ev = JSON.parse(fs.readFileSync(evFile, 'utf8')); } catch (e) { /* none */ }
  add(ev && ev.total > 0 && ev.passed === ev.total ? 'PASS' : 'FAIL', 'evidence file demo/out/uc08.json written', ev ? `${ev.passed}/${ev.total}` : 'missing');
  if (ev) {
    const raw = fs.readFileSync(evFile, 'utf8');
    const secrets = [st.users.broker.password, st.users.consumer.password, st.totp.secret, process.env.API_SECRET, ...Object.values(st.apps).flatMap((a) => [a.clientSecret, a.registrationToken])].filter(Boolean);
    const leaked = secrets.some((s) => raw.includes(s)) || /eyJ[A-Za-z0-9_-]{20,}\./.test(raw);
    add(leaked ? 'FAIL' : 'PASS', 'evidence contains no secrets and no JWTs');
  }

  // --- things only a human can prove ---
  add('HUMAN', 'SSO + global logout in a real browser (Chrome) across localhost:4001-4003', 'scripted browser proves the protocol; see demo/uc08-sso/README.md for the visual check');
  add('HUMAN', 'back-channel logout_token delivery to an RP', 'needs a public https URL (cloudflared/ngrok not installed): setup.js --backchannel https://<public>; mode now: ' + mode);
  add('HUMAN', 'idle / absolute session timeout per persona', 'no session-policy API exists on the tenant [LIVE]; configure in the admin console if IFC asks');

  const f = rows.filter((r) => r.status === 'FAIL').length, h = rows.filter((r) => r.status === 'HUMAN').length;
  console.log(`\n${rows.filter((r) => r.status === 'PASS').length} PASS, ${f} FAIL, ${h} HUMAN`);
  process.exit(f ? 1 : 0);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

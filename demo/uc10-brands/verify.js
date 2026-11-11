'use strict';
// UC-10 verification: checks the tenant state, runs the scenarios, inspects the evidence file.
//   node demo/uc10-brands/verify.js
// Result per check: PASS, FAIL, or HUMAN (cannot be proven without a person/browser/IBM enablement; never counted as a pass).
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
  console.log('UC-10 verification\n');
  const st = c.state.read();
  if (!st || !st.apps) { add('FAIL', 'setup state present (demo/out/uc10.state.json)', 'run: node demo/uc10-brands/setup.js'); process.exit(1); }

  // --- tenant state ---
  const uid = {};
  for (const [k, u] of Object.entries(c.USERS)) {
    const user = await idem.findUser(u.userName);
    uid[k] = user && user.id;
    add(user && user.active ? 'PASS' : 'FAIL', `user ${u.userName} exists and is active`, user ? `id ${user.id}` : 'missing');
    if (u.totp && user) {
      const t = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${user.id}"` } });
      const e = ((t.data && t.data.totp) || [])[0];
      add(e && e.validated ? 'PASS' : 'FAIL', `${u.userName} has a validated TOTP enrolment (Boréal's fallback factor)`);
    }
  }
  const polIds = {};
  for (const [k, p] of Object.entries(c.POLICIES)) {
    const l = await api('GET', '/v5.0/policyvault/accesspolicy', { query: { search: `name="${p.name}"` } });
    const f = ((l.data && l.data.policies) || []).find((x) => x.name === p.name);
    const g = f && await api('GET', `/v5.0/policyvault/accesspolicy/${f.id}`);
    const r = g && g.status === 200 ? g.data.rules || [] : [];
    polIds[k] = f && String(f.id);
    add(r.length === 1 && r[0].result.action === p.action ? 'PASS' : 'FAIL', `policy ${p.name}: ${p.action}`);
  }
  const apps = await idem.listApplications();
  for (const b of c.BRAND_LIST) {
    const x = apps.find((y) => y.name === b.appName);
    const g = x && await api('GET', x._links.self.href);
    const oc = g && g.status === 200 ? g.data.providers.oidc.properties : null;
    const owners = (g && g.data && g.data.owners) || [];
    const ok = oc && String(oc.grantTypes.authorizationCode) === 'true' && g.data.authPolicy && String(g.data.authPolicy.id) === polIds[b.policy];
    add(ok ? 'PASS' : 'FAIL', `application ${b.appName}: authorization-code client with its own ${b.policy} policy`);
    add(owners.length === 1 && owners[0].id === uid[b.adminUser] ? 'PASS' : 'FAIL', `application ${b.appName}: owned by ${b.adminUser} only (delegated admin)`);
    const ents = (await idem.listAppEntitlements(await idem.appIdOf(b.appName))).map((e) => e.assignee.userName).sort();
    const want = (b.key === 'aurora' ? [c.USERS.customer.userName, c.USERS.auroraOnly.userName] : [c.USERS.customer.userName]).sort();
    add(ents.join() === want.join() ? 'PASS' : 'FAIL', `application ${b.appName}: customers entitled = ${want.map((n) => n.replace(c.PREFIX + 'uc10-', '')).join(', ')}`);
  }

  // --- theme packages ---
  for (const b of c.BRAND_LIST) {
    const zip = path.join(__dirname, '..', 'out', 'themes', `${b.themeName}.zip`);
    const have = fs.existsSync(zip) && fs.statSync(zip).size > 100000;
    add(have ? 'PASS' : 'FAIL', `theme package for ${b.name} built (${have ? fs.statSync(zip).size + ' bytes' : 'missing'})`);
  }
  const th = await api('GET', '/v1.0/branding/themes', { quiet: true });
  const regd = ((th.data && th.data.themeRegistrations) || []).filter((x) => x.name.startsWith(c.PREFIX + 'uc10-')).length;
  add(regd === 0 ? 'PASS' : 'FAIL', 'no brand theme is registered on the tenant (branding is refused on the trial: 403 CSIAZ3060E), so none is claimed to be applied', `registered: ${regd}`);

  // --- scenarios ---
  console.log('\nRunning scenarios (demo/uc10-brands/run.js) ...');
  const run = spawnSync('node', [path.join(__dirname, 'run.js')], { encoding: 'utf8', timeout: 260000 });
  const lines = (run.stdout || '').split('\n');
  const fails = lines.filter((l) => /^\s+FAIL\s/.test(l));
  const summary = lines.find((l) => /checks passed/.test(l)) || `no summary (exit ${run.status}) ${(run.stderr || '').slice(0, 200)}`;
  add(run.status === 0 && !fails.length ? 'PASS' : 'FAIL', 'scenario run A-I (scripted browser, 2 brand portals, real tenant)', summary.trim());
  fails.forEach((l) => console.log('      ' + l.trim()));

  // --- evidence ---
  const evFile = path.join(__dirname, '..', 'out', 'uc10.json');
  let ev = null;
  try { ev = JSON.parse(fs.readFileSync(evFile, 'utf8')); } catch (e) { /* none */ }
  add(ev && ev.total > 0 && ev.passed === ev.total ? 'PASS' : 'FAIL', 'evidence file demo/out/uc10.json written', ev ? `${ev.passed}/${ev.total}` : 'missing');
  if (ev) {
    const raw = fs.readFileSync(evFile, 'utf8');
    const secrets = [...Object.values(st.users).map((u) => u.password), st.totp.secret, process.env.API_SECRET, st.console.clientSecret, st.console.registrationToken,
      ...Object.values(st.apps).flatMap((a) => [a.clientSecret, a.registrationToken])].filter(Boolean);
    const leaked = secrets.some((s) => raw.includes(s)) || /eyJ[A-Za-z0-9_-]{20,}\./.test(raw);
    add(leaked ? 'FAIL' : 'PASS', 'evidence contains no secrets and no JWTs');
  }

  // --- things only a human / IBM can prove ---
  add('HUMAN', 'what the audience sees in a real browser (Chrome) at aurora.localhost:4101 and boreal.localhost:4102', 'scripted browser proves the protocol, not the pixels; see demo/uc10-brands/README.md');
  add('HUMAN', 'passkey (FIDO2) at Boréal', 'needs a browser authenticator and a registered passkey; the TOTP fallback is proven');
  add('HUMAN', 'brand look (colours, logo, French and English strings, legal text, support link) on the Verify login pages', 'theme ZIPs are built; registering them is refused on this trial (403 CSIAZ3060E): IBM must enable branding');
  add('HUMAN', 'multiple custom IdP URLs (idp.brand1.com, idp.brand2.com)', 'a request for an unregistered Host is refused (400); custom domains are an IBM / sales configuration [DOCS]');
  add('HUMAN', 'per-brand sender domain for e-mails, per-brand user directory and per-brand admin partitioning of users', 'question for IBM (CSIAP3564E; SCIM directory is shared)');

  const f = rows.filter((r) => r.status === 'FAIL').length, h = rows.filter((r) => r.status === 'HUMAN').length;
  console.log(`\n${rows.filter((r) => r.status === 'PASS').length} PASS, ${f} FAIL, ${h} HUMAN`);
  process.exit(f ? 1 : 0);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

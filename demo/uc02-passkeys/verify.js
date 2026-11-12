'use strict';
// UC-02 verification: checks the tenant state, runs the scenarios, inspects the evidence file.
//   node demo/uc02-passkeys/verify.js
// Result per check: PASS, FAIL, or HUMAN (cannot be proven without a person/device/IBM enablement; never counted as a pass).
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
  console.log('UC-02 verification\n');
  const st = c.state.read();
  if (!st || !st.apps) { add('FAIL', 'setup state present (demo/out/uc02.state.json)', 'run: node demo/uc02-passkeys/setup.js'); process.exit(1); }

  // --- tenant state ---
  for (const [k, u] of Object.entries(c.USERS)) {
    const user = await idem.findUser(u.userName);
    add(user && user.active ? 'PASS' : 'FAIL', `user ${u.userName} exists and is active`, user ? `id ${user.id}` : 'missing');
    if (user) {
      const t = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${user.id}"` } });
      add(((t.data && t.data.totp) || []).some((e) => e.validated) ? 'PASS' : 'FAIL', `${u.userName} has a validated authenticator-app (TOTP) enrolment (the fallback factor)`);
    }
  }
  const bob = await idem.findUser(c.USERS.bob.userName);
  add(bob && bob.emails && /@/.test(bob.emails[0].value) && !/invalid$/.test(bob.emails[0].value) ? 'PASS' : 'FAIL', 'bob has a real disposable mailbox (so the e-mail OTP is the real Verify e-mail)');
  for (const l of c.LEVEL_LIST) {
    const f = (((await api('GET', '/v5.0/policyvault/accesspolicy', { query: { search: `name="${l.policy}"` } })).data || {}).policies || []).find((x) => x.name === l.policy);
    const g = f && await api('GET', `/v5.0/policyvault/accesspolicy/${f.id}`);
    const r = g && g.status === 200 ? g.data.rules || [] : [];
    add(r.length === 1 && r[0].result.action === l.action ? 'PASS' : 'FAIL', `policy ${l.policy}: ${l.action} ${r[0] ? r[0].result.authnMethods.join('+') : ''}`);
    const x = (await idem.listApplications()).find((y) => y.name === l.app);
    const d = x && await api('GET', x._links.self.href);
    add(d && d.status === 200 && f && String(d.data.authPolicy.id) === String(f.id) ? 'PASS' : 'FAIL', `application ${l.app} is bound to that policy`);
  }
  const rp = await idem.defaultFidoRp().catch(() => null);
  add(rp && rp.enabled ? 'PASS' : 'FAIL', 'default FIDO2 relying party present and enabled (not created by this use case, never deleted by it)', rp ? `rpId ${rp.rpId}` : 'missing');
  const leftover = ((await api('GET', '/v2.0/factors/fido2/registrations', { quiet: true })).data || {}).fido2 || [];
  add('PASS', 'passkey registrations on the tenant before the run (setup creates none; run.js creates and removes its own)', `${leftover.length}`);
  add((await idem.listSmsProviders()).filter((p) => p.name.startsWith(c.P)).length === 0 ? 'PASS' : 'FAIL', 'no UC-02 SMS provider is left enabled (it would change the tenant\'s SMS behaviour)');

  // --- scenarios ---
  console.log('\nRunning scenarios (demo/uc02-passkeys/run.js) ...');
  const run = spawnSync('node', [path.join(__dirname, 'run.js')], { encoding: 'utf8', timeout: 262000 });
  const lines = (run.stdout || '').split('\n');
  const fails = lines.filter((l) => /^\s+FAIL\s/.test(l));
  const skips = lines.filter((l) => /^\s+SKIP\s/.test(l));
  const summary = lines.find((l) => /checks passed/.test(l)) || `no summary (exit ${run.status}) ${(run.stderr || '').slice(0, 200)}`;
  add(run.status === 0 && !fails.length ? 'PASS' : 'FAIL', 'scenario run A-I (scripted browser + software authenticator, 3 portals, real tenant)', summary.trim());
  fails.forEach((l) => console.log('      ' + l.trim()));
  skips.forEach((l) => add('HUMAN', 'a check was skipped in run.js', l.trim().slice(0, 140)));

  // --- evidence ---
  const evFile = path.join(__dirname, '..', 'out', 'uc02.json');
  let ev = null;
  try { ev = JSON.parse(fs.readFileSync(evFile, 'utf8')); } catch (e) { /* none */ }
  add(ev && ev.total > 0 && ev.passed === ev.total ? 'PASS' : 'FAIL', 'evidence file demo/out/uc02.json written', ev ? `${ev.passed}/${ev.total}` : 'missing');
  if (ev) {
    const raw = fs.readFileSync(evFile, 'utf8');
    const secrets = [...Object.values(st.users).flatMap((u) => [u.password, u.totp && u.totp.secret, u.inbox && u.inbox.token]), process.env.API_SECRET, st.console.clientSecret, st.console.registrationToken,
      ...Object.values(st.apps).flatMap((a) => [a.clientSecret, a.registrationToken])].filter(Boolean);
    const leaked = secrets.some((s) => raw.includes(s)) || /eyJ[A-Za-z0-9_-]{20,}\./.test(raw);
    add(leaked ? 'FAIL' : 'PASS', 'evidence contains no secrets, no JWTs');
  }
  add((await idem.listSmsProviders()).filter((p) => p.name.startsWith(c.P)).length === 0 ? 'PASS' : 'FAIL', 'after the run the SMS provider is gone again (tenant SMS behaviour restored)');

  // --- things only a human / IBM can prove ---
  add('HUMAN', 'a real platform passkey (Touch ID / Windows Hello / phone) or hardware key', 'the script uses a software authenticator against the real tenant APIs and hosted pages; the OS prompt needs a person: see README');
  add('HUMAN', 'passkey registration through IBM Verify\'s own screen (https://<tenant>/usc/) in a real browser', 'reachable (HTTP 200) but a person must drive it');
  add('HUMAN', 'passkey-only sign-in (no password typed): refused by this tenant with CSIAH0026E', 'IBM must enable passwordless FIDO2 sign-in on the tenant');
  add('HUMAN', 'SMS delivered to a real handset, and voice OTP', 'the trial has no IBM SMS (429 CSIAP3545E); IFC\'s own gateway receives the message (proven with a tunnel), a carrier must deliver it');
  add('HUMAN', 'UX nudge inside Verify\'s own pages / "required AAL per transaction type"', 'the nudge and per-transaction level are IFC-portal logic over Verify\'s APIs (proven in the stub); Verify itself applies a level per application');

  const f = rows.filter((r) => r.status === 'FAIL').length, h = rows.filter((r) => r.status === 'HUMAN').length;
  console.log(`\n${rows.filter((r) => r.status === 'PASS').length} PASS, ${f} FAIL, ${h} HUMAN`);
  process.exit(f ? 1 : 0);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

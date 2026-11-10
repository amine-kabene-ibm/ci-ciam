'use strict';
// UC-08 scenario runner: single sign-on across three apps and global logout, against the REAL Verify tenant.
//   node demo/uc08-sso/run.js
// A scripted browser (demo/uc08-sso/browser.js) plays the person; the three relying parties (stubs/rp-sso) run in this process on :4001-4003.
// Evidence (status codes, ids, timings; never secrets, tokens or codes): demo/out/uc08.json
const express = require('express');
const { evidence, api, oauthClient, sleep, send, BASE } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { createRp, listen } = require('../../stubs/rp-sso/server');
const { Browser } = require('./browser');
const c = require('./common');

const ev = evidence('uc08');
const results = [];
const note = (s) => console.log(`    ${s}`);

(async () => {
  const st = c.state.read();
  if (!st || !st.apps) { console.error('Run setup first: node demo/uc08-sso/setup.js'); process.exit(1); }
  const player = require('../lib/totp').totpPlayer(c.state);
  const totp = async () => (await player.next()).code;
  const broker = { username: c.USERS.broker.userName, password: st.users.broker.password, totp };
  const client = { username: c.USERS.consumer.userName, password: st.users.consumer.password, totp };

  const check = (scenario, title, pass, extra = {}) => {
    results.push({ scenario, title, pass });
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${title}`);
    ev.step(`${scenario}: ${title}`, { pass, ...extra });
  };

  // ---- the three relying parties, in process ------------------------------------------------------------------
  const rp = {}; const servers = [];
  for (const a of c.APPS) {
    rp[a.key] = createRp({
      key: a.key, title: a.title, colour: a.colour, port: a.port, clientId: st.apps[a.key].clientId, clientSecret: st.apps[a.key].clientSecret,
      requireGroup: a.requireGroup, introspectEachRequest: a.introspectEachRequest, registry: rp,
    });
    servers.push(await listen(rp[a.key]));
  }
  const A = c.appByKey;
  const url = (key, p = '/') => `${c.origin(A[key])}${p}`;
  const idp = (key) => oauthClient(st.apps[key].clientId, st.apps[key].clientSecret);
  const sess = (key) => [...rp[key].sessions.values()];
  const sidOf = (key, sub) => (sess(key).find((s) => !sub || s.sub === sub) || {}).idpSid;
  const signedIn = (page) => page.status === 200 && /<h2>Signed in<\/h2>/.test(page.html);
  const verifySessions = async (userId) => {
    const r = await api('GET', `/v1.0/auth/sessions/${userId}`);
    return { status: r.status, count: r.status === 200 ? ((r.data && r.data.sessions) || []).length : null, cid: r.cid };
  };
  // "Open the app": with a local session the app just shows it; otherwise the person clicks Sign in.
  const enter = async (br, key, creds) => {
    const home = await br.get(url(key));
    if (signedIn(home)) return { ...home, steps: [], ms: home.ms };
    return br.open(url(key, '/login'), creds);
  };
  const protectedCall = async (br, key) => {
    const r = await br.get(url(key, '/protected'));
    let body = null; try { body = JSON.parse(r.html); } catch (e) { /* keep null */ }
    return { status: r.status, body };
  };
  const globalLogout = (br, key) => br.open(url(key, '/logout'), {});

  // clean slate: no Verify session left over for the two personas
  for (const u of Object.values(st.users)) await api('DELETE', `/v1.0/auth/sessions/${u.id}`, { quiet: true });

  // ================================================================================================================
  console.log('\nA. Broker signs in once, then opens the other apps (SSO), each app with its own assurance');
  const brk = new Browser();
  const a1 = await enter(brk, 'portal', broker);
  note(`portal: Verify pages shown = ${JSON.stringify(a1.steps)}, ${a1.ms} ms`);
  check('A', 'first app (portal): Verify shows the login page and then the broker second factor (TOTP)', signedIn(a1) && a1.steps.join() === 'login,totp', { steps: a1.steps, ms: a1.ms });
  const brokerId = st.users.broker.id;
  const sidPortal = sidOf('portal', brokerId);
  const a2 = await enter(brk, 'claims', broker);
  note(`claims: Verify pages shown = ${JSON.stringify(a2.steps)}, ${a2.ms} ms`);
  check('A', 'second app (claims): NO login page and NO second factor, the user is signed in straight away (SSO)', signedIn(a2) && a2.steps.length === 0, { steps: a2.steps, ms: a2.ms });
  check('A', 'both apps hold the SAME Verify session id (sid): one authentication, one SSO session', !!sidPortal && sidPortal === sidOf('claims', brokerId), { sameSid: sidPortal === sidOf('claims', brokerId) });
  const a3 = await enter(brk, 'quote', broker);
  note(`quote (high assurance): Verify pages shown = ${JSON.stringify(a3.steps)}, ${a3.ms} ms`);
  check('A', 'third app (quote, policy "second factor at every sign-in"): the password is NOT asked again but the second factor IS asked again', signedIn(a3) && a3.steps.join() === 'totp', { steps: a3.steps, ms: a3.ms });
  check('A', 'all three apps still share one Verify session (the extra factor did not create a new one)', sidOf('quote', brokerId) === sidPortal, { sameSid: sidOf('quote', brokerId) === sidPortal });
  const s0 = await verifySessions(brokerId);
  check('A', 'Verify session list for the broker (GET /v1.0/auth/sessions/{id}) shows exactly one session', s0.status === 200 && s0.count === 1, s0);
  const amrP = sess('portal')[0].amr; const amrQ = sess('quote')[0].amr;
  check('A', 'ID token tells each app how the user authenticated (amr): password + totp', amrP.includes('password') && amrP.includes('totp') && amrQ.includes('totp'), { portalAmr: amrP, quoteAmr: amrQ });
  const p1 = [await protectedCall(brk, 'portal'), await protectedCall(brk, 'claims'), await protectedCall(brk, 'quote')];
  check('A', 'every app serves its protected resource to the same person (3 x HTTP 200)', p1.every((x) => x.status === 200), { statuses: p1.map((x) => x.status) });
  const lifetimes = Object.fromEntries(c.APPS.map((a) => [a.key, sess(a.key)[0].expiresIn]));
  note(`access token lifetime per app (s): ${JSON.stringify(lifetimes)}`);
  check('A', 'per-app token lifetimes are set from one management plane (portal 2 h, claims 15 min, quote 30 min)', Math.abs(lifetimes.portal - 7200) <= 5 && Math.abs(lifetimes.claims - 900) <= 5 && Math.abs(lifetimes.quote - 1800) <= 5, lifetimes);
  const quoteAgain = await brk.open(url('quote', '/login'), broker);
  check('A', 'quote again, same SSO session: the factor is demanded again (ACTION_MFA_ALWAYS); claims never asked twice (ACTION_MFA_PER_SESSION)', quoteAgain.steps.join() === 'totp' && signedIn(quoteAgain), { steps: quoteAgain.steps });

  // ================================================================================================================
  console.log('\nB. Each app enforces its own authorization from the claims (policyholder vs broker)');
  const cli = new Browser();
  const b1 = await enter(cli, 'portal', client);
  note(`portal as policyholder: Verify pages = ${JSON.stringify(b1.steps)}`);
  check('B', 'policyholder signs in with the password only: no second factor is required for this persona', signedIn(b1) && b1.steps.join() === 'login', { steps: b1.steps });
  check('B', 'policyholder ID token carries the persona group and a password-only amr', sess('portal').some((s) => s.sub === st.users.consumer.id && s.groups.includes(c.GROUP_CONSUMERS) && s.amr.join() === 'password'), {});
  const b2 = await enter(cli, 'claims', client);
  note(`claims as policyholder: HTTP ${b2.status}, Verify pages = ${JSON.stringify(b2.steps)}`);
  check('B', 'claims app: SSO works (no login page) but the app itself refuses a non-broker with HTTP 403', b2.status === 403 && b2.steps.length === 0 && /Access denied/.test(b2.html), { status: b2.status, steps: b2.steps });
  const b3 = await enter(cli, 'quote', client);
  check('B', 'quote app (high assurance): the policyholder is not a broker, so no second factor either', signedIn(b3) && b3.steps.length === 0, { steps: b3.steps });
  check('B', 'the refused app did not create a session for the policyholder', !sess('claims').some((s) => s.sub === st.users.consumer.id), {});
  await globalLogout(cli, 'portal');

  // ================================================================================================================
  console.log('\nC. Global logout from ONE app ends the session in ALL apps (front-channel)');
  const t0 = Date.now();
  const lo = await globalLogout(brk, 'portal');
  const loMs = Date.now() - t0;
  const iframes = (lo.logout && lo.logout.iframes) || [];
  note(`logout ran ${loMs} ms; Verify's logout page loaded ${iframes.length} iframes: ${iframes.map((i) => `${i.url.replace('http://localhost:', ':')} ${i.status}`).join(', ')}`);
  check('C', "Verify's logout page notifies each application (one iframe per app, plus the tenant's own SSO cookie)", iframes.length === 4 && iframes.filter((i) => i.url.startsWith('http://localhost:')).length === 3, { iframes });
  check('C', 'every notified app answered 200', iframes.length > 0 && iframes.every((i) => i.status === 200), { statuses: iframes.map((i) => i.status) });
  check('C', 'post-logout redirect returned to the app that started the logout, carrying state', /^http:\/\/localhost:4001\/\?state=/.test(lo.url), { url: lo.url.replace(/state=.*/, 'state=...') });
  const remaining = ['portal', 'claims', 'quote'].map((k) => sess(k).filter((s) => s.sub === brokerId).length);
  check('C', "the broker's sessions are gone from ALL three apps", remaining.every((n) => n === 0), { remaining });
  const p2 = [await protectedCall(brk, 'portal'), await protectedCall(brk, 'claims'), await protectedCall(brk, 'quote')];
  check('C', 'protected resources now refuse the broker in all three apps (3 x HTTP 401)', p2.every((x) => x.status === 401), { statuses: p2.map((x) => x.status) });
  const s1 = await verifySessions(brokerId);
  check('C', 'Verify session list for the broker is empty after logout', s1.status === 200 && s1.count === 0, s1);
  const c1 = await brk.open(url('claims', '/login'), {});
  check('C', 'opening any app again goes back to the Verify login page (the SSO session really ended)', c1.kind === 'login' && c1.steps.join() === 'login', { steps: c1.steps });
  ev.step('C: timing', { logoutMs: loMs, iframes });

  // ================================================================================================================
  console.log('\nD. Contrast: logging out of ONE app only (local logout) leaves the SSO session alive');
  const dBr = new Browser();
  const clientId = st.users.consumer.id;
  await enter(dBr, 'portal', client); await enter(dBr, 'quote', client);
  const before = await verifySessions(clientId);
  await dBr.get(url('portal', '/local-logout'));
  const after = await verifySessions(clientId);
  const quoteP = await protectedCall(dBr, 'quote');
  const reopen = await enter(dBr, 'portal', client);
  check('D', 'local logout: the other app keeps its session, the Verify session stays alive, and the app signs straight back in with no prompt',
    before.count === 1 && after.count === 1 && quoteP.status === 200 && signedIn(reopen) && reopen.steps.length === 0,
    { before: before.count, after: after.count, quoteStatus: quoteP.status, reopenSteps: reopen.steps });
  note('=> this is why "log out of this app" is not enough: the RP-initiated (global) logout in C is the pattern to use');
  await globalLogout(dBr, 'portal');

  // ================================================================================================================
  console.log('\nE. An administrator (or a SCIM offboarding) ends the session on the Verify side');
  const eBr = new Browser();
  await enter(eBr, 'portal', broker); await enter(eBr, 'claims', broker);
  const portalToken = sess('portal').find((s) => s.sub === brokerId).accessToken;
  const preAct = (await idp('portal').introspect(portalToken)).data.active;
  const t1 = Date.now();
  const kill = await api('DELETE', `/v1.0/auth/sessions/${brokerId}`);
  const postAct = await idp('portal').introspect(portalToken);
  const killMs = Date.now() - t1;
  check('E', 'DELETE /v1.0/auth/sessions/{userId} returns 204 and the Verify session list becomes empty', kill.status === 204 && (await verifySessions(brokerId)).count === 0, { status: kill.status, cid: kill.cid });
  check('E', 'the access token introspects active:true before and active:false immediately after', preAct === true && postAct.data.active === false, { before: preAct, after: postAct.data.active, ms: killMs });
  const pc = await protectedCall(eBr, 'claims'); const pp = await protectedCall(eBr, 'portal');
  check('E', 'claims app (asks Verify about the token on every request) cuts the user off at once: HTTP 401', pc.status === 401 && pc.body && pc.body.error === 'session_revoked_at_idp', { status: pc.status });
  note(`portal app (trusts its own session, never asks Verify): HTTP ${pp.status}`);
  check('E', 'portal app (local session only) keeps serving until told or its own session ends: HTTP 200. Honest gap that logout notifications or per-request introspection close', pp.status === 200, { status: pp.status });
  const e1 = await eBr.open(url('quote', '/login'), {});
  check('E', 'a NEW sign-in to any app needs credentials again: the Verify SSO session is gone', e1.kind === 'login', { steps: e1.steps });
  ev.step('E: timing', { adminKillAndIntrospectMs: killMs });
  await globalLogout(eBr, 'portal'); await api('DELETE', `/v1.0/auth/sessions/${brokerId}`, { quiet: true });

  // ================================================================================================================
  console.log('\nF. Silent check and forced re-authentication');
  const fBr = new Browser();
  const none0 = await fBr.get(url('portal', '/login?prompt=none'));
  check('F', 'prompt=none with no SSO session: the app is told login_required (HTTP 401), nothing is shown to the user', none0.status === 401 && /login_required/.test(none0.html), { status: none0.status });
  await enter(fBr, 'portal', client);
  const none1 = await fBr.get(url('quote', '/login?prompt=none'));
  check('F', 'prompt=none WITH an SSO session: the second app is signed in silently, no page shown', signedIn(none1) && none1.hops.length > 0, { hops: none1.hops.length });
  await sleep(2500);
  const fresh = await fBr.open(url('portal', '/login?max_age=1'), client);
  check('F', 'max_age=1 on an older session forces the user to authenticate again (freshness enforceable per request)', fresh.steps.includes('login') && signedIn(fresh), { steps: fresh.steps });
  await globalLogout(fBr, 'portal');

  // ================================================================================================================
  console.log('\nG. Back-channel logout: what can be proven without a public URL');
  const gBr = new Browser();
  await enter(gBr, 'portal', client);
  const victim = sess('portal').find((s) => s.sub === clientId);
  const post = (body) => send({ method: 'post', url: url('portal', '/backchannel-logout'), data: new URLSearchParams(body).toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, validateStatus: () => true });
  const g1 = await post({ logout_token: 'not.a.jwt' });
  check('G', 'back-channel endpoint rejects garbage (HTTP 400)', g1.status === 400, { status: g1.status });
  const g2 = await post({ logout_token: victim.idToken });
  check('G', 'a REAL signed Verify ID token is not accepted as a logout token (no logout event): HTTP 400, session survives', g2.status === 400 && sess('portal').some((s) => s.sub === clientId), { status: g2.status, error: g2.data && g2.data.error_description });
  const parts = victim.idToken.split('.');
  const forged = [parts[0], Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(parts[1], 'base64url')), sid: 'x' })).toString('base64url'), parts[2]].join('.');
  const g3 = await post({ logout_token: forged });
  check('G', 'a tampered token fails the signature check: HTTP 400', g3.status === 400 && /signature/.test((g3.data && g3.data.error_description) || ''), { status: g3.status, error: g3.data && g3.data.error_description });

  // Register a back-channel app by API, point it at an unreachable receiver, and log out through the portal.
  const tmpName = `${c.PREFIX}uc08-tmp-backchannel`;
  const catcher = express(); catcher.get('/callback', (q, s) => s.send('ok'));
  const catcherSrv = await new Promise((r) => { const s = catcher.listen(4009, () => r(s)); });
  const tmp = await idem.ensureDcrClient(tmpName, {
    redirect_uris: ['http://localhost:4009/callback'], grant_types: ['authorization_code'], response_types: ['code'], all_users_entitled: true, enforce_pkce: false,
    consent_action: 'never_prompt', scope: 'openid', backchannel_logout_uri: 'https://unreachable.ifc-demo.invalid/bc', backchannel_logout_session_required: true,
  });
  const tmpApp = (await idem.listApplications()).find((x) => x.name === tmpName);
  const tmpCfg = (await api('GET', tmpApp._links.self.href)).data.providers.oidc.properties.additionalConfig;
  check('G', 'dynamic registration with backchannel_logout_uri is accepted and stored as logoutOption=back_channel (session required)', tmpCfg.logoutOption === 'back_channel' && /unreachable/.test(tmpCfg.logoutURI) && tmpCfg.sessionRequired === true, { logoutOption: tmpCfg.logoutOption, sessionRequired: tmpCfg.sessionRequired });
  const tmpSignIn = await gBr.get(`${BASE}/v1.0/endpoint/default/authorize?${new URLSearchParams({ response_type: 'code', client_id: tmp.clientId, redirect_uri: 'http://localhost:4009/callback', scope: 'openid', state: 'tmp-state-123', nonce: 'tmp-nonce-123' })}`);
  const tL = Date.now();
  const lo2 = await globalLogout(gBr, 'portal');
  const gMs = Date.now() - tL;
  check('G', 'with that unreachable back-channel receiver in the session, logout still completes without hanging or erroring', tmpSignIn.status === 200 && /^http:\/\/localhost:4001\//.test(lo2.url) && gMs < 15000, { ms: gMs, tempAppSignIn: tmpSignIn.status });
  note(`logout with an unreachable back-channel receiver registered: ${gMs} ms`);
  note('Delivery of a real logout_token needs a public URL: NOT executed here ([HUMAN], see README).');
  catcherSrv.close();
  await idem.deleteApplicationsByPrefix(tmpName);

  // ================================================================================================================
  console.log('\nH. Session limits: what the tenant exposes');
  const probes = [];
  for (const p of ['/v1.0/session-policies', '/v1.0/sessionpolicies', '/v1.0/sessions', '/v1.0/config/session', '/v1.0/tenantsettings']) {
    const r = await api('GET', p, { quiet: true });
    probes.push({ path: p, status: r.status, body: JSON.stringify(r.data || '').slice(0, 60) });
  }
  check('H', 'no session-policy object in the API (every candidate path answers with the console login page): idle/absolute timeouts are NOT configurable by API', probes.every((x) => /"operation":"login"/.test(x.body)), { probed: probes });
  note('=> per-persona lifetimes here come from per-app token lifetimes (accessTokenExpiry) and per-app access policies, not from a session-policy object');

  servers.forEach((s) => s.close());
  for (const u of Object.values(st.users)) await api('DELETE', `/v1.0/auth/sessions/${u.id}`, { quiet: true });
  const failed = results.filter((r) => !r.pass);
  failed.forEach((r) => console.log(`  FAIL  ${r.scenario}: ${r.title}`));
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  console.log('evidence:', ev.save({ passed: results.length - failed.length, total: results.length, mode: st.mode }));
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error(e.stack || e.message || e); process.exit(2); });

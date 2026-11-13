'use strict';
// UC-03 test run (risk-aware account recovery, agent-assisted), against the live tenant. Takes about 8 minutes (Verify events lag 15 to 90 s).
//   node demo/uc03-recovery/run.js
// Scenarios:
//   A  objects, least privilege (agent client), hosted "Forgot password" switched on
//   B  risk rules on synthetic signals (pure logic: new geography cannot be produced from this laptop, so it is proven on data only)
//   C  risk-aware sign-in policy (ipAddress condition): same network -> no step-up, other network -> TOTP step-up
//   D  risk evaluation from the REAL Verify signals: low (Sophie), high (Marc: authenticator added minutes ago; Lena: attempts from a new device)
//   E  low risk, self-service: hosted Forgot password -> e-mailed link -> new password -> sessions end -> notification -> single use link
//   F  high risk, agent-assisted: verify the caller (e-mail code on file) -> reset -> sessions end -> temporary password e-mailed -> must change it
//   G  abuse cases: unknown user, request flood (rate limit), agent cannot redirect the code or change the account
//   H  audit trail from the Verify events API
const http = require('http');
const { api, oauthClient, createClient, evidence, sleep } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { totpPlayer } = require('../lib/totp');
const uc01 = require('../uc01-registration/common');
const { Browser } = require('../uc08-sso/browser');
const { createRecoveryConsole, assess, IBM_EXT } = require('../../stubs/recovery-console/recovery');
const { consoleConfig } = require('./config');
const { riskPolicyRules, SIGNIN_POLICY, POLICY_DESC, SIGNIN_APP } = require('./setup');
const hosted = require('./hosted');
const c = require('./common');

const ev = evidence('uc03');
const results = [];
const PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const check = (scenario, title, pass, extra = {}) => { results.push({ scenario, title, pass }); console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${scenario}  ${title}`); ev.step(`${scenario}: ${title}`, { pass, ...extra }); };
const info = (scenario, title, extra = {}) => { console.log(`  INFO  ${scenario}  ${title}`); ev.step(`${scenario}: ${title}`, { info: true, ...extra }); };
const head = (t) => console.log(`\n${t}`);
const upd = (fn) => { const s = c.state.read(); fn(s); c.state.write(s); };
const secs = (ms) => Math.round(ms / 100) / 10;

async function main() {
  const st = c.state.read();
  if (!st || !st.agent || !st.users) { console.error('State missing. Run: node demo/uc03-recovery/setup.js'); process.exit(2); }
  const t0 = Date.now();
  const cfg = { ...consoleConfig(st) };
  const rc = createRecoveryConsole(cfg);
  const portal = oauthClient(st.portal.clientId, st.portal.clientSecret);
  const U = st.users;
  const inboxes = {};
  for (const k of Object.keys(U)) { inboxes[k] = await uc01.inboxLogin(U[k].inbox); if (!inboxes[k]) throw new Error(`mailbox of ${k} unreachable`); }
  const seen = { sophie: new Set(), marc: new Set(), lena: new Set() };
  // anything already in the inboxes is old news
  for (const k of Object.keys(seen)) for (const m of (await uc01.readMessages(inboxes[k])) || []) seen[k].add(m.id);
  const player = totpPlayer(c.state);
  // the customer portal's callback (the sign-in redirects there); serve.js has its own, so a busy port is fine
  const cb = http.createServer((q, r) => r.end('ok'));
  await new Promise((res) => { cb.once('error', res); cb.listen(c.PORT, '127.0.0.1', res); });

  console.log('UC-03 Run: risk-aware account recovery, agent-assisted');

  // ===== A. objects and least privilege =====
  head('A. Objects and least privilege');
  const ac = (await api('GET', `/v1.0/apiclients/${st.agent.id}`)).data;
  check('A', 'the recovery console runs on its own API client with 6 measured entitlements, not the admin client', JSON.stringify([...ac.entitlements].sort()) === JSON.stringify([...c.AGENT_ENTITLEMENTS].sort()), { entitlements: ac.entitlements });
  check('A', 'hosted "Forgot password" is switched ON on the tenant (identity-source property passwordResetEnabled)', await idem.hostedPasswordResetEnabled());
  const agentApi = createClient(st.agent.clientId, st.agent.clientSecret).api;
  const denied = [
    ['list API clients', await agentApi('GET', '/v1.0/apiclients', { quiet: true })],
    ['delete a user', await agentApi('DELETE', `/v2.0/Users/${U.sophie.id}`, { quiet: true })],
    ['create a user', await agentApi('POST', '/v2.0/Users', { body: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: `${c.PREFIX}nope` }, quiet: true })],
    ['change the e-mail on file', await agentApi('PATCH', `/v2.0/Users/${U.sophie.id}`, { body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'emails', value: [{ type: 'work', value: 'attacker@example.com' }] }] }, quiet: true })],
    ['deactivate a user', await agentApi('PATCH', `/v2.0/Users/${U.sophie.id}`, { body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'active', value: false }] }, quiet: true })],
    ['read access policies', await agentApi('GET', '/v5.0/policyvault/accesspolicy', { quiet: true })],
  ];
  check('A', 'the console is refused outside its scope (403): ' + denied.map((d) => d[0]).join(', '), denied.every((d) => d[1].status === 403), { statuses: denied.map((d) => `${d[0]}=${d[1].status}`) });
  const after = (await api('GET', `/v2.0/Users/${U.sophie.id}`)).data;
  check('A', 'the refused e-mail change left the address on file untouched', after.emails[0].value === U.sophie.inbox.address);

  // Baseline: a successful sign-in from the customers' usual device (setup did one; this keeps it fresh for the 6 h history window)
  for (const k of Object.keys(U)) await c.signIn(st.portal, U[k].userName, U[k].password, c.KNOWN_UA);
  const tokSophie = (await c.signIn(st.portal, U.sophie.userName, U.sophie.password, c.KNOWN_UA)).data.access_token;
  check('A', 'Sophie holds a live session before the incident (access token active)', !!tokSophie && (await portal.introspect(tokSophie)).data.active === true);

  // The incident: Sophie locks herself out (6 wrong passwords, usual device); an attacker tries Lena from an unknown device
  for (let i = 0; i < 6; i++) await c.signIn(st.portal, U.sophie.userName, `Wrong!Pass${i}x`, c.KNOWN_UA);
  const lockedNow = (await api('GET', `/v2.0/Users/${U.sophie.id}`, { quiet: true })).data[IBM_EXT];
  check('A', 'Sophie is locked out after 6 wrong passwords (pwdAccountLockedTime set)', !!(lockedNow && lockedNow.pwdAccountLockedTime));
  const lockedLogin = await c.signIn(st.portal, U.sophie.userName, U.sophie.password, c.KNOWN_UA);
  check('A', 'while locked, even her CORRECT password is refused (CSIAQ0264E)', lockedLogin.status === 400 && /CSIAQ0264E/.test(lockedLogin.data.error_description || ''), { http: lockedLogin.status });
  for (let i = 0; i < 2; i++) await c.signIn(st.portal, U.lena.userName, `Wrong!Guess${i}x`, c.NEW_UA);
  const incidentAt = Date.now();

  // ===== B. risk rules on synthetic data =====
  head('B. Risk rules (synthetic signals: proves the logic, not the data source)');
  const now = Date.now(); const R = { recentFactorMs: 24 * 3600 * 1000 };
  const ok = (t, o) => ({ timeMs: now - t, result: 'success', device: 'UA-A', country: 'CAN', origin: '1.1.1.1', ...o });
  const at = (o) => ({ timeMs: now - 60000, result: 'failure', device: 'UA-A', country: 'CAN', origin: '1.1.1.1', ...o });
  const lvl = (s) => assess(s, R, now).level;
  check('B', 'usual device, usual country, no recent factor -> LOW (self-service)', lvl({ history: [ok(3600000), at()], attempts: [at()], factors: [] }) === 'low');
  check('B', 'authenticator added 10 minutes ago -> HIGH (recent factor change)', assess({ history: [ok(3600000)], attempts: [], factors: [{ createdMs: now - 600000 }] }, R, now).reasons.some((r) => r.code === 'RECENT_FACTOR_CHANGE'));
  check('B', 'authenticator added 3 days ago -> LOW', lvl({ history: [ok(3600000)], attempts: [], factors: [{ createdMs: now - 3 * 86400000 }] }) === 'low');
  check('B', 'attempt from a device never seen on a successful sign-in -> HIGH (new device)', assess({ history: [ok(3600000), at({ device: 'UA-NEW' })], attempts: [at({ device: 'UA-NEW' })], factors: [] }, R, now).reasons.some((r) => r.code === 'NEW_DEVICE'));
  check('B', 'attempt from a country never seen on a successful sign-in -> HIGH (new geography)', assess({ history: [ok(3600000), at({ country: 'FRA' })], attempts: [at({ country: 'FRA' })], factors: [] }, R, now).reasons.some((r) => r.code === 'NEW_GEOGRAPHY'));
  check('B', 'a new IP address alone is informational, not scored (mobile users change IPs)', lvl({ history: [ok(3600000), at({ origin: '9.9.9.9' })], attempts: [at({ origin: '9.9.9.9' })], factors: [] }) === 'low');
  const nb = assess({ history: [], attempts: [at({ device: 'UA-NEW' })], factors: [] }, R, now);
  check('B', 'no earlier successful sign-in: device and country cannot be judged -> LOW with an explicit NO_BASELINE note', nb.level === 'low' && nb.info.some((i) => i.code === 'NO_BASELINE'));

  // ===== C. risk-aware sign-in policy (ipAddress) =====
  head('C. Risk-aware sign-in policy: step-up to TOTP outside the usual network (real hosted sign-in)');
  const authz = `https://${new URL(rc.loginUrl()).host}/v1.0/endpoint/default/authorize?` + new URLSearchParams({ client_id: st.signin.clientId, response_type: 'code', redirect_uri: cfg.redirectUri, scope: 'openid', state: 'ifcdemo03state0002', nonce: 'ifcdemo03nonce0002' });
  const mkBrowser = () => { const b = new Browser(); b.headers = { 'User-Agent': c.KNOWN_UA }; return b; };
  const marcCreds = { username: U.marc.userName, password: U.marc.password, totp: async () => (await player.next()).code };
  const same = await mkBrowser().open(authz, marcCreds);
  check('C', 'from the usual network: password only, no step-up, authorization code issued', same.steps.join('>') === 'login' && /[?&]code=/.test(same.url), { steps: same.steps, ms: same.ms });
  const pol = await idem.ensurePolicy(SIGNIN_POLICY, POLICY_DESC, riskPolicyRules(['203.0.113.0/24']));
  await idem.updateApplication(SIGNIN_APP, (a) => { a.authPolicy = { id: pol.id }; });
  await sleep(4000);
  const stop = await mkBrowser().open(authz, { username: U.marc.userName, password: U.marc.password });
  check('C', 'from another network (policy range changed to 203.0.113.0/24): the sign-in stops at the TOTP page', stop.kind === 'totp', { steps: stop.steps, kind: stop.kind });
  const other = await mkBrowser().open(authz, marcCreds);
  check('C', 'with the TOTP code from his authenticator the step-up completes and the code is issued', other.steps.join('>') === 'login>totp' && /[?&]code=/.test(other.url), { steps: other.steps, ms: other.ms });
  const polBack = await idem.ensurePolicy(SIGNIN_POLICY, POLICY_DESC, riskPolicyRules(st.policy.usualNetwork));
  await idem.updateApplication(SIGNIN_APP, (a) => { a.authPolicy = { id: polBack.id }; });
  check('C', 'the policy is restored to the usual network', polBack.updated === true);
  info('C', 'geoLocation condition: accepted by the policy API but never changed a sign-in outcome in 40+ tests [LIVE: not proven]; the policy above uses ipAddress, which IS evaluated');
  info('C', 'X-Forwarded-For is ignored by Verify: the recorded origin stayed the real IP, so a "new country" cannot be produced from this laptop [LIVE]');

  // ===== D. risk evaluation from the REAL signals =====
  head('D. Risk evaluation from the real Verify signals (events lag 15 to 90 s: waiting for the incident to appear)');
  const waitFor = async (userName, pred, label, maxMs = 180000) => {
    const w0 = Date.now(); let s;
    while (Date.now() - w0 < maxMs) { s = await rc.signals(userName); if (!s.error && pred(s.signals)) return { s, lagMs: Date.now() - incidentAt }; await sleep(8000); }
    return { s, lagMs: null, timedOut: label };
  };
  const wl = await waitFor(U.lena.userName, (g) => g.attempts.filter((a) => a.device === c.NEW_UA).length >= 2 && g.history.some((h) => h.result === 'success'), 'lena');
  info('D', `Verify events for the incident became readable after ${wl.lagMs === null ? 'more than 180' : secs(wl.lagMs)} s`, { lagMs: wl.lagMs });
  const ws = await waitFor(U.sophie.userName, (g) => g.attempts.filter((a) => a.result === 'failure').length >= 6, 'sophie');

  const sophie = await rc.startRecovery(U.sophie.userName, { full: true });
  check('D', 'Sophie (locked out, usual device and country, no recent security change) -> LOW risk -> self-service', sophie.case.risk.level === 'low' && sophie.case.route === 'self-service', { reasons: sophie.case.risk.reasons, info: sophie.case.risk.info.map((i) => i.code), attempts: sophie.case.recentAttempts.length });
  check('D', 'the lock is shown to the agent as a fact, not as a risk', sophie.case.risk.info.some((i) => i.code === 'LOCKED') && sophie.case.locked === true);
  const marc = await rc.startRecovery(U.marc.userName, { full: true });
  check('D', 'Marc (authenticator added minutes ago, then a recovery request) -> HIGH risk -> assisted recovery', marc.case.risk.level === 'high' && marc.case.route === 'assisted' && marc.case.risk.reasons.some((r) => r.code === 'RECENT_FACTOR_CHANGE'), { reasons: marc.case.risk.reasons });
  const lena = await rc.startRecovery(U.lena.userName, { full: true });
  check('D', 'Lena (2 attempts from a device never seen on a successful sign-in) -> HIGH risk -> assisted recovery', lena.case.risk.level === 'high' && lena.case.risk.reasons.some((r) => r.code === 'NEW_DEVICE'), { reasons: lena.case.risk.reasons, recentAttempts: lena.case.recentAttempts.slice(0, 3).map((a) => ({ result: a.result, country: a.country })) });
  check('D', 'the customer is told only the route, never the reasons', !JSON.stringify(marc.public).match(/RECENT_FACTOR|factor|device|risk/i) && marc.public.route === 'assisted', { public: marc.public });
  const unk = await rc.startRecovery(`${c.PREFIX}nobody`);
  check('D', 'an unknown user name gets the SAME wording as a low-risk customer (no account enumeration)', unk.public.message === sophie.public.message && unk.public.route === 'self-service');
  check('D', 'the signals come from Verify: SCIM (lock, last login), factor list (created), events (device, IP, country)', sophie.case.recentAttempts.every((a) => a.origin && a.country) && ws.s && ws.s.signals.eventsRead > 0, { eventsRead: ws.s && ws.s.signals.eventsRead, country: sophie.case.recentAttempts[0] && sophie.case.recentAttempts[0].country });
  info('D', 'this is rule-based context (device, geography, recent factor change), NOT an AI risk score: Verify Adaptive Access is not enabled on this trial');

  // ===== E. low risk, self-service via the hosted Forgot password =====
  head('E. Low risk, self-service: hosted "Forgot password"');
  const e0 = Date.now();
  const rq = await hosted.requestReset(st.portal.clientId, cfg.redirectUri, U.sophie.userName);
  check('E', 'the sign-in page offers "Forgot password" and accepts the user name (CSIAH0323I)', rq.code === 'CSIAH0323I', { code: rq.code, ms: rq.ms, error: rq.error });
  const mail = await hosted.waitForMail(inboxes.sophie, /password reset information/i, { sinceMs: e0, seen: seen.sophie });
  check('E', 'the e-mail with the time-limited reset link arrives at the address on file', !!mail, { arrivedAfterMs: mail && mail.ms });
  const link = mail && hosted.resetLink(mail.msg);
  check('E', 'the link states its validity: 30 minutes', !!mail && /expires in 30 minutes/i.test(mail.msg.text));
  const opened = link ? await hosted.openLink(link) : { ok: false };
  check('E', 'opening the link shows the "set new password" page', opened.ok === true, { code: opened.code });
  const weak = opened.ok ? await hosted.setPassword(opened, 'short') : {};
  check('E', 'a weak password is refused by the password policy (CSIAH0315I "does not meet the password policy requirements")', weak.code === 'CSIAH0315I' && /does not meet/i.test(weak.message || ''), { code: weak.code, message: weak.message });
  const mism = opened.ok ? await hosted.setPassword(opened, c.newPassword(), c.newPassword()) : {};
  check('E', 'a mismatching confirmation is refused (CSIAH0331I)', mism.code === 'CSIAH0331I', { codes: mism.codes });
  const np = c.newPassword();
  const done = opened.ok ? await hosted.setPassword(opened, np) : {};
  check('E', 'a compliant new password is accepted: "The password is reset" (CSIAH0324I)', done.code === 'CSIAH0324I', { code: done.code });
  const e1 = Date.now();
  await sleep(2500);
  const old = await c.signIn(st.portal, U.sophie.userName, U.sophie.password, c.KNOWN_UA);
  check('E', 'the OLD password no longer works', old.status === 400, { http: old.status });
  const fresh = await c.signIn(st.portal, U.sophie.userName, np, c.KNOWN_UA);
  check('E', 'the NEW password signs in (and the reset cleared the lock)', fresh.status === 200, { http: fresh.status });
  check('E', 'her session from before the incident ended: the access token is now inactive', (await portal.introspect(tokSophie)).data.active === false);
  const lockAfter = (await api('GET', `/v2.0/Users/${U.sophie.id}`, { quiet: true })).data[IBM_EXT];
  check('E', 'the account is no longer locked', !(lockAfter && lockAfter.pwdAccountLockedTime));
  const note = await hosted.waitForMail(inboxes.sophie, /reset is complete|password.*(changed|reset)/i, { sinceMs: e1 - 5000, seen: seen.sophie, timeoutMs: 45000 });
  info('E', note ? `a notification e-mail "${note.msg.subject}" reached the address on file` : 'NO notification e-mail reached the address on file within 45 s after the reset, although the page says "A password change notification email is sent to the user" (CSIAH0324I). Not observed in 4 runs [LIVE: not proven]. The AGENT route does notify ("Password reset" e-mail). For self-service, IFC would send its own notification (webhook/event) [INFER]', { notificationArrived: !!note });
  const reuse = link ? await hosted.openLink(link) : {};
  check('E', 'the link is single use: opening it again is refused (CSIAH0328E)', reuse.ok === false && reuse.code === 'CSIAH0328E', { code: reuse.code });
  upd((s) => { s.users.sophie.password = np; });
  U.sophie.password = np;
  ev.step('E: timings', { requestToMailMs: mail && mail.ms, resetToNotificationMs: note && note.ms, totalMs: e1 - e0 });

  // ===== F. high risk, agent-assisted =====
  head('F. High risk, agent-assisted recovery (Marc)');
  const cid = marc.caseId;
  const opts = rc.verificationOptions(cid);
  check('F', 'the agent may verify Marc by e-mail code ON FILE; his new authenticator is NOT accepted as proof (enrolled inside the recent-change window)', opts.options.some((o) => o.method === 'emailotp' && o.trusted) && opts.options.some((o) => o.method === 'totp' && o.trusted === false) && !opts.options.some((o) => o.method === 'totp' && o.trusted === true), { options: opts.options });
  const early = await rc.resetAndEndSessions(cid);
  check('F', 'before the caller is verified the reset is refused (403)', early.httpStatus === 403, { error: early.error });
  const tokMarc = (await c.signIn(st.portal, U.marc.userName, U.marc.password, c.KNOWN_UA)).data.access_token;
  check('F', 'Marc (or the attacker holding his session) has a live access token', !!tokMarc && (await portal.introspect(tokMarc)).data.active === true);
  const f0 = Date.now();
  let vs = await rc.startVerification(cid);
  if (vs.verification) check('F', 'Verify e-mails a one-time code to the address on file (201)', true, { sentMs: vs.verification.sentMs });
  let conf;
  if (vs.verification) {
    const wrong = await rc.confirmVerification(cid, '000000');
    check('F', 'a wrong code is refused and the caller stays unverified', wrong.httpStatus === 401, { verifyMessageId: wrong.verifyMessageId });
    const still = await rc.resetAndEndSessions(cid);
    check('F', 'still refused after a wrong code (403)', still.httpStatus === 403);
    const otp = await uc01.waitForOtp(inboxes.marc, { correlation: vs.verification.correlation, timeoutMs: 120000 });
    check('F', 'the code read from the real e-mail carries the correlation shown to the caller', !!otp, { arrivedAfterMs: otp && otp.ms });
    conf = await rc.confirmVerification(cid, otp.code);
    ev.step('F: timings (otp)', { otpMailMs: otp && otp.ms });
    check('F', 'with the right code the caller is VERIFIED', !!conf.verified, { attempts: conf.verified && conf.verified.attempts });
  } else {
    // The trial's e-mail OTP quota is used up (CSIAP3523E). Run the REST of the scenario with the other verification route, so nothing else hides behind it.
    info('F', `FALLBACK: the e-mail one-time code could not be sent (${vs.error}). The rest of F runs with the authenticator-code route and a test-only "trusted after 1 s" threshold. The e-mail route is therefore NOT proven in this run [LIVE]`, { fallback: true });
    cfg.trustedFactorMs = 1000;
    vs = await rc.startVerification(cid, 'totp');
    check('F-fallback', 'verification by authenticator code started (test threshold 1 s)', !!vs.verification, { error: vs.error });
    const wrong = await rc.confirmVerification(cid, player.wrong());
    check('F-fallback', 'a wrong authenticator code is refused and the caller stays unverified', wrong.httpStatus === 401, { verifyMessageId: wrong.verifyMessageId });
    const still = await rc.resetAndEndSessions(cid);
    check('F-fallback', 'still refused after a wrong code (403)', still.httpStatus === 403);
    conf = await rc.confirmVerification(cid, (await player.next()).code);
    check('F-fallback', 'with the right authenticator code the caller is VERIFIED', !!conf.verified);
  }
  const rs = await rc.resetAndEndSessions(cid);
  check('F', 'the agent resets the password: Verify answers 204 and generates the temporary password', !!rs.reset && rs.reset.httpStatus === 204, { cid: rs.reset && rs.reset.cid });
  check('F', 'every active session of the customer is ended (DELETE sessions -> 204)', !!rs.reset && rs.reset.sessionsHttpStatus === 204, { cid: rs.reset && rs.reset.sessionsCid });
  await sleep(2500);
  check('F', 'Marc\'s access token from before is now inactive', (await portal.introspect(tokMarc)).data.active === false);
  const oldM = await c.signIn(st.portal, U.marc.userName, U.marc.password, c.KNOWN_UA);
  check('F', 'his old password no longer works', oldM.status === 400, { http: oldM.status });
  const tmpMail = await hosted.waitForMail(inboxes.marc, /^Password reset$/i, { sinceMs: f0, seen: seen.marc });
  check('F', 'the notification "Password reset" reaches the registered address, with a temporary password the agent never saw', !!tmpMail && /temporary password/i.test(tmpMail.msg.text), { arrivedAfterMs: tmpMail && tmpMail.ms });
  const temp = tmpMail && (tmpMail.msg.text.match(/temporary password is:\s*(\S+)/i) || [])[1];
  const tl = temp ? await c.signIn(st.portal, U.marc.userName, temp, c.KNOWN_UA) : { status: 0, data: {} };
  check('F', 'the temporary password cannot be used as is: he must choose a new one at sign-in (CSIAQ0267E)', tl.status === 400 && /CSIAQ0267E/.test(tl.data.error_description || ''), { http: tl.status });
  const again = await rc.resetAndEndSessions(cid);
  check('F', 'one verification = one reset: a second reset needs a new verification (403)', again.httpStatus === 403, { error: again.error });
  // the scripted customer picks a new password so later runs can sign in
  const npM = c.newPassword();
  await api('PATCH', `/v2.0/Users/${U.marc.id}`, { headers: { usershouldnotneedtoresetpassword: 'true' }, quiet: true, body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'password', value: npM }] } });
  upd((s) => { s.users.marc.password = npM; }); U.marc.password = npM;
  ev.step('F: timings', { resetToMailMs: tmpMail && tmpMail.ms });

  // The reset alone does NOT end an already-issued token: this is why the console always adds the session call [LIVE 2026-11-12]
  head('F2. Why the console also ends sessions (Lena)');
  const tokLena = (await c.signIn(st.portal, U.lena.userName, U.lena.password, c.KNOWN_UA)).data.access_token;
  const bare = await agentApi('PATCH', `/v2.0/Users/${U.lena.id}/passwordResetter`, { quiet: true, body: { schemas: [PATCH_OP], operations: [{ op: 'replace', value: { password: 'auto-generate', 'urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification': { notifyType: 'NONE', notifyPassword: false, notifyManager: false } } }] } });
  await sleep(2500);
  const stillActive = (await portal.introspect(tokLena)).data.active;
  const sess = await agentApi('DELETE', `/v1.0/auth/sessions/${U.lena.id}`, { quiet: true });
  await sleep(2500);
  const nowActive = (await portal.introspect(tokLena)).data.active;
  check('F2', 'reset alone: Verify answers 204 but an already-issued access token STAYS ACTIVE', bare.status === 204 && stillActive === true, { reset: bare.status, tokenActive: stillActive });
  check('F2', 'DELETE sessions then ends it (204, token inactive)', sess.status === 204 && nowActive === false, { sessions: sess.status, tokenActive: nowActive });
  const npL = c.newPassword();
  await api('PATCH', `/v2.0/Users/${U.lena.id}`, { headers: { usershouldnotneedtoresetpassword: 'true' }, quiet: true, body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'password', value: npL }] } });
  upd((s) => { s.users.lena.password = npL; }); U.lena.password = npL;

  // ===== G. abuse cases =====
  head('G. Abuse cases');
  const unkReset = await hosted.requestReset(st.portal.clientId, cfg.redirectUri, `${c.PREFIX}nobody`);
  check('G', 'Forgot password for an unknown user answers exactly like a known one (CSIAH0323I): no account enumeration', unkReset.code === 'CSIAH0323I', { code: unkReset.code });
  const flood = [];
  for (let i = 0; i < 5; i++) { const r = await hosted.requestReset(st.portal.clientId, cfg.redirectUri, U.lena.userName); flood.push(r.code); if (r.code === 'CSIAH0327I') break; }
  check('G', 'a flood of reset requests for one user is stopped by Verify (CSIAH0327I, "maximum number of reset password attempts")', flood.includes('CSIAH0327I'), { sequence: flood });
  await sleep(10000);
  const floodMails = ((await uc01.readMessages(inboxes.lena)) || []).filter((m) => /password reset information/i.test(m.subject) && !seen.lena.has(m.id)).length;
  check('G', 'the victim received at most 2 e-mails from the flood before the limit', floodMails <= 2, { mailsReceived: floodMails });
  info('G', 'finding: the hosted "Forgot password" link stays reachable for HIGH-risk customers too (Lena above got the same CSIAH0323I). Verify does not consult IFC\'s risk route: IFC\'s portal must not offer the hosted link to a high-risk case [INFER]');

  // ===== H. audit =====
  head('H. Audit trail (Verify events API; lag 15 to 90 s)');
  let aud = null; const h0 = Date.now();
  const wanted = (a) => a && a.rows.some((r) => r.kind === 'agent password reset' && (r.by || '').length) && a.rows.some((r) => /password/i.test(r.cause || '') && r.type !== 'authentication');
  while (Date.now() - h0 < 200000) {
    const [am, as] = [await rc.audit({ userName: U.marc.userName, sinceMs: t0 - 5000 }), await rc.audit({ userName: U.sophie.userName, sinceMs: t0 - 5000 })];
    aud = { marc: am.audit, sophie: as.audit };
    if (aud.marc && wanted(aud.marc) && aud.sophie && aud.sophie.rows.some((r) => /password/i.test(r.cause || '') && r.type !== 'authentication')) break;
    await sleep(10000);
  }
  const kinds = (a) => [...new Set((a ? a.rows : []).map((r) => r.kind))];
  const agentRow = aud.marc && aud.marc.rows.find((r) => r.kind === 'agent password reset');
  check('H', 'Verify logged the agent\'s reset: who (the console API client), what, when, from which IP and country', !!agentRow && !!agentRow.by && !!agentRow.origin && !!agentRow.country, { row: agentRow });
  check('H', 'Verify logged the sign-in attempts of Marc with device, IP and country (the same facts the risk rules use)', aud.marc.rows.some((r) => r.type === 'authentication' && r.device && r.origin && r.country));
  const sRow = aud.sophie.rows.find((r) => /password/i.test(r.cause || '') && r.type !== 'authentication');
  check('H', 'Verify logged the self-service reset of Sophie (hosted flow)', !!sRow, { kinds: kinds(aud.sophie), row: sRow });
  check('H', 'Verify logged Sophie\'s 6 failed sign-ins and the lock', aud.sophie.rows.filter((r) => r.type === 'authentication' && r.result === 'failure').length >= 6, { failures: aud.sophie.rows.filter((r) => r.type === 'authentication' && r.result === 'failure').length });
  const cases = rc.allCases();
  check('H', 'the console\'s case log records each step (started, code sent, verified, reset + sessions ended)', cases.some((x) => x.userName === U.marc.userName && ['recovery started', 'caller verified', 'password reset + sessions ended'].every((s) => x.steps.some((y) => y.step === s))), { cases: cases.map((x) => ({ id: x.id, user: x.userName, risk: x.risk.level, steps: x.steps.map((s) => s.step) })) });
  ev.step('H: event kinds seen', { marc: kinds(aud.marc), sophie: kinds(aud.sophie), auditWaitSec: secs(Date.now() - h0) });
  info('H', 'IFC fraud analytics: the events API is pull-only here; real-time streaming to a SIEM needs a webhook or the Event Streams integration [DOCS], not exercised in this use case');

  cb.close();
  const failed = results.filter((r) => !r.pass).length; const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed} checks passed, ${failed} failed  (${Math.round((Date.now() - t0) / 1000)} s)`);
  ev.save({ total: results.length, passed, failed, results, durationSec: Math.round((Date.now() - t0) / 1000) });
  console.log(`Evidence written: ${ev.file}`);
  process.exit(failed ? 1 : 0);
}

if (require.main === module) {
  main().catch((e) => {
    console.error('RUN FAILED:', e.message || e); if (process.env.DEBUG) console.error(e.stack);
    const passed = results.filter((r) => r.pass).length;
    ev.save({ total: results.length, passed, failed: results.length - passed + 1, results, aborted: String(e.message || e) });
    process.exit(2);
  });
}
module.exports = { main };

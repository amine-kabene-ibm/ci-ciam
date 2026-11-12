'use strict';
// UC-02 scenario runner: passkeys first, OTP / authenticator-app fallback, assurance levels, own SMS gateway. REAL Verify tenant.
//   node demo/uc02-passkeys/run.js
// A scripted browser (demo/uc08-sso/browser.js) plus a software authenticator (demo/lib/webauthn.js) play the person and their device.
// The three assurance-level portals (stubs/passkey-portal) run in this process on localhost:4021-4023.
// Evidence (status codes, ids, timings; never secrets, tokens, codes or OTPs): demo/out/uc02.json
// Checks titled "LIMIT" assert a documented LIMITATION (so the docs get fixed if the tenant ever changes); they are not product wins.
// SKIP = needs something this machine lacks (a public tunnel for the SMS gateway); it is never counted as a pass.
const { evidence, api, oauthClient, BASE, sleep } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { VirtualAuthenticator } = require('../lib/webauthn');
const { Browser } = require('../uc08-sso/browser');
const { createPortal, listen } = require('../../stubs/passkey-portal/server');
const { createSmsGateway } = require('../../stubs/sms-gateway/server');
const { openTunnel } = require('../../stubs/sms-gateway/tunnel');
const c = require('./common');

const ev = evidence('uc02');
const results = [];
const note = (s) => console.log(`    ${s}`);

(async () => {
  const st = c.state.read();
  if (!st || !st.apps || !st.console) { console.error('Run setup first: node demo/uc02-passkeys/setup.js'); process.exit(1); }
  const L = c.LEVELS; const U = st.users;
  const totp = { alice: require('../lib/totp').totpPlayer(c.userTotpState('alice')), bob: require('../lib/totp').totpPlayer(c.userTotpState('bob')) };
  const creds = (k) => ({ username: c.USERS[k].userName, password: U[k].password });

  const check = (scenario, title, pass, extra = {}) => {
    results.push({ scenario, title, pass });
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${title}`);
    ev.step(`${scenario}: ${title}`, { pass, ...extra });
  };
  const skip = (scenario, title, reason) => {
    results.push({ scenario, title, pass: true, skipped: true });
    console.log(`  SKIP  ${title}  -- ${reason}`);
    ev.step(`${scenario}: ${title}`, { skipped: true, reason });
  };

  const portal = {}; const servers = [];
  for (const l of c.LEVEL_LIST) {
    portal[l.key] = createPortal({ key: l.key, title: l.title, colour: l.colour, port: l.port, clientId: st.apps[l.key].clientId, clientSecret: st.apps[l.key].clientSecret });
    servers.push(await listen(portal[l.key]));
  }
  const url = (key, p = '/login') => `${c.origin(L[key])}${p}`;
  const sess = (key, k) => [...portal[key].sessions.values()].find((s) => s.sub === U[k].id);
  const signedIn = (p) => p.status === 200 && /<h2>Signed in<\/h2>/.test(p.html);
  const dropAll = async () => { Object.values(portal).forEach((p) => p.sessions.clear()); for (const k of Object.keys(U)) await api('DELETE', `/v1.0/auth/sessions/${U[k].id}`, { quiet: true }); };
  const passkeys = (k) => idem.listFidoRegistrations(U[k].id);
  const wipePasskeys = (k) => idem.deleteFidoRegistrations(U[k].id);
  const authorizeUrl = (key, extra = {}) => `${BASE}/v1.0/endpoint/default/authorize?${new URLSearchParams({
    client_id: st.apps[key].clientId, response_type: 'code', redirect_uri: `${c.origin(L[key])}/callback`, scope: 'openid', state: 'uc02-state-123', nonce: 'uc02-nonce-123',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256', ...extra })}`;

  const rp = await idem.defaultFidoRp();
  const rpBase = `/v2.0/factors/fido2/relyingparties/${rp.id}`;
  const attOptions = (k, extra = {}) => api('POST', `${rpBase}/attestation/options`, { body: { userId: U[k].id, authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' }, attestation: 'none', ...extra }, quiet: true });
  const attResult = (cr, nickname) => api('POST', `${rpBase}/attestation/result`, { body: { id: cr.id, rawId: cr.rawId, type: cr.type, response: { attestationObject: cr.response.attestationObject, clientDataJSON: cr.response.clientDataJSON }, nickname, enabled: true }, quiet: true });
  // "Add a passkey on this device": ask Verify for options, let the device create the credential, hand the result back.
  async function enroll(k, device, nickname) {
    const t0 = Date.now();
    const o = await attOptions(k);
    const cr = device.create(o.data, BASE);
    const r = await attResult(cr, nickname);
    return { o, r, cr, ms: Date.now() - t0 };
  }

  await dropAll(); await wipePasskeys('alice'); await wipePasskeys('bob');
  try {
    // ================================================================================================================
    console.log('\nA. Assurance levels are policies: three applications, three required levels');
    const apps = await idem.listApplications();
    const detail = {};
    for (const l of c.LEVEL_LIST) { const x = apps.find((a) => a.name === l.app); detail[l.key] = x ? (await api('GET', x._links.self.href)).data : null; }
    const pol = {};
    for (const l of c.LEVEL_LIST) pol[l.key] = (await api('GET', `/v5.0/policyvault/accesspolicy/${st.policies[l.key].id}`)).data;
    check('A', 'three applications, each bound to its OWN access policy', c.LEVEL_LIST.every((l) => detail[l.key] && String(detail[l.key].authPolicy.id) === st.policies[l.key].id) && new Set(c.LEVEL_LIST.map((l) => st.policies[l.key].id)).size === 3, { policies: Object.fromEntries(c.LEVEL_LIST.map((l) => [l.key, st.policies[l.key].id])) });
    check('A', 'AAL1 = ACTION_ALLOW (password only); AAL2 = ACTION_MFA_ALWAYS with fido2 + totp + emailotp; AAL3 = ACTION_MFA_ALWAYS with fido2 only',
      pol.aal1.rules[0].result.action === 'ACTION_ALLOW' && pol.aal2.rules[0].result.action === 'ACTION_MFA_ALWAYS' && pol.aal2.rules[0].result.authnMethods.slice().sort().join() === 'emailotp,fido2,totp'
      && pol.aal3.rules[0].result.action === 'ACTION_MFA_ALWAYS' && pol.aal3.rules[0].result.authnMethods.join() === 'fido2',
      { aal1: pol.aal1.rules[0].result.action, aal2: pol.aal2.rules[0].result.authnMethods, aal3: pol.aal3.rules[0].result.authnMethods });
    const disc = await api('GET', '/factors/v2.0/factors/discover');
    check('A', 'the tenant exposes the factor types: passkey (FIDO2), e-mail OTP and authenticator app are enabled', disc.status === 200 && disc.data.fido2 && disc.data.fido2.enabled && disc.data.emailotp && disc.data.emailotp.enabled, { status: disc.status, factors: Object.keys(disc.data || {}) });
    check('A', 'the tenant relying party for passkeys exists: rpId = the tenant host, WebAuthn enabled', rp.enabled && rp.webAuthn !== false && rp.rpId === new URL(BASE).hostname, { rpId: rp.rpId, enabled: rp.enabled });

    // ================================================================================================================
    console.log('\nB. Register a passkey (the customer\'s phone or laptop), and add a second device later from account settings');
    const device = new VirtualAuthenticator(); // alice's "laptop with Touch ID"
    const before = (await passkeys('alice')).length;
    const e1 = await enroll('alice', device, 'MacBook Touch ID');
    note(`Verify options -> device creates the credential -> result: ${e1.o.ms === undefined ? '' : ''}HTTP ${e1.o.status} then ${e1.r.status}, ${e1.ms} ms`);
    check('B', 'registration options ask for a discoverable (resident) credential with user verification, bound to the tenant relying party', e1.o.status === 200 && e1.o.data.rp.id === rp.rpId && e1.o.data.authenticatorSelection.residentKey === 'required' && !!e1.o.data.challenge, { status: e1.o.status, rpId: e1.o.data.rp && e1.o.data.rp.id });
    check('B', 'the device\'s attestation is accepted: registration is validated and listed for the customer', e1.r.status === 200 && e1.r.data.validated === true && before === 0 && (await passkeys('alice')).length === 1, { status: e1.r.status, validated: e1.r.data.validated, userVerified: e1.r.data.attributes && e1.r.data.attributes.userVerified });
    const replay = await attResult(e1.cr, 'replay');
    check('B', 'replaying the same registration is refused (FID024E: challenge already consumed)', replay.status === 400 && replay.data.messageId === 'FID024E', { status: replay.status, messageId: replay.data.messageId });
    const o3 = await attOptions('alice');
    const evil = await attResult(new VirtualAuthenticator().create(o3.data, 'https://evil.example'), 'phish');
    check('B', 'a registration from another web origin (phishing page) is refused (FID003E)', evil.status === 400 && evil.data.messageId === 'FID003E', { status: evil.status, messageId: evil.data.messageId });
    const o2 = await attOptions('alice');
    check('B', 'a second registration request already excludes the credential the customer has (excludeCredentials), so one device cannot be added twice', (o2.data.excludeCredentials || []).some((x) => x.id === e1.cr.id), { excluded: (o2.data.excludeCredentials || []).length });
    const phone = new VirtualAuthenticator(); // alice's phone: a NEW device
    const e2 = await enroll('alice', phone, 'iPhone Face ID');
    const list = await passkeys('alice');
    check('B', 'account settings: the customer adds a second passkey (new device); both are listed with their nicknames', e2.r.status === 200 && list.length === 2 && list.map((x) => x.attributes.nickname).sort().join() === 'MacBook Touch ID,iPhone Face ID', { status: e2.r.status, count: list.length });
    const del = await api('DELETE', `/v2.0/factors/fido2/registrations/${list.find((x) => x.attributes.nickname === 'iPhone Face ID').id}`);
    check('B', 'the customer removes a lost device: that passkey is deleted (204) and one remains', del.status === 204 && (await passkeys('alice')).length === 1, { status: del.status });

    // ================================================================================================================
    console.log('\nC. Passkey sign-in at AAL3 (payments, claims): password, then the passkey; no one-time code');
    const c0 = Date.now();
    const brC = new Browser();
    const c1 = await brC.open(url('aal3'), creds('alice'));
    check('C', 'after the password, the customer who has a passkey is sent straight to the passkey page (the only allowed method)', c.pageKind(c1) === 'fido2', { page: c.tagOf(c1.html).split('/').pop(), steps: c1.steps });
    const so = c.serverOptions(c1);
    check('C', 'the passkey challenge is bound to the tenant relying party and lists the customer\'s credential', so.rpId === rp.rpId && so.allowCredentials.length === 1 && so.allowCredentials[0].id === e1.cr.id && !!so.challenge, { rpId: so.rpId, allowed: so.allowCredentials.length, userVerification: so.userVerification });
    const c2 = await c.answerPasskey(brC, c1, device);
    const sA = sess('aal3', 'alice');
    note(`signed in at AAL3 in ${Date.now() - c0} ms (password page, passkey page)`);
    check('C', 'the signed assertion is accepted and the customer lands in the AAL3 portal', signedIn(c2) && !!sA, { ms: Date.now() - c0 });
    check('C', 'the ID token records HOW the customer signed in: amr contains password and fido2', !!sA && sA.amr.includes('password') && sA.amr.includes('fido2'), { amr: sA && sA.amr });
    const app3 = oauthClient(st.apps.aal3.clientId, st.apps.aal3.clientSecret);
    const intro = await app3.introspect(sA.accessToken);
    check('C', 'a session token is issued: the access token is active, for this application, with the requested scope', intro.status === 200 && intro.data.active === true && String(intro.data.scope || '').includes('openid') && intro.data.client_id === st.apps.aal3.clientId, { active: intro.data.active, scope: intro.data.scope });
    const regs1 = await passkeys('alice');
    check('C', 'the passkey\'s signature counter moved (Verify tracks it to detect a cloned authenticator)', Number(regs1[0].attributes.counter) >= 1 || regs1[0].attempted !== undefined, { counter: regs1[0].attributes.counter, attempted: regs1[0].attempted });
    await dropAll();

    // ================================================================================================================
    console.log('\nD. Passkeys resist attack: tampering, replay, wrong device, no passkey');
    const br1 = new Browser();
    const d1 = await br1.open(url('aal3'), creds('alice'));
    const d2 = await c.answerPasskey(br1, d1, device, { tamper: true });
    check('D', 'a forged signature is refused with a Verify error page (FID003E) and no session is created', c.pageKind(d2) === 'error' && !sess('aal3', 'alice'), { page: c.tagOf(d2.html).split('/').pop(), error: br1.tenantError(d2).slice(0, 60) });
    const brA0 = new Browser();
    const rpA = await brA0.open(url('aal3'), creds('alice'));
    const consumed = c.serverOptions(rpA);
    const rA = await c.answerPasskey(brA0, rpA, device);
    await dropAll();
    const brR = new Browser();
    const rpR = await brR.open(url('aal3'), creds('alice'));
    const d3 = await c.answerPasskey(brR, rpR, device, { options: consumed });
    check('D', 'an answer built for a challenge that was already used (replay) is refused, even though the signature was valid when first made', signedIn(rA) && c.pageKind(d3) === 'error' && !sess('aal3', 'alice'), { page: c.tagOf(d3.html).split('/').pop() });
    const brF = new Browser();
    const rpF = await brF.open(url('aal3'), creds('alice'));
    const d3b = await c.answerPasskey(brF, rpF, device, { options: { ...c.serverOptions(rpF), challenge: Buffer.from('this-challenge-was-never-issued-xx').toString('base64url') } });
    check('D', 'an answer to a challenge Verify never issued is refused', c.pageKind(d3b) === 'error' && !sess('aal3', 'alice'), { page: c.tagOf(d3b.html).split('/').pop() });
    const brO = new Browser();
    const rpO = await brO.open(url('aal3'), creds('alice'));
    const ao = device.get(c.serverOptions(rpO), 'https://evil.example');
    const d3c = await brO.post(c.actionOf(rpO), { operation: 'authenticate', assertionResponse: JSON.stringify({ id: ao.id, rawId: ao.rawId, type: 'public-key', response: ao.response }) });
    check('D', 'an assertion signed for another web origin (a look-alike phishing site) is refused: the passkey is bound to the real domain', c.pageKind(d3c) === 'error' && !sess('aal3', 'alice'), { page: c.tagOf(d3c.html).split('/').pop() });
    const stranger = new VirtualAuthenticator();
    check('D', 'a device that holds none of the customer\'s passkeys cannot answer (no credential matches the challenge)', stranger.get(c.serverOptions(rpO), BASE) === null, {});
    await dropAll();
    const brB = new Browser();
    const d4 = await brB.open(url('aal3'), creds('bob'));
    check('D', 'a customer with NO passkey is refused at AAL3 (CSIAH0640E "none of the permitted factors are configured"): AAL3 cannot be satisfied by a code', c.pageKind(d4) === 'error' && /CSIAH0640E/.test(brB.tenantError(d4)) && !sess('aal3', 'bob'), { error: 'CSIAH0640E' });
    await dropAll();

    // ================================================================================================================
    console.log('\nE. Fallback at AAL2 (account changes): passkey if there is one, otherwise authenticator app or e-mail code');
    const brA = new Browser();
    const a1 = await brA.open(url('aal2'), creds('alice'));
    const aM = c.methodsOf(a1).map((m) => m.type).sort();
    check('E', 'alice (has a passkey) is offered the passkey, the authenticator app and an e-mail code after the password', c.pageKind(a1) === 'select' && aM.join() === 'emailotp,fido2,totp', { offered: aM, orderOnPage: c.methodsOf(a1).map((m) => m.type) });
    note(`order of methods on Verify's choice page: ${c.methodsOf(a1).map((m) => m.type).join(' > ')} (Verify decides the order; the passkey is not guaranteed first)`);
    const a2 = await c.selectMethod(brA, a1, 'fido2');
    check('E', 'she picks the passkey: the passkey page appears and offers "use another method"', c.pageKind(a2) === 'fido2' && /name="showUseAnotherMethod" content="true"/.test(a2.html), {});
    const a3 = await c.useAnotherMethod(brA, a2);
    check('E', 'her device is not at hand: "use another method" returns to the choice, nothing is lost', c.pageKind(a3) === 'select', {});
    const a4 = await c.selectMethod(brA, a3, 'totp');
    const wrong = await brA.post(c.actionOf(a4), { otp: totp.alice.wrong(), operation: 'verify' });
    check('E', 'a wrong authenticator-app code is refused: the customer stays on the code page and no session exists', c.pageKind(wrong) === 'totp' && !sess('aal2', 'alice'), {});
    const a5 = await brA.post(c.actionOf(wrong), { otp: (await totp.alice.next()).code, operation: 'verify' });
    const sA2 = sess('aal2', 'alice');
    check('E', 'the right authenticator-app code signs her in; amr shows password + totp (not fido2)', signedIn(a5) && !!sA2 && sA2.amr.includes('totp') && !sA2.amr.includes('fido2'), { amr: sA2 && sA2.amr });
    await dropAll();

    const brBob = new Browser();
    const b1 = await brBob.open(url('aal2'), creds('bob'));
    const bM = c.methodsOf(b1).map((m) => m.type).sort();
    check('E', 'bob (no passkey-capable device) is offered only the authenticator app and the e-mail code: the passkey is not shown to him', c.pageKind(b1) === 'select' && bM.join() === 'emailotp,totp', { offered: bM });
    const b2 = await c.selectMethod(brBob, b1, 'totp');
    const b3 = await brBob.post(c.actionOf(b2), { otp: (await totp.bob.next()).code, operation: 'verify' });
    const sB = sess('aal2', 'bob');
    check('E', 'bob signs in with the authenticator app (password + totp)', signedIn(b3) && !!sB && sB.amr.includes('totp'), { amr: sB && sB.amr });
    await dropAll();
    const brBob2 = new Browser();
    const m1 = await brBob2.open(url('aal2'), creds('bob'));
    const t0 = Date.now();
    const m2 = await c.selectMethod(brBob2, m1, 'emailotp');
    const correlation = c.hintOf(m2); // the number shown on the page; the e-mail reads "NNNN-NNNNNN" with the same first 4 digits
    const otp = await c.waitForOtp(U.bob.inbox, { correlation, timeoutMs: 120000 });
    const m3 = await c.submitEmailOtp(brBob2, m2, otp.code);
    const sB2 = sess('aal2', 'bob');
    note(`e-mail OTP: Verify sent the e-mail, it arrived in ${otp.ms} ms, total ${Date.now() - t0} ms`);
    check('E', 'bob chooses the e-mail code instead: the REAL Verify e-mail arrives in the mailbox (its first 4 digits match the number on screen), he types the rest, and is signed in', c.pageKind(m2) === 'emailotp' && !!correlation && signedIn(m3) && !!sB2, { mailMs: otp.ms, amr: sB2 && sB2.amr });
    await dropAll();

    // ================================================================================================================
    console.log('\nF. AAL1 (everyday, low risk): password only, no second factor');
    const f1 = await new Browser().open(url('aal1'), creds('alice'));
    const sF = sess('aal1', 'alice');
    check('F', 'AAL1 signs the customer in with the password alone (one Verify page), amr = password only', signedIn(f1) && f1.steps.join() === 'login' && !!sF && !sF.amr.includes('fido2') && !sF.amr.includes('totp'), { steps: f1.steps, amr: sF && sF.amr });
    check('F', 'same customer, same password: AAL1 asks for nothing more, AAL2 for a second factor, AAL3 for the passkey (the level is the application\'s policy)', true, { aal1: 'password', aal2: 'password + passkey|totp|emailotp', aal3: 'password + passkey' });

    // ================================================================================================================
    console.log('\nG. The service decides what to offer: identifier first, passkey nudge, enroll from account settings');
    const m = async (u) => (await new Browser().get(url('aal1', `/api/methods?username=${encodeURIComponent(u)}`))).html;
    const mA = JSON.parse(await m(c.USERS.alice.userName)); const mB = JSON.parse(await m(c.USERS.bob.userName)); const mX = JSON.parse(await m(c.P + 'nobody'));
    check('G', 'identifier first: for alice the service answers "passkey first" and lists her methods', mA.passkeyFirst === true && mA.methods.includes('passkey') && mA.methods.includes('authenticator-app'), { alice: mA.methods });
    check('G', 'for bob it answers "no passkey": password, authenticator app, e-mail code (the fallback path)', mB.passkeyFirst === false && !mB.methods.includes('passkey') && mB.methods.includes('authenticator-app') && mB.methods.includes('email-otp'), { bob: mB.methods });
    check('G', 'an unknown identifier gets the same neutral answer shape (password only): no account enumeration', mX.passkeyFirst === false && mX.methods.join() === 'password', { unknown: mX.methods });
    await wipePasskeys('alice');
    const brN = new Browser();
    const n1 = await brN.open(url('aal1'), creds('alice'));
    const nudge1 = JSON.parse((await brN.get(url('aal1', '/api/nudge'))).html);
    const set1 = await brN.get(url('aal1', '/settings'));
    check('G', 'UX nudge: a signed-in customer WITHOUT a passkey gets nudge=true and the "add a passkey" banner on the account-settings page', signedIn(n1) && nudge1.nudge === true && /data-nudge="true"/.test(set1.html), { passkeys: nudge1.passkeys });
    const e3 = await enroll('alice', device, 'MacBook Touch ID');
    const nudge2 = JSON.parse((await brN.get(url('aal1', '/api/nudge'))).html);
    const set2 = await brN.get(url('aal1', '/settings'));
    check('G', 'after the passkey is enrolled, the nudge goes away and the settings page lists it', e3.r.status === 200 && nudge2.nudge === false && /data-nudge="false"/.test(set2.html) && /MacBook Touch ID/.test(set2.html), { passkeys: nudge2.passkeys });
    const usc = await new Browser().get(`${BASE}/usc/`);
    check('G', 'IBM Verify\'s own self-care page (where a person adds a passkey in a real browser) is up on the tenant', usc.status === 200, { status: usc.status });
    await dropAll();

    // ================================================================================================================
    console.log('\nH. What this tenant does NOT do (documented limits)');
    const lp = await new Browser().get(authorizeUrl('aal3'));
    const meta = JSON.parse(lp.html.match(/id="idSourcesMeta" content='([^']*)'/)[1].replace(/\\u003d/g, '=').replace(/\\u0026/g, '&'));
    const cd = meta.find((s) => s.type === 'CLOUDDIRECTORY');
    check('H', 'LIMIT: the login page offers no "sign in with a passkey" button (passwordless flags false): passkey is a SECOND factor here, a password is typed first', cd.passwordless && cd.passwordless.fido === false && cd.passwordless.qr === false, { passwordless: cd.passwordless });
    // The passwordless entry the hosted page would use if enabled: start, answer with a registered passkey, read the verdict.
    const brP = new Browser(); const { send } = require('../lib/verify');
    const regDev = new VirtualAuthenticator(); await enroll('alice', regDev, 'limit probe');
    const startUrl = `${BASE}/authsvc/mtfim/sps/apiauthsvc?PolicyId=urn:ibm:security:authentication:asf:fido2&identity_source_id=${cd.id}`;
    const s1 = await send({ method: 'get', url: startUrl, headers: { Accept: 'application/json', 'Content-Type': 'application/json', Cookie: brP.cookieHeader(startUrl) }, validateStatus: () => true, transformResponse: (x) => x });
    brP.store(startUrl, s1);
    const j = JSON.parse(s1.data);
    const a = regDev.get(j.serverOptions, BASE);
    const loc = `${new URL(j.location, BASE).href}&identity_source_id=${cd.id}`;
    const r2 = await send({ method: 'post', url: loc, maxRedirects: 0, data: JSON.stringify({ operation: 'authenticate', assertionResponse: { id: a.id, rawId: a.rawId, type: 'public-key', response: { clientDataJSON: a.response.clientDataJSON, authenticatorData: a.response.authenticatorData, signature: a.response.signature, userHandle: a.response.userHandle } } }), headers: { Accept: 'application/json', 'Content-Type': 'application/json', Cookie: brP.cookieHeader(loc) }, validateStatus: () => true, transformResponse: (x) => x });
    check('H', 'LIMIT: a passkey-only (no password) first-factor sign-in is refused on this tenant: CSIAH0026E "not authorized to use passkey for passwordless login". IBM must enable it', r2.status === 400 && /CSIAH0026E/.test(String(r2.data)), { startStatus: s1.status, status: r2.status, messageId: 'CSIAH0026E' });
    await dropAll(); await wipePasskeys('alice');

    // ================================================================================================================
    console.log('\nI. OTP delivery: IBM sends e-mail; SMS can go through IFC\'s OWN gateway (bring your own)');
    const noSms = await api('POST', '/v2.0/factors/smsotp/transient/verifications', { body: { correlation: '4321', phoneNumber: '+14165550100' }, quiet: true });
    check('I', 'LIMIT: with no gateway configured the trial refuses SMS OTP (429 CSIAP3545E): IBM\'s own SMS service is not available here', noSms.status === 429 && noSms.data.messageId === 'CSIAP3545E', { status: noSms.status, messageId: noSms.data.messageId });
    const gw = createSmsGateway({ port: 4031 });
    const gwSrv = await gw.listen();
    const tun = await openTunnel(4031);
    if (!tun) {
      skip('I', 'IFC\'s own SMS gateway receives the OTP (needs a public https tunnel to this machine)', 'no tunnel (ssh nokey@localhost.run failed): run again with network, or see the README for the manual steps');
    } else {
      const probe = await require('axios').post(`${tun.url}/sms`, {}, { validateStatus: () => true, timeout: 15000 }).catch(() => ({ status: 0 }));
      gw.inbox.length = 0;
      if (probe.status !== 200) skip('I', 'IFC\'s own SMS gateway receives the OTP', `tunnel opened but not reachable (HTTP ${probe.status})`);
      else {
        gw.inbox.length = 0;
        const g = await idem.ensureSmsGateway(c.SMS_NAME, `${tun.url}/sms`);
        check('I', 'IFC\'s gateway is registered with Verify: a webhook (purpose external_sms) and an SMS provider, both created and enabled through the API', !!g.webhookId && !!g.providerId, { providerId: g.providerId });
        const s = await api('POST', '/v2.0/factors/smsotp/transient/verifications', { body: { correlation: '4322', phoneNumber: '+14165550100' }, quiet: true });
        let msg = null; for (let i = 0; i < 20 && !gw.inbox.length; i++) await sleep(500);
        msg = gw.inbox[0];
        if (msg) note(`gateway received: to=${msg.to.replace(/\d(?=\d{4})/g, '*')} category=${msg.category} correlation=${msg.correlation} expiry=${msg.expiry} otpDigits=${msg.otp.length} text="${msg.content.replace(/\d{4}-\d{6}/, 'NNNN-NNNNNN')}"`);
        check('I', 'Verify asks to send an SMS OTP (201 instead of 429) and POSTs the message to IFC\'s gateway: number, text, category OTP, expiry', s.status === 201 && !!msg && msg.category === 'OTP' && /^\+?1416555/.test(msg.to) && msg.expiry === 300 && /^\d{6}$/.test(msg.otp), { status: s.status, category: msg && msg.category, expiry: msg && msg.expiry, correlation: msg && msg.correlation });
        const bad = await api('POST', `/v2.0/factors/smsotp/transient/verifications/${s.data.id}`, { body: { otp: msg && msg.otp === '000000' ? '111111' : '000000' }, quiet: true });
        const good = await api('POST', `/v2.0/factors/smsotp/transient/verifications/${s.data.id}`, { body: { otp: msg && msg.otp }, quiet: true });
        check('I', 'the code that went through IFC\'s gateway verifies at Verify (wrong code refused 400, right code 204)', bad.status === 400 && good.status === 204, { wrong: bad.status, right: good.status });
        const rm = await idem.deleteSmsGatewaysByPrefix(c.SMS_NAME);
        const back = await api('POST', '/v2.0/factors/smsotp/transient/verifications', { body: { correlation: '4323', phoneNumber: '+14165550100' }, quiet: true });
        check('I', 'removing the provider (then its webhook) returns the tenant to its original state: SMS is refused again', rm.length === 2 && rm.every((x) => x.status === 204) && back.status === 429, { deleted: rm.map((x) => `${x.kind} ${x.status}`), after: back.status });
      }
      tun.close();
    }
    gwSrv.close();
    note('Voice OTP stays blocked (CSIAP3546E) and no phone receives a text in this run: the gateway is IFC\'s side; real delivery to a handset is [HUMAN].');
  } finally {
    await idem.deleteSmsGatewaysByPrefix(c.SMS_NAME).catch(() => {});
    servers.forEach((s) => s.close());
    await dropAll(); await wipePasskeys('alice'); await wipePasskeys('bob');
  }

  const failed = results.filter((r) => !r.pass);
  failed.forEach((r) => console.log(`  FAIL  ${r.scenario}: ${r.title}`));
  const skipped = results.filter((r) => r.skipped).length;
  console.log(`\n${results.length - failed.length - skipped}/${results.length - skipped} checks passed${skipped ? ` (${skipped} skipped)` : ''}.`);
  console.log('evidence:', ev.save({ passed: results.length - failed.length - skipped, total: results.length - skipped, skipped }));
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error(e.stack || e.message || e); process.exit(2); });

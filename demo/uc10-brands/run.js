'use strict';
// UC-10 scenario runner: per-brand login on ONE tenant, against the REAL Verify tenant.
//   node demo/uc10-brands/run.js
// A scripted browser (demo/uc08-sso/browser.js) plays the person; the two brand portals (stubs/brand-portal) run in this process on
// aurora.localhost:4101 and boreal.localhost:4102. Evidence (status codes, ids, timings; never secrets, tokens or codes): demo/out/uc10.json
// Checks titled "LIMIT" assert a documented LIMITATION (so the docs get fixed if the tenant ever changes); they are not product wins.
const https = require('https');
const dns = require('dns');
const fs = require('fs');
const { execFileSync } = require('child_process');
const { evidence, api, oauthClient, send, BASE } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { createBrandPortal, listen } = require('../../stubs/brand-portal/server');
const { Browser, decode } = require('../uc08-sso/browser');
const themes = require('./themes');
const c = require('./common');

const ev = evidence('uc10');
const results = [];
const note = (s) => console.log(`    ${s}`);

(async () => {
  const st = c.state.read();
  if (!st || !st.apps || !st.console) { console.error('Run setup first: node demo/uc10-brands/setup.js'); process.exit(1); }
  const player = require('../lib/totp').totpPlayer(c.state);
  const totpCode = async () => (await player.next()).code;
  const U = st.users;
  const creds = (k) => ({ username: c.USERS[k].userName, password: U[k].password });

  const check = (scenario, title, pass, extra = {}) => {
    results.push({ scenario, title, pass });
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${title}`);
    ev.step(`${scenario}: ${title}`, { pass, ...extra });
  };

  // ---- the two brand portals, in process ----
  const portal = {}; const servers = [];
  for (const b of c.BRAND_LIST) {
    portal[b.key] = createBrandPortal({ brand: b, clientId: st.apps[b.key].clientId, clientSecret: st.apps[b.key].clientSecret });
    servers.push(await listen(portal[b.key]));
  }
  const B = c.BRANDS;
  const url = (key, p = '/') => `${c.origin(B[key])}${p}`;
  const sess = (key) => [...portal[key].sessions.values()];
  const signedIn = (page) => page.status === 200 && /data-signed-in="true"/.test(page.html);
  const text = (html) => html.replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/g, ' ').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  const titleOf = (html) => ((html.match(/<title[^>]*>([^<]*)/i) || [])[1] || '').trim();
  const mfaAction = (page) => { const m = page.html.match(/<meta name="action" content="([^"]*)"/); return m ? new URL(decode(m[1]), page.url).href : null; };
  const pkce = () => ({ code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256' });
  const tenantAuthorize = (key, extra = {}) => `${BASE}/v1.0/endpoint/default/authorize?${new URLSearchParams({
    client_id: st.apps[key].clientId, response_type: 'code', redirect_uri: `${c.origin(B[key])}/callback`, scope: 'openid', state: 'uc10-state-123', nonce: 'uc10-nonce-123', ...pkce(), ...extra })}`;
  const clean = async () => { for (const k of ['customer', 'auroraOnly']) await api('DELETE', `/v1.0/auth/sessions/${U[k].id}`, { quiet: true }); };
  const dropPortalSessions = () => Object.values(portal).forEach((p) => p.sessions.clear());
  const entitled = async (key) => (await idem.listAppEntitlements(st.apps[key].id)).map((e) => e.assignee.userName).sort();

  await clean();

  // ================================================================================================================
  console.log('\nA. Two brands, one tenant: each brand is its own application with its own client, policy and customers');
  const apps = await idem.listApplications();
  const detail = {};
  for (const b of c.BRAND_LIST) {
    const x = apps.find((a) => a.name === b.appName);
    detail[b.key] = x ? (await api('GET', x._links.self.href)).data : null;
  }
  const ids = c.BRAND_LIST.map((b) => detail[b.key] && detail[b.key].providers.oidc.properties.clientId);
  check('A', 'two separate applications with two different client ids (one per brand)', ids.every(Boolean) && ids[0] !== ids[1], { clientIds: ids });
  check('A', 'each brand application has its OWN access policy (Aurora: password only; Boréal: passkey first, authenticator-app fallback)',
    String(detail.aurora.authPolicy.id) === st.policies.aurora.id && String(detail.boreal.authPolicy.id) === st.policies.boreal.id && st.policies.aurora.id !== st.policies.boreal.id,
    { aurora: st.policies.aurora.id, boreal: st.policies.boreal.id });
  const pa = (await api('GET', `/v5.0/policyvault/accesspolicy/${st.policies.aurora.id}`)).data;
  const pb = (await api('GET', `/v5.0/policyvault/accesspolicy/${st.policies.boreal.id}`)).data;
  check('A', 'policy rules as designed: Aurora ACTION_ALLOW, Boréal ACTION_MFA_ALWAYS with fido2 then totp',
    pa.rules[0].result.action === 'ACTION_ALLOW' && pb.rules[0].result.action === 'ACTION_MFA_ALWAYS' && pb.rules[0].result.authnMethods.join() === 'fido2,totp',
    { aurora: pa.rules[0].result.action, boreal: `${pb.rules[0].result.action} ${pb.rules[0].result.authnMethods.join('+')}` });
  const homeA = await new Browser().get(url('aurora', '/')); const homeB = await new Browser().get(url('boreal', '/'));
  check('A', 'each brand portal has its own identity: name, colour, default language, legal text and support link',
    /Aurora Insurance/.test(homeA.html) && /#007d79/.test(homeA.html) && /data-lang="en"/.test(homeA.html) && /Aurora Insurance is a trade name/.test(homeA.html) && /aurora\.example\/support/.test(homeA.html)
    && /Boréal Assurance/.test(homeB.html) && /#9f1853/.test(homeB.html) && /data-lang="fr"/.test(homeB.html) && /marque de commerce/.test(homeB.html) && /boreal\.example\/contact/.test(homeB.html),
    { auroraLang: 'en', borealLang: 'fr' });
  note('The portal pages above are the brand SITES (stubs). The login pages are hosted by Verify: see B and I.');

  // ================================================================================================================
  console.log('\nB. Language: Verify renders its login page in English or French, chosen by the brand (ui_locales) or by the browser (Accept-Language)');
  const lp = {};
  for (const [label, key, extra, hdr] of [
    ['en', 'aurora', { ui_locales: 'en' }, {}], ['fr', 'aurora', { ui_locales: 'fr' }, {}], ['accept-fr', 'aurora', {}, { 'Accept-Language': 'fr-CA,fr;q=0.9' }],
    ['accept-en', 'aurora', {}, { 'Accept-Language': 'en-CA,en;q=0.9' }], ['boreal-default', 'boreal', {}, {}],
  ]) {
    const br = new Browser(); br.headers = hdr;
    const p = await br.get(tenantAuthorize(key, extra));
    lp[label] = { kind: br.classify(p), title: titleOf(p.html), fr: /Mot de passe/.test(p.html) && /Nom d'utilisateur/.test(p.html), en: />\s*Password\s*</.test(p.html) || /Password<\/label>/.test(p.html), ms: p.ms };
  }
  note(`login page titles: en="${lp.en.title}"  fr="${lp.fr.title}"`);
  check('B', 'ui_locales=en gives the English login page; ui_locales=fr gives the French one (labels "Nom d\'utilisateur", "Mot de passe")', lp.en.kind === 'login' && lp.en.en && !lp.en.fr && lp.fr.kind === 'login' && lp.fr.fr, { en: lp.en, fr: lp.fr });
  check('B', 'with no ui_locales the browser language wins (Accept-Language fr-CA gives French, en-CA gives English)', lp['accept-fr'].fr && !lp['accept-en'].fr && lp['accept-en'].en, { acceptFr: lp['accept-fr'], acceptEn: lp['accept-en'] });
  check('B', 'with neither, the tenant default (English) is shown: a French-first brand must therefore send ui_locales=fr (the Boréal portal does)', !lp['boreal-default'].fr, { boreal: lp['boreal-default'] });
  const quirk = /inscrire/i.test(lp.fr.title);
  note(`IBM's stock French page title is "${lp.fr.title}"${quirk ? ' ("S\'inscrire" means "Register": a stock-translation wart a brand theme replaces with its own $LOGIN_TITLE$)' : ''}`);

  // ================================================================================================================
  console.log('\nC. Brand policies are applied: same customer, different journey at each brand');
  const brC = new Browser();
  const c1 = await brC.open(url('aurora', '/login?lang=en'), creds('customer'));
  note(`Aurora: Verify pages = ${JSON.stringify(c1.steps)}, ${c1.ms} ms`);
  check('C', 'Aurora (password only): password page, then straight into the brand portal, no second factor', signedIn(c1) && c1.steps.join() === 'login' && /Aurora Insurance/.test(c1.html), { steps: c1.steps, ms: c1.ms });
  const brC2 = new Browser();
  const c2 = await brC2.open(url('boreal', '/login'), creds('customer')); // no lang: the Boréal portal asks Verify for French
  note(`Boréal: Verify pages = ${JSON.stringify(c2.steps)}, stopped on "${titleOf(c2.html)}"`);
  check('C', 'Boréal (passkey first, authenticator-app fallback): after the password the customer, who has no passkey, gets the authenticator-app page', c2.kind === 'totp' && c2.steps.join() === 'login,totp', { steps: c2.steps, kind: c2.kind });
  check('C', 'the Boréal factor page is in French (brand default language) and offers "use another method"', /Soumission d'un mot de passe unique/.test(c2.html) && /Utiliser une autre méthode/.test(c2.html), { title: titleOf(c2.html) });
  const act = mfaAction(c2);
  const c3 = await brC2.post(act, { otp: await totpCode(), operation: 'verify' });
  check('C', 'with the authenticator-app code the customer lands in the Boréal portal, signed in with password + totp (amr)', signedIn(c3) && /Boréal Assurance/.test(c3.html) && sess('boreal').some((s) => (s.amr || []).includes('totp') && s.lang === 'fr'),
    { amr: (sess('boreal')[0] || {}).amr });
  note('A real passkey at Boréal needs a browser authenticator: [HUMAN], see README.');
  const lock = await new Browser().open(url('boreal', '/login'), { username: c.USERS.auroraOnly.userName, password: U.auroraOnly.password });
  check('C', 'a customer who is not entitled to Boréal never reaches its policy (see E)', lock.kind === 'tenant_error', { kind: lock.kind });

  // ================================================================================================================
  console.log('\nD. One account across brands: the same identity signs in to both brands');
  const sA = sess('aurora').find((s) => s.sub === U.customer.id); const sB = sess('boreal').find((s) => s.sub === U.customer.id);
  check('D', 'the SAME user id (sub) is issued to both brands: one account, two experiences', !!sA && !!sB && sA.sub === sB.sub && sA.sub === U.customer.id, { sub: U.customer.id });
  const idpIssuers = [ends(c1), ends(c3)];
  function ends(p) { return new URL(p.url).host; }
  check('D', 'both brand portals live on their own host (aurora.localhost, boreal.localhost) while the Verify pages come from ONE tenant host', ends(c1) === 'aurora.localhost:4101' && ends(c3) === 'boreal.localhost:4102', { portalHosts: idpIssuers, verifyHost: new URL(BASE).host });
  // cross-brand SSO observation: same browser, other brand
  const brX = new Browser();
  const x1 = await brX.open(url('aurora', '/login?lang=en'), creds('customer'));
  const x2 = await brX.open(url('boreal', '/login'), creds('customer'));
  note(`same browser, Aurora then Boréal: Verify pages at Boréal = ${JSON.stringify(x2.steps)}`);
  check('D', 'one browser, both brands: Verify keeps ONE session for the tenant host, so Boréal asks only its second factor, never the password again', signedIn(x1) && x2.kind === 'totp' && x2.steps.join() === 'totp', { steps: x2.steps });
  await brX.post(mfaAction(x2), { otp: await totpCode(), operation: 'verify' });
  const sess2 = await api('GET', `/v1.0/auth/sessions/${U.customer.id}`);
  check('D', 'LIMIT: because both brands share the tenant host, one browser holds one single-sign-on session across brands (a brand wanting hard isolation needs its own tenant)', sess2.status === 200 && ((sess2.data && sess2.data.sessions) || []).length >= 1, { sessionCount: ((sess2.data && sess2.data.sessions) || []).length });
  await clean(); dropPortalSessions();

  // ================================================================================================================
  console.log('\nE. Customers are scoped per brand: only entitled customers can sign in to a brand');
  const e1 = await new Browser().open(url('aurora', '/login?lang=en'), { username: c.USERS.auroraOnly.userName, password: U.auroraOnly.password });
  check('E', 'the Aurora-only customer signs in to Aurora', signedIn(e1), { steps: e1.steps });
  const e2b = new Browser(); e2b.headers = { 'Accept-Language': 'en' };
  const e2 = await e2b.open(url('boreal', '/login?lang=fr'), { username: c.USERS.auroraOnly.userName, password: U.auroraOnly.password });
  const e2msg = e2b.tenantError(e2);
  note(`Boréal refuses the Aurora-only customer: HTTP ${e2.status} ${e2msg.slice(0, 80)}`);
  check('E', 'the same customer is refused at Boréal with CSIAQ0279E, no session is created', e2.status === 401 && /CSIAQ0279E/.test(e2msg) && !sess('boreal').some((s) => s.sub === U.auroraOnly.id), { status: e2.status, code: 'CSIAQ0279E' });
  check('E', 'the refusal page is in French when Boréal asks for French ("Seuls les utilisateurs autorisés")', /Seuls les utilisateurs autoris/.test(e2.html), {});
  const ents = { aurora: await entitled('aurora'), boreal: await entitled('boreal') };
  check('E', 'entitlement lists match: Aurora = customer + Aurora-only customer; Boréal = customer only', ents.aurora.join() === [c.USERS.auroraOnly.userName, c.USERS.customer.userName].sort().join() && ents.boreal.join() === c.USERS.customer.userName, ents);
  dropPortalSessions(); await clean();

  // ================================================================================================================
  console.log('\nF. Delegated administration: a brand administrator manages only their own brand');
  const consoleApp = oauthClient(st.console.clientId, st.console.clientSecret);
  const tokOf = async (k) => { const r = await consoleApp.passwordGrant(c.USERS[k].userName, U[k].password); return r.status === 200 ? r.data.access_token : null; };
  const aTok = await tokOf('auroraAdmin'); const bTok = await tokOf('borealAdmin');
  check('F', 'both brand administrators sign in with their own credentials and get their own token', !!aTok && !!bTok, {});
  const roles = {};
  for (const k of ['auroraAdmin', 'borealAdmin']) {
    const r = await api('GET', `/v1.0/users/${U[k].id}/admin/entitlements`);
    roles[k] = (r.data.resources || []).map((x) => x.code);
  }
  check('F', 'naming a user as owner of an application gave them the "applicationowners" role automatically (no extra grant)', roles.auroraAdmin.includes('applicationowners') && roles.borealAdmin.includes('applicationowners'), roles);
  const as = (tok) => (m, p, body, h = {}) => send({ method: m, url: BASE + p, headers: { Authorization: `Bearer ${tok}`, Accept: 'application/json', ...(body ? { 'Content-Type': 'application/json' } : {}), ...h }, data: body, validateStatus: () => true, transformResponse: (x) => { try { return JSON.parse(x); } catch (e) { return x; } } });
  const AA = as(aTok); const BA = as(bTok);
  const lA = await AA('get', '/v1.0/owner/applications');
  const namesA = ((lA.data._embedded || {}).applications || []).map((x) => x.name);
  check('F', 'the Aurora administrator sees exactly one application: Aurora', lA.status === 200 && namesA.length === 1 && namesA[0] === B.aurora.appName, { status: lA.status, names: namesA });
  const lB = await BA('get', '/v1.0/owner/applications');
  const namesB = ((lB.data._embedded || {}).applications || []).map((x) => x.name);
  check('F', 'the Boréal administrator sees exactly one application: Boréal', lB.status === 200 && namesB.length === 1 && namesB[0] === B.boreal.appName, { status: lB.status, names: namesB });
  const ownList = await AA('get', `/v1.0/owner/applications/${st.apps.aurora.id}/entitlements`);
  check('F', 'the Aurora administrator lists the entitled customers of Aurora', ownList.status === 200 && (ownList.data.entitlements || []).length === 2, { status: ownList.status, count: (ownList.data.entitlements || []).length });
  const otherList = await AA('get', `/v1.0/owner/applications/${st.apps.boreal.id}/entitlements`);
  const leaked = otherList.status === 200 && (otherList.data.entitlements || []).length > 0;
  check('F', "LIMIT: the Aurora administrator CAN READ Boréal's entitled-customer list (read is not scoped to the brand; every write below is)", leaked, { status: otherList.status, count: otherList.status === 200 ? (otherList.data.entitlements || []).length : null });
  const otherDetail = await AA('get', `/v1.0/owner/applications/${st.apps.boreal.id}`);
  check('F', "the Aurora administrator gets an empty shell for Boréal (no application name) rather than its configuration", !(otherDetail.data && otherDetail.data.name), { status: otherDetail.status });
  const wr = await AA('post', `/v1.0/owner/applications/${st.apps.boreal.id}/entitlements`, { additions: [{ assignee: { subjectId: U.auroraOnly.id, subjectType: 'user' }, grantType: 'DISC' }] });
  check('F', 'the Aurora administrator cannot add a customer to Boréal (refused CSIAD0047) and the Boréal list is unchanged', wr.status >= 400 && (await entitled('boreal')).join() === c.USERS.customer.userName, { status: wr.status, messageId: wr.data && wr.data.messageId });
  const wp = await AA('put', `/v1.0/owner/applications/${st.apps.boreal.id}`, { name: B.boreal.appName, provisioning: {} });
  check('F', "the Aurora administrator cannot update Boréal's application (400)", wp.status >= 400, { status: wp.status, messageId: wp.data && wp.data.messageId });
  const polTry = await AA('put', `/v1.0/owner/applications/${st.apps.aurora.id}`, { name: B.aurora.appName, provisioning: {}, authPolicy: { id: st.policies.boreal.id } });
  const after = (await api('GET', `/appaccess/v1.0/applications/${st.apps.aurora.id}`)).data;
  check('F', "LIMIT: a brand administrator cannot change the brand's access policy: the owner API takes only name + provisioning, and an authPolicy in the body changes nothing", String(after.authPolicy.id) === st.policies.aurora.id, { putStatus: polTry.status, policyStillAurora: String(after.authPolicy.id) === st.policies.aurora.id });
  for (const [label, m, p, body, hdr] of [
    ['list all applications', 'get', '/v1.0/applications'], ['list access policies', 'get', '/v5.0/policyvault/accesspolicy'], ['create a group', 'post', '/v2.0/Groups', { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'], displayName: `${c.PREFIX}uc10-should-not-exist` }, { Accept: 'application/scim+json', 'Content-Type': 'application/scim+json' }],
    ['deactivate the Boréal customer', 'patch', `/v2.0/Users/${U.customer.id}`, { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'active', value: false }] }, { Accept: 'application/scim+json', 'Content-Type': 'application/scim+json' }],
  ]) {
    const r = await AA(m, p, body, hdr);
    check('F', `the Aurora administrator cannot ${label} (HTTP 403)`, r.status === 403, { status: r.status, messageId: r.data && r.data.messageId });
  }
  const brandThemes = await AA('get', '/v1.0/branding/themes');
  note(`Aurora administrator on /v1.0/branding/themes: HTTP ${brandThemes.status}`);
  check('F', 'the Aurora administrator has no access to theme management unless given the tenant-wide "themedeveloper" role (LIMIT: that role has no brand scope)', brandThemes.status === 403, { status: brandThemes.status, note: 'themedeveloper has no brand scope: when granted it covers ALL themes' });
  const scimOwner = await AA('get', '/v2.0/Users?count=1', undefined, { Accept: 'application/scim+json' });
  const scimAdmin = await api('GET', '/v2.0/Users', { query: { count: 1 } });
  check('F', 'LIMIT: the application owner can READ the tenant user directory through SCIM (same total as the privileged client): users are not partitioned per brand', scimOwner.status === 200 && scimOwner.data.totalResults === scimAdmin.data.totalResults, { ownerTotal: scimOwner.data.totalResults, tenantTotal: scimAdmin.data.totalResults });

  // the delegated admin acts, the customer feels it at once
  console.log('  -- the Aurora administrator revokes, then restores, the Aurora-only customer; the effect is immediate');
  const rev = await AA('post', `/v1.0/owner/applications/${st.apps.aurora.id}/entitlements`, { deletions: [(await idem.listAppEntitlements(st.apps.aurora.id)).find((e) => e.assignee.subjectId === U.auroraOnly.id).id] });
  const t0 = Date.now();
  const f1 = await new Browser().open(url('aurora', '/login?lang=en'), { username: c.USERS.auroraOnly.userName, password: U.auroraOnly.password });
  check('F', 'after the Aurora administrator revokes the customer, Aurora refuses them (CSIAQ0279E) at once', rev.status === 200 && f1.status === 401 && /CSIAQ0279E/.test(f1.html), { revokeStatus: rev.status, loginStatus: f1.status, afterMs: Date.now() - t0 });
  const gr = await AA('post', `/v1.0/owner/applications/${st.apps.aurora.id}/entitlements`, { additions: [{ assignee: { subjectId: U.auroraOnly.id, subjectType: 'user' }, grantType: 'DISC' }] });
  const f2 = await new Browser().open(url('aurora', '/login?lang=en'), { username: c.USERS.auroraOnly.userName, password: U.auroraOnly.password });
  check('F', 'after the administrator restores the entitlement the customer signs in again', gr.status === 200 && signedIn(f2), { grantStatus: gr.status });
  console.log('  -- the Boréal administrator removes the shared customer from Boréal only');
  const brevId = (await idem.listAppEntitlements(st.apps.boreal.id)).find((e) => e.assignee.subjectId === U.customer.id).id;
  const brev = await BA('post', `/v1.0/owner/applications/${st.apps.boreal.id}/entitlements`, { deletions: [brevId] });
  const g1 = await new Browser().open(url('boreal', '/login'), creds('customer'));
  const g2 = await new Browser().open(url('aurora', '/login?lang=en'), creds('customer'));
  check('F', 'the shared customer is refused at Boréal but still signs in to Aurora: one account, per-brand access', brev.status === 200 && g1.status === 401 && /CSIAQ0279E/.test(g1.html) && signedIn(g2), { borealStatus: g1.status, auroraSignedIn: signedIn(g2) });
  const bgr = await BA('post', `/v1.0/owner/applications/${st.apps.boreal.id}/entitlements`, { additions: [{ assignee: { subjectId: U.customer.id, subjectType: 'user' }, grantType: 'DISC' }] });
  const g3b = new Browser();
  const g3 = await g3b.open(url('boreal', '/login'), creds('customer'));
  const g4 = g3.kind === 'totp' ? await g3b.post(mfaAction(g3), { otp: await totpCode(), operation: 'verify' }) : g3;
  check('F', 'the Boréal administrator restores them and the customer is back in (password, then the brand second factor)', bgr.status === 200 && signedIn(g4), { grantStatus: bgr.status });
  check('F', 'entitlements end exactly as setup left them', (await entitled('aurora')).length === 2 && (await entitled('boreal')).join() === c.USERS.customer.userName, { aurora: await entitled('aurora'), boreal: await entitled('boreal') });
  await clean(); dropPortalSessions();

  // ================================================================================================================
  console.log('\nG. Custom IdP domains and tenancy: what the tenant exposes');
  const host = new URL(BASE).hostname;
  const ip = (await dns.promises.lookup(host, { family: 4 })).address;
  const viaHost = (h) => new Promise((res) => {
    const req = https.request({ host: ip, servername: host, path: '/oidc/endpoint/default/.well-known/openid-configuration', method: 'GET', headers: { Host: h } }, (r) => {
      let b = ''; r.on('data', (d) => { b += d; }); r.on('end', () => { let iss = null; try { iss = JSON.parse(b).issuer; } catch (e) { /* not json */ } res({ status: r.statusCode, issuer: iss }); });
    });
    req.on('error', (e) => res({ status: 0, error: e.code })); req.end();
  });
  const custom = await viaHost('idp.aurora.example'); const own = await viaHost(host);
  check('G', 'LIMIT: a brand host name that is not registered on the tenant is refused by the edge (HTTP 400): idp.<brand>.com cannot be made up on the client side', custom.status === 400 && own.status === 200 && own.issuer === `${BASE}/oidc/endpoint/default`, { unregisteredHostStatus: custom.status, tenantHostStatus: own.status });
  const sub = await api('GET', '/v1.0/identitysources/subtenants', { quiet: true });
  check('G', 'LIMIT: sub-tenants (separate directory and admin per brand) are a reseller offering, not available here (405 CSIAG0746E)', sub.status === 405 && sub.data && sub.data.messageId === 'CSIAG0746E', { status: sub.status, messageId: sub.data && sub.data.messageId });
  const snd = await api('GET', '/config/v1.0/email-domain-auth', { quiet: true });
  check('G', 'LIMIT: per-brand sender domains are not enabled on this tenant (400 CSIAP3564E "Sender customization is not enabled")', snd.status === 400 && snd.data && snd.data.messageId === 'CSIAP3564E', { status: snd.status, messageId: snd.data && snd.data.messageId });
  const props = await api('GET', '/v2.0/tenant/properties', { quiet: true });
  check('G', 'tenant properties list one allowed target host: the tenant itself (no brand domains configured)', props.status === 200 && (props.data.targetUrlAllowedHostV2 || []).length === 1, { hosts: (props.data.targetUrlAllowedHostV2 || []).map((h) => h.targetUrl) });
  note('Custom IdP domains (idp.brand1.com) are a sales / IBM configuration [DOCS]: not demonstrable on this tenant. See README for the question to ask IBM.');

  // ================================================================================================================
  console.log('\nH. Consent wording: what a brand controls today');
  const tmpName = `${c.PREFIX}uc10-consent-aurora`;
  const tmp = await idem.ensureDcrClient(tmpName, {
    redirect_uris: [`${c.origin(B.aurora)}/callback`], grant_types: ['authorization_code'], response_types: ['code'], all_users_entitled: true,
    enforce_pkce: true, consent_action: 'always_prompt', scope: 'openid profile email', client_uri: 'https://aurora.example/', policy_uri: 'https://aurora.example/privacy', tos_uri: 'https://aurora.example/terms',
  });
  const consent = {};
  for (const lang of ['en', 'fr']) {
    const br = new Browser();
    let p = await br.get(`${BASE}/v1.0/endpoint/default/authorize?${new URLSearchParams({ client_id: tmp.clientId, response_type: 'code', redirect_uri: `${c.origin(B.aurora)}/callback`, scope: 'openid profile email', state: 'uc10-state-123', nonce: 'uc10-nonce-123', ui_locales: lang, ...pkce() })}`);
    const meta = JSON.parse(p.html.match(/id="idSourcesMeta" content='([^']*)'/)[1].replace(/\\u003d/g, '=').replace(/\\u0026/g, '&'));
    p = await br.post(meta.find((s) => s.type === 'CLOUDDIRECTORY').loginUrl, { ...{ username: c.USERS.customer.userName, password: U.customer.password }, operation: 'verify', error_redirect_support: 'true' });
    consent[lang] = { kind: br.classify(p), text: text(p.html).slice(0, 260), names: p.html.includes(tmpName), brandUri: /aurora\.example/.test(p.html) };
  }
  check('H', 'the consent page is shown per application, in the requested language, and names the application (client_name)', consent.en.kind === 'consent' && consent.fr.kind === 'consent' && consent.en.names && consent.en.text !== consent.fr.text, { en: consent.en.text.slice(0, 120), fr: consent.fr.text.slice(0, 120) });
  check('H', "LIMIT: client_uri / policy_uri / tos_uri given at registration do NOT appear on the consent page: brand-specific consent wording and legal links need the brand THEME", !consent.en.brandUri, { brandUriShown: consent.en.brandUri });
  await idem.deleteApplicationsByPrefix(tmpName);

  // ================================================================================================================
  console.log('\nI. Brand themes (look, French and English strings, legal text, support links)');
  let blocked = 0; const built = {};
  for (const b of c.BRAND_LIST) {
    const out = themes.build(b);
    const reg = await themes.register(b, out.zip);
    if (reg.blocked) blocked++;
    const cssHas = execFileSync('unzip', ['-p', out.zip, 'templates/common/page_components/default/page_style.css']).toString().includes(b.colour);
    const fr = execFileSync('unzip', ['-p', out.zip, 'templates/common/labels/fr/template_labels.properties']).toString();
    const en = execFileSync('unzip', ['-p', out.zip, 'templates/common/labels/default/template_labels.properties']).toString();
    const loginHtml = execFileSync('unzip', ['-p', out.zip, 'templates/authentication/login/identity_source/identity_source_selection/default/combined_login_selection.html']).toString();
    built[b.key] = {
      bytes: out.bytes, register: reg.status, messageId: reg.messageId,
      content: cssHas && fr.includes(b.text.fr.legal) && en.includes(b.text.en.legal) && fr.includes(`$LOGIN_TITLE$=${b.text.fr.signIn} - ${b.name}`) && loginHtml.includes('$BRAND_SUPPORT_URL$') && fs.existsSync(out.zip),
    };
  }
  check('I', 'a theme package per brand is built from the repo theme: brand colour, logo, French and English legal text, support link, login title', built.aurora.content && built.boreal.content, built);
  check('I', 'LIMIT: registering the themes is refused on this trial (403 CSIAZ3060E for both): the packages are READY, NOT APPLIED. IBM must enable branding', blocked === 2 && built.aurora.register === 403 && built.boreal.register === 403, { aurora: built.aurora.register, boreal: built.boreal.register });
  note('Until branding is enabled the Verify login pages carry IBM styling (see README: what the audience sees today).');

  servers.forEach((s) => s.close());
  await clean();
  const failed = results.filter((r) => !r.pass);
  failed.forEach((r) => console.log(`  FAIL  ${r.scenario}: ${r.title}`));
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  console.log('evidence:', ev.save({ passed: results.length - failed.length, total: results.length }));
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error(e.stack || e.message || e); process.exit(2); });

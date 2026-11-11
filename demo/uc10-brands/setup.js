'use strict';
// UC-10 setup. Idempotent: safe to run any number of times.
//   node demo/uc10-brands/setup.js
// Creates on the tenant (everything named ifc-demo-uc10-*):
//   - users         customer (both brands, + validated TOTP), aurora-only customer, one brand administrator per brand (passwords in demo/out/uc10.state.json)
//   - policies      -policy-aurora (password only), -policy-boreal (passkey first, authenticator-app fallback)
//   - applications  -aurora, -boreal   one OIDC app per brand (dynamic registration, PKCE), own policy, all_users_entitled:false (only entitled customers),
//                                      owners = that brand's administrator (delegated admin scoped to that one application)
//                   -admin-console     password-grant client, used only to obtain the brand administrators' own tokens
//   - entitlements  customer -> both brands, aurora-only -> Aurora
//   - themes        builds the two brand theme ZIPs and TRIES to register them (refused on the trial, 403 CSIAZ3060E [LIVE])
const idem = require('../lib/idempotent');
const { api } = require('../lib/verify');
const themes = require('./themes');
const c = require('./common');

const PW_APP_BODY = { grant_types: ['password'], response_types: ['code'], all_users_entitled: true, scope: 'openid', redirect_uris: ['http://localhost:4199/unused'] };

async function main() {
  const prev = c.state.read() || {};
  const out = { users: {}, policies: {}, apps: {}, themes: {} };

  // ---- users ----
  for (const [k, u] of Object.entries(c.USERS)) {
    const p = (prev.users || {})[k];
    let existing = await idem.findUser(u.userName);
    if (existing && !(p && p.id === existing.id && p.password)) { await idem.deleteUser(existing.id); existing = null; console.log(`User         ${u.userName}  password unknown (no state): recreating`); }
    const password = existing ? p.password : c.newUserCredential();
    const { user, created } = await idem.ensureUser({ userName: u.userName, email: u.email, given: u.given, family: u.family, password });
    out.users[k] = { id: user.id, userName: u.userName, password };
    console.log(`User         ${u.userName}  ${created ? 'created' : 'exists'}  id=${user.id}`);
  }

  // ---- the customer's second factor (Boréal's fallback). A TOTP enrolment only counts at login once validated [LIVE] ----
  const cu = out.users.customer;
  const t = await idem.ensureTotp(cu.id, 'IFC UC-10 customer', prev.users && prev.users.customer && prev.users.customer.id === cu.id ? prev.totp : null);
  out.totp = { id: t.id, secret: t.secret };
  if (prev.totpLastWindow && !t.created) out.totpLastWindow = prev.totpLastWindow;
  c.state.write({ ...out, apps: prev.apps || {} });
  const l = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${cu.id}"` } });
  const validated = ((l.data && l.data.totp) || []).some((e) => e.id === t.id && e.validated);
  if (!validated) {
    const code = await require('../lib/totp').totpPlayer(c.state).next();
    const v = await api('POST', `/v2.0/factors/totp/${t.id}`, { body: { otp: code.code } });
    if (v.status !== 204) throw new Error(`TOTP validation failed: HTTP ${v.status} cid=${v.cid}`);
  }
  out.totpLastWindow = (c.state.read() || {}).totpLastWindow || out.totpLastWindow;
  console.log(`TOTP         ${t.created ? 'enrolled' : 'exists  '} id=${t.id}  validated ${validated ? '(already)' : '(now, HTTP 204)'}`);

  // ---- brand policies ----
  for (const [k, p] of Object.entries(c.POLICIES)) {
    const r = await idem.ensurePolicy(p.name, p.description, c.policyRules(p));
    out.policies[k] = { id: r.id, name: p.name };
    console.log(`Policy       ${p.name}  ${r.created ? 'created' : r.updated ? 'updated' : 'exists'}  id=${r.id}  (${p.action}, ${p.authnMethods.join('+')})`);
  }

  // ---- theme packages (built offline; registration is blocked on the trial) ----
  for (const b of c.BRAND_LIST) {
    const built = themes.build(b);
    const reg = await themes.register(b, built.zip);
    out.themes[b.key] = { zip: built.zip, bytes: built.bytes, status: reg.status, blocked: reg.blocked, id: reg.id || null, messageId: reg.messageId };
    console.log(`Theme        ${b.themeName}  zip ${built.bytes} bytes  register: HTTP ${reg.status}${reg.blocked ? ' (branding not enabled on this tenant: ZIP is READY, not APPLIED)' : ''}`);
  }

  // ---- one OIDC application per brand ----
  for (const b of c.BRAND_LIST) {
    const pol = out.policies[b.policy];
    const reg = await idem.ensureDcrClient(b.appName, {
      redirect_uris: [`${c.origin(b)}/callback`], grant_types: ['authorization_code'], response_types: ['code'], all_users_entitled: false,
      enforce_pkce: true, consent_action: 'never_prompt', scope: 'openid profile email', access_policy: pol.id, post_logout_redirect_uris: [`${c.origin(b)}/`],
    }, (prev.apps || {})[b.key]);
    await idem.updateApplication(b.appName, (app) => {
      app.authPolicy = { id: pol.id };
      app.description = b.text[b.defaultLocale].tagline;
      app.owners = [out.users[b.adminUser].id]; // delegated admin: this brand's administrator owns this application only [LIVE]
      if (out.themes[b.key].id) app.customization = { themeId: out.themes[b.key].id }; // NOT executed so far: needs branding enabled
    });
    out.apps[b.key] = { clientId: reg.clientId, clientSecret: reg.clientSecret, registrationUri: reg.registrationUri, registrationToken: reg.registrationToken, id: await idem.appIdOf(b.appName) };
    console.log(`Application  ${b.appName}  ${reg.created ? 'created' : 'exists'}  clientId=${reg.clientId}  policy=${pol.name}  owner=${b.adminUser}`);
  }

  // ---- who belongs to which brand (direct user entitlements; a group entitlement did NOT gate sign-in [LIVE]) ----
  const wants = { aurora: [out.users.customer.id, out.users.auroraOnly.id], boreal: [out.users.customer.id] };
  for (const b of c.BRAND_LIST) {
    const want = wants[b.key];
    for (const uid of want) await idem.ensureAppEntitlement(out.apps[b.key].id, uid);
    for (const e of await idem.listAppEntitlements(out.apps[b.key].id)) if (!want.includes(e.assignee.subjectId)) await idem.removeAppEntitlement(out.apps[b.key].id, e.assignee.subjectId);
    console.log(`Entitlement  ${b.appName}  customers entitled: ${(await idem.listAppEntitlements(out.apps[b.key].id)).length}`);
  }

  // ---- console client for the brand administrators' own tokens ----
  const cc = await idem.ensureDcrClient(c.CONSOLE_APP, PW_APP_BODY, prev.console);
  out.console = { clientId: cc.clientId, clientSecret: cc.clientSecret, registrationUri: cc.registrationUri, registrationToken: cc.registrationToken };
  console.log(`Application  ${c.CONSOLE_APP}  ${cc.created ? 'created' : 'exists'}  (password grant, brand administrators only)`);

  c.state.write(out);
  console.log(`\nState saved (secrets stay local): ${c.state.file}`);
  console.log('Next: node demo/uc10-brands/run.js   |   browser demo: node demo/uc10-brands/serve.js');
}

main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });

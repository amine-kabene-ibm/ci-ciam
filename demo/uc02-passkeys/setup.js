'use strict';
// UC-02 setup. Idempotent: safe to run any number of times.
//   node demo/uc02-passkeys/setup.js [--sms-url https://<public host>/sms]
// Creates on the tenant (everything named ifc-demo-uc02-*):
//   - users         alice (passkey customer: enrolls a passkey later), bob (no passkey: fallback customer). Both have a validated authenticator app (TOTP).
//                   bob's e-mail is a real disposable mailbox (mail.tm), so the e-mail OTP is the real Verify e-mail. Passwords/secrets: demo/out/uc02.state.json
//   - policies      -policy-aal1-password, -policy-aal2-otp, -policy-aal3-passkey   (the "required AAL" is a policy)
//   - applications  -app-aal1 / -aal2 / -aal3   one OIDC app per assurance level (code + PKCE), each bound to its policy
//                   -app-console   password-grant client: lets a script act as the signed-in customer
//   - SMS gateway   only with --sms-url: webhook (external_sms) + SMS provider pointing at IFC's own gateway. While enabled, the tenant's SMS OTP goes to that URL.
const idem = require('../lib/idempotent');
const { api } = require('../lib/verify');
const c = require('./common');

const PW_APP_BODY = { grant_types: ['password'], response_types: ['code'], all_users_entitled: true, scope: 'openid', redirect_uris: ['http://localhost:4199/unused'] };
const smsUrl = (() => { const i = process.argv.indexOf('--sms-url'); return i > 0 ? process.argv[i + 1] : null; })();

async function main() {
  const prev = c.state.read() || {};
  const out = { users: {}, policies: {}, apps: {} };

  for (const [k, u] of Object.entries(c.USERS)) {
    const p = (prev.users || {})[k];
    let existing = await idem.findUser(u.userName);
    if (existing && !(p && p.id === existing.id && p.password)) { await idem.deleteUser(existing.id); existing = null; console.log(`User         ${u.userName}  password unknown (no state): recreating`); }
    const password = existing ? p.password : c.newUserCredential();
    let inbox = existing && p.inbox;
    if (k === 'bob' && !inbox) inbox = await c.createInbox();
    const email = inbox ? inbox.address : `uc02.${k}@ifc-demo.invalid`;
    const { user, created } = await idem.ensureUser({ userName: u.userName, email, given: u.given, family: u.family, password });
    const prevTotp = existing && p.totp && p.id === user.id ? p.totp : null;
    const t = await idem.ensureTotp(user.id, `IFC UC-02 ${k}`, prevTotp);
    out.users[k] = { id: user.id, userName: u.userName, password, email, ...(inbox ? { inbox } : {}), totp: { id: t.id, secret: t.secret }, totpLastWindow: t.created ? 0 : p.totpLastWindow || 0 };
    c.state.write({ ...prev, ...out });
    const l = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${user.id}"` } });
    const validated = ((l.data && l.data.totp) || []).some((e) => e.id === t.id && e.validated);
    if (!validated) { // a TOTP enrolment only counts at login once validated [LIVE]
      const code = await require('../lib/totp').totpPlayer(c.userTotpState(k)).next();
      const v = await api('POST', `/v2.0/factors/totp/${t.id}`, { body: { otp: code.code } });
      if (v.status !== 204) throw new Error(`TOTP validation failed: HTTP ${v.status} cid=${v.cid}`);
    }
    console.log(`User         ${u.userName}  ${created ? 'created' : 'exists '} id=${user.id}  TOTP ${t.created ? 'enrolled' : 'exists'}, validated ${validated ? '(already)' : '(now, HTTP 204)'}${inbox ? '  mailbox ' + inbox.address : ''}`);
  }
  out.users.alice.passkeys = (await idem.listFidoRegistrations(out.users.alice.id)).length;

  for (const l of c.LEVEL_LIST) {
    const r = await idem.ensurePolicy(l.policy, l.description, c.policyRules(l));
    out.policies[l.key] = { id: r.id, name: l.policy };
    console.log(`Policy       ${l.policy}  ${r.created ? 'created' : r.updated ? 'updated' : 'exists'}  id=${r.id}  (${l.action}, ${l.authnMethods.join('+')})`);
  }

  for (const l of c.LEVEL_LIST) {
    const pol = out.policies[l.key];
    const reg = await idem.ensureDcrClient(l.app, {
      redirect_uris: [`${c.origin(l)}/callback`], grant_types: ['authorization_code'], response_types: ['code'], all_users_entitled: true,
      enforce_pkce: true, consent_action: 'never_prompt', scope: 'openid profile email', access_policy: pol.id,
    }, (prev.apps || {})[l.key]);
    await idem.updateApplication(l.app, (app) => { app.authPolicy = { id: pol.id }; app.description = l.title; });
    out.apps[l.key] = { clientId: reg.clientId, clientSecret: reg.clientSecret, registrationUri: reg.registrationUri, registrationToken: reg.registrationToken, id: await idem.appIdOf(l.app) };
    console.log(`Application  ${l.app}  ${reg.created ? 'created' : 'exists '} clientId=${reg.clientId}  policy=${l.policy}`);
  }
  const cc = await idem.ensureDcrClient(c.CONSOLE_APP, PW_APP_BODY, prev.console);
  out.console = { clientId: cc.clientId, clientSecret: cc.clientSecret, registrationUri: cc.registrationUri, registrationToken: cc.registrationToken };
  console.log(`Application  ${c.CONSOLE_APP}  ${cc.created ? 'created' : 'exists '} (password grant, acts as the signed-in customer)`);

  if (smsUrl) {
    const g = await idem.ensureSmsGateway(c.SMS_NAME, smsUrl);
    out.sms = { url: smsUrl.replace(/\/\/([^/]{4})[^/]*/, '//$1...'), webhookId: g.webhookId, providerId: g.providerId };
    console.log(`SMS gateway  ${c.SMS_NAME}  ${g.created ? 'created' : 'exists '} webhook+provider enabled -> ${out.sms.url}  (SMS OTP now goes to IFC's gateway)`);
  }
  c.state.write(out);
  console.log(`\nState saved (secrets stay local): ${c.state.file}`);
  console.log('Next: node demo/uc02-passkeys/run.js   |   browser demo: node demo/uc02-passkeys/serve.js');
}

main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });

'use strict';
// UC-07 setup. Idempotent: safe to run any number of times.
//   node demo/uc07-handoff/setup.js
// Creates on the tenant:
//   - user        ifc-demo-uc07-marie        the policyholder (password kept in demo/out/uc07.state.json, gitignored; e-mail = presenter mailbox)
//   - TOTP        for Marie                  plays "the code generator in the app" for the sensitive-request step-up
//   - API client  ifc-demo-uc07-ccaas        5 entitlements: the voicebot's own identity (the admin client has 165)
//   - STS client  ifc-demo-uc07-ccaas-sts    the CCaaS validates app tokens (introspection) and exchanges them (RFC 8693), 300 s tokens
//   - application ifc-demo-uc07-mobile-app   dynamic-registration client with the password grant: plays the mobile app for scripted logins
const idem = require('../lib/idempotent');
const c = require('./common');

const mask = (e) => e.replace(/^(.).*(@.*)$/, '$1***$2');

async function main() {
  const prev = c.state.read() || {};
  const out = {};

  const cc = await idem.ensureApiClient(c.CCAAS_CLIENT, c.CCAAS_ENTITLEMENTS);
  console.log(`API client   ${c.CCAAS_CLIENT}  ${cc.created ? 'created' : 'exists'}  (${cc.entitlements.length} entitlements)`);
  out.ccaas = { clientId: cc.clientId, clientSecret: cc.clientSecret, entitlements: cc.entitlements };

  // The user's password is only known at creation. If we lost it (state deleted), recreate the user.
  const mailbox = await c.resolveMailbox();
  let existing = await idem.findUser(c.USER_NAME);
  if (existing && !(prev.user && prev.user.id === existing.id && prev.user.password)) {
    await idem.deleteUser(existing.id);
    existing = null;
    console.log('User         password unknown (no state): recreating the user');
  }
  const credential = existing ? prev.user.password : c.newUserCredential();
  const { user, created } = await idem.ensureUser({ userName: c.USER_NAME, email: mailbox, given: c.customer.given, family: c.customer.family, password: credential });
  console.log(`User         ${c.USER_NAME}  ${created ? 'created' : 'exists'}  id=${user.id}  mailbox=${mask(mailbox)}`);
  out.user = { id: user.id, userName: c.USER_NAME, password: credential };

  const t = await idem.ensureTotp(user.id, `Intact (${c.customer.policyNumber})`, prev.user && prev.user.id === user.id ? prev.totp : null);
  console.log(`TOTP         ${t.created ? 'enrolled' : 'exists  '}  id=${t.id}`);
  out.totp = { id: t.id, secret: t.secret };
  if (prev.totpLastWindow && !t.created) out.totpLastWindow = prev.totpLastWindow;

  const stsSecret = prev.sts && prev.sts.secret ? prev.sts.secret : `Sts-${c.randomSecret(18)}`;
  const sts = await idem.ensureStsClient(c.STS_CLIENT, { secret: stsSecret, accessTokenLifetime: c.VOICE_TOKEN_TTL_SEC });
  console.log(`STS client   ${c.STS_CLIENT}  ${sts.created ? 'created' : 'exists'}  clientId=${sts.clientId}  token lifetime ${c.VOICE_TOKEN_TTL_SEC} s`);
  out.sts = { clientId: sts.clientId, secret: stsSecret };

  const app = await idem.ensureDcrClient(c.APP_CLIENT, {
    redirect_uris: ['https://localhost/ifc-demo-uc07/cb'], grant_types: ['password'], all_users_entitled: true, scope: 'openid',
  }, prev.app);
  console.log(`Application  ${c.APP_CLIENT}  ${app.created ? 'created' : 'exists'}  clientId=${app.clientId}  (password grant, plays the mobile app)`);
  out.app = { clientId: app.clientId, clientSecret: app.clientSecret, registrationUri: app.registrationUri, registrationToken: app.registrationToken };

  c.state.write(out);
  console.log(`\nState saved (secrets stay local): ${c.state.file}`);
  console.log('Next: node demo/uc07-handoff/run.js   |   browser path: see demo/uc07-handoff/README.md');
}

main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });

'use strict';
// UC-08 setup. Idempotent: safe to run any number of times.
//   node demo/uc08-sso/setup.js                                    front-channel logout (works with no tunnel)
//   node demo/uc08-sso/setup.js --backchannel https://<public>     back-channel logout (the tenant POSTs to <public>/bc/<app>; needs a tunnel)
// Creates on the tenant:
//   - groups       ifc-demo-uc08-brokers / ifc-demo-uc08-consumers          the two personas (B2B / B2C)
//   - users        ifc-demo-uc08-broker (+ TOTP, validated), ifc-demo-uc08-client    passwords kept in demo/out/uc08.state.json (gitignored)
//   - policies     ifc-demo-uc08-policy-standard / -high                    brokers: second factor; policyholders: password only
//   - applications ifc-demo-uc08-rp-portal / -claims / -quote               three OIDC apps (dynamic registration) with PKCE, per-app policy,
//                                                                           per-app token lifetime and the logout settings
const idem = require('../lib/idempotent');
const { api } = require('../lib/verify');
const c = require('./common');

const argv = process.argv.slice(2);
const bcIx = argv.indexOf('--backchannel');
const mode = bcIx >= 0 ? 'back' : 'front';
const backchannelBase = bcIx >= 0 ? argv[bcIx + 1] : null;
if (mode === 'back' && !/^https:\/\/[^/]+/.test(backchannelBase || '')) { console.error('--backchannel needs a public https URL, e.g. https://abc.trycloudflare.com'); process.exit(1); }

async function main() {
  const prev = c.state.read() || {};
  const out = { mode, backchannelBase, users: {}, groups: {}, policies: {}, apps: {} };

  for (const [k, gname] of [['brokers', c.GROUP_BROKERS], ['consumers', c.GROUP_CONSUMERS]]) {
    const { group, created } = await idem.ensureGroup(gname);
    out.groups[k] = { id: group.id, name: gname };
    console.log(`Group        ${gname}  ${created ? 'created' : 'exists'}  id=${group.id}`);
  }

  for (const [k, u] of Object.entries(c.USERS)) {
    const p = (prev.users || {})[k];
    let existing = await idem.findUser(u.userName);
    if (existing && !(p && p.id === existing.id && p.password)) { await idem.deleteUser(existing.id); existing = null; console.log(`User         ${u.userName}  password unknown (no state): recreating`); }
    const password = existing ? p.password : c.newUserCredential();
    const { user, created } = await idem.ensureUser({ userName: u.userName, email: u.email, given: u.given, family: u.family, password });
    await idem.ensureGroupMember(out.groups[u.group === c.GROUP_BROKERS ? 'brokers' : 'consumers'].id, user.id);
    out.users[k] = { id: user.id, userName: u.userName, password };
    console.log(`User         ${u.userName}  ${created ? 'created' : 'exists'}  id=${user.id}  group ${u.group}`);
  }

  // The broker's second factor. A TOTP enrolment only counts at login once it has been validated with one code [LIVE]
  // (an unvalidated one gives CSIAH0640E "None of the permitted authentication factors are configured").
  const b = out.users.broker; const pb = (prev.users || {}).broker;
  const t = await idem.ensureTotp(b.id, 'IFC Broker Portal', pb && pb.id === b.id ? prev.totp : null);
  out.totp = { id: t.id, secret: t.secret };
  if (prev.totpLastWindow && !t.created) out.totpLastWindow = prev.totpLastWindow;
  c.state.write({ ...out, apps: prev.apps || {} });
  const l = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${b.id}"` } });
  const validated = ((l.data && l.data.totp) || []).some((e) => e.id === t.id && e.validated);
  if (!validated) {
    const code = await require('../lib/totp').totpPlayer(c.state).next();
    const v = await api('POST', `/v2.0/factors/totp/${t.id}`, { body: { otp: code.code } });
    if (v.status !== 204) throw new Error(`TOTP validation failed: HTTP ${v.status} cid=${v.cid}`);
  }
  console.log(`TOTP         ${t.created ? 'enrolled' : 'exists  '} id=${t.id}  validated ${validated ? '(already)' : '(now, HTTP 204)'}`);
  out.totpLastWindow = (c.state.read() || {}).totpLastWindow || out.totpLastWindow;

  for (const [k, p] of Object.entries(c.POLICIES)) {
    const r = await idem.ensurePolicy(p.name, p.description, c.policyRules(p));
    out.policies[k] = { id: r.id, name: p.name, action: p.action };
    console.log(`Policy       ${p.name}  ${r.created ? 'created' : r.updated ? 'updated' : 'exists'}  id=${r.id}  (brokers: ${p.action})`);
  }

  for (const a of c.APPS) {
    const pol = out.policies[a.policy];
    const lc = c.logoutConfig(a, out);
    const reg = await idem.ensureDcrClient(a.name, {
      redirect_uris: [`${c.origin(a)}/callback`], grant_types: ['authorization_code'], response_types: ['code'], all_users_entitled: true,
      enforce_pkce: true, consent_action: 'never_prompt', scope: 'openid profile email', access_policy: pol.id,
      post_logout_redirect_uris: [`${c.origin(a)}/`],
    }, (prev.apps || {})[a.key]);
    // Settings the registration call does not take, or that must follow a mode change: applied in place (GET, change, PUT).
    await idem.updateApplication(a.name, (app) => {
      const oc = app.providers.oidc.properties;
      oc.accessTokenExpiry = a.ttl; oc.sendAllKnownUserAttributes = 'true';
      Object.assign(oc.additionalConfig, lc);
      app.authPolicy = { id: pol.id };
    });
    out.apps[a.key] = { clientId: reg.clientId, clientSecret: reg.clientSecret, registrationUri: reg.registrationUri, registrationToken: reg.registrationToken, port: a.port };
    console.log(`Application  ${a.name}  ${reg.created ? 'created' : 'exists'}  clientId=${reg.clientId}  policy=${pol.name}  token ${a.ttl} s  logout=${lc.logoutOption}`);
  }

  c.state.write(out);
  console.log(`\nState saved (secrets stay local): ${c.state.file}`);
  console.log('Next: node demo/uc08-sso/run.js   |   browser demo: node demo/uc08-sso/serve.js');
}

main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });

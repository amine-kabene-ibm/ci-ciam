'use strict';
// UC-03 setup (risk-aware account recovery, agent-assisted). Idempotent.
//   node demo/uc03-recovery/setup.js
// Creates on the tenant:
//   - tenant setting  hosted "Forgot password" ON (Cloud Directory identity source, property passwordResetEnabled) - OFF by default, restored by teardown
//   - api client      ifc-demo-uc03-recovery-console  (6 entitlements, measured; not the admin client)
//   - application     ifc-demo-uc03-portal            (DCR; the IFC customer portal: hosted login + forgot-password entry, scripted password grant)
//   - application     ifc-demo-uc03-signin            (DCR + access policy ifc-demo-uc03-risk-signin: TOTP step-up when the sign-in comes from outside the usual network)
//   - users           ifc-demo-uc03-sophie, ifc-demo-uc03-marc, each with its own disposable mailbox (mail.tm) so scripts can read the real Verify e-mails
//   - TOTP            Marc's authenticator, enrolled NOW (the "recent factor change" signal)
// Secrets and customer passwords stay local in demo/out/uc03.state.json (gitignored, mode 0600).
const crypto = require('crypto');
const axios = require('axios');
const { api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { totpPlayer } = require('../lib/totp');
const uc01 = require('../uc01-registration/common');
const c = require('./common');

const PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const mask = (e) => e.replace(/^(.).*(@.*)$/, '$1***$2');
const REDIRECT = `http://localhost:${c.PORT}/callback`;
const SIGNIN_POLICY = `${c.PREFIX}risk-signin`;
const POLICY_DESC = 'UC-03: step up to TOTP when the sign-in comes from outside the usual network (ipAddress condition)';
const SIGNIN_APP = `${c.PREFIX}signin`;
const WHOLE_INTERNET = ['0.0.0.0/1', '128.0.0.0/1']; // "nothing is outside the usual network" fallback when the public IP cannot be detected

// The customers' "usual network": the /24 this machine is on, so the demo shows no step-up here and a step-up from anywhere else.
async function usualNetwork() {
  try {
    const r = await axios.get('https://api.ipify.org', { timeout: 5000, validateStatus: () => true });
    const m = String(r.data).match(/^(\d+\.\d+\.\d+)\.\d+$/);
    if (r.status === 200 && m) return [`${m[1]}.0/24`];
  } catch (e) { /* fall through */ }
  return WHOLE_INTERNET;
}
const riskPolicyRules = (usual) => [
  { name: 'outside-usual-network', action: 'ACTION_MFA_ALWAYS', authnMethods: ['totp'], conditions: [{ type: 'ipAddress', opCode: 'NOMATCH', values: usual }] },
  { name: 'usual-network', action: 'ACTION_ALLOW', authnMethods: ['totp'], conditions: [] },
];

async function main() {
  const prev = c.state.read() || {};
  const out = { users: {} };
  console.log('UC-03 Setup (risk-aware account recovery, agent-assisted)\n');

  // 1. Hosted Forgot password: OFF by default on the tenant [LIVE]
  const sw = await idem.setHostedPasswordReset(true);
  console.log(`Tenant       hosted "Forgot password"          ${sw.changed ? 'switched ON' : 'already ON'} (Cloud Directory identity source, passwordResetEnabled=true)`);

  // 2. Agent console API client
  const agent = await idem.ensureApiClient(c.AGENT_CLIENT, c.AGENT_ENTITLEMENTS);
  out.agent = { id: agent.id, clientId: agent.clientId, clientSecret: agent.clientSecret };
  console.log(`API client   ${c.AGENT_CLIENT.padEnd(34)} ${agent.created ? 'created' : 'exists '}  entitlements=${agent.entitlements.join(',')}`);

  // 3. Customers, each with a disposable mailbox
  for (const [key, def] of Object.entries(c.CUSTOMERS)) {
    const old = prev.users && prev.users[key];
    // The hosted "Forgot password" limit (CSIAH0327I) sticks to the USER NAME for tens of minutes, even if the user is deleted and recreated [LIVE].
    // A fresh setup therefore picks a fresh name (kept in the state file), so teardown -> setup -> run is repeatable.
    const userName = (old && old.userName) || `${def.userName}-${crypto.randomBytes(2).toString('hex')}`;
    const existing = await idem.findUser(userName);
    let inbox = old && old.inbox && existing && old.id === existing.id ? await uc01.inboxLogin(old.inbox) : null;
    let password = existing && old && old.id === existing.id ? old.password : null;
    let id;
    if (!existing) {
      inbox = await uc01.createInbox(`${c.PREFIX}${key}-`);
      password = c.newPassword();
      id = (await idem.ensureUser({ userName, email: inbox.address, given: def.given, family: def.family, password })).user.id;
      console.log(`User         ${userName.padEnd(34)} created  id=${id}  mailbox=${mask(inbox.address)}`);
    } else {
      id = existing.id;
      if (!inbox) { // the state is gone: new mailbox, point the account at it, reset the password
        inbox = await uc01.createInbox(`${c.PREFIX}${key}-`);
        const r = await api('PATCH', `/v2.0/Users/${id}`, { body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'emails', value: [{ type: 'work', value: inbox.address }] }] } });
        if (r.status !== 204 && r.status !== 200) throw new Error(`repoint e-mail of ${def.userName}: HTTP ${r.status} cid=${r.cid}`);
        password = null;
      }
      // Always reset: a password replace is the only thing that clears a lock [LIVE], and a previous run may have left the account locked or the password changed.
      {
        password = c.newPassword();
        const r = await api('PATCH', `/v2.0/Users/${id}`, { headers: { usershouldnotneedtoresetpassword: 'true' }, body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'password', value: password }] } });
        if (r.status !== 204) throw new Error(`reset password of ${def.userName}: HTTP ${r.status} cid=${r.cid}`);
      }
      console.log(`User         ${userName.padEnd(34)} exists   id=${id}  mailbox=${mask(inbox.address)}`);
    }
    out.users[key] = { id, userName, password, inbox: { address: inbox.address, password: inbox.password } };
  }

  // 4. Marc's authenticator is (re-)enrolled now: its age IS the "recent factor change" signal, so it must be fresh each time
  const marc = out.users.marc;
  const t = await idem.ensureTotp(marc.id, 'IFC Marc Bouchard', null);
  out.totp = { id: t.id, secret: t.secret };
  c.state.write(out);
  const code = await totpPlayer(c.state).next();
  const v = await api('POST', `/v2.0/factors/totp/${t.id}`, { body: { otp: code.code } });
  if (v.status !== 204 && v.status !== 200) throw new Error(`validate TOTP: HTTP ${v.status} cid=${v.cid}`);
  out.totpLastWindow = c.state.read().totpLastWindow; // the player stored the window it just used
  console.log(`TOTP         enrolled for ${marc.userName} just now and validated (HTTP ${v.status})`);

  // 5. Portal stand-in and the sign-in app guarded by the risk policy
  const portal = await idem.ensureDcrClient(c.PORTAL_APP, {
    grant_types: ['authorization_code', 'password'], response_types: ['code'], all_users_entitled: true, consent_action: 'never_prompt', scope: 'openid', redirect_uris: [REDIRECT],
  }, prev.portal || null);
  out.portal = { clientId: portal.clientId, clientSecret: portal.clientSecret, registrationUri: portal.registrationUri, registrationToken: portal.registrationToken };
  console.log(`Application  ${c.PORTAL_APP.padEnd(34)} ${portal.created ? 'created' : 'exists '}  clientId=${portal.clientId}`);

  const signin = await idem.ensureDcrClient(SIGNIN_APP, {
    grant_types: ['authorization_code'], response_types: ['code'], all_users_entitled: true, consent_action: 'never_prompt', scope: 'openid', redirect_uris: [REDIRECT], enforce_pkce: false,
  }, prev.signin || null);
  out.signin = { clientId: signin.clientId, clientSecret: signin.clientSecret, registrationUri: signin.registrationUri, registrationToken: signin.registrationToken };
  const usual = await usualNetwork();
  const pol = await idem.ensurePolicy(SIGNIN_POLICY, POLICY_DESC, riskPolicyRules(usual));
  await idem.updateApplication(SIGNIN_APP, (app) => { app.authPolicy = { id: pol.id }; });
  out.policy = { id: pol.id, name: SIGNIN_POLICY, usualNetwork: usual };
  console.log(`Application  ${SIGNIN_APP.padEnd(34)} ${signin.created ? 'created' : 'exists '}  clientId=${signin.clientId}`);
  console.log(`Policy       ${SIGNIN_POLICY.padEnd(34)} ${pol.created ? 'created' : pol.updated ? 'updated' : 'exists '}  usual network=${usual.join(',')}`);

  c.state.write(out);
  // 6. A known-device baseline: one successful password sign-in each, from the device the customer "always uses"
  for (const u of Object.values(out.users)) {
    const s = await c.signIn(out.portal, u.userName, u.password, c.KNOWN_UA);
    console.log(`Baseline     ${u.userName.padEnd(34)} sign-in from the known device -> HTTP ${s.status}`);
    if (s.status !== 200) throw new Error(`baseline sign-in of ${u.userName} failed: HTTP ${s.status} ${String(s.data.error_description || s.data.error || '').slice(0, 120)}`);
  }

  c.state.write(out);
  console.log(`\nState saved (secrets kept local, mode 0600): ${c.state.file}`);
  console.log('Next: node demo/uc03-recovery/run.js       (all scenarios against the live tenant, about 5 minutes)');
  console.log('      node demo/uc03-recovery/serve.js     (recovery console on http://localhost:' + c.PORT + ')');
}

if (require.main === module) {
  main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });
}
module.exports = { main, riskPolicyRules, usualNetwork, SIGNIN_APP, SIGNIN_POLICY, POLICY_DESC, REDIRECT };

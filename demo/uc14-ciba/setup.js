'use strict';
// UC-14 setup (Policyholder authorizing a Call Center Agent via CIBA). Idempotent.
//   node demo/uc14-ciba/setup.js
// Creates on the tenant:
//   - application ifc-demo-uc14-agent-ciba  (OIDC, grant CIBA, poll mode, e-mail channel; admits entitled users only)
//   - application ifc-demo-uc14-portal      (DCR, password grant: stands in for the customer portal)
//   - api client  ifc-demo-uc14-agent-console (readUsers, manageUsers, readReports)
//   - users       ifc-demo-uc14-marie (entitled, e-mail = presenter mailbox) and ifc-demo-uc14-outsider (not entitled)
// Secrets and the customer password stay local in demo/out/uc14.state.json (gitignored, mode 0600).
const { api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const c = require('./common');

const mask = (e) => e.replace(/^(.).*(@.*)$/, '$1***$2');
const PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

async function main() {
  const prev = c.state.read() || {};
  const out = { users: {} };
  console.log('UC-14 Setup (CIBA agent-initiated authentication)\n');

  const mailbox = await c.resolveMailbox();

  // 1. CIBA application + 2. API client for the console
  const app = await idem.ensureCibaApp(c.CIBA_APP, { channels: ['email'] });
  out.app = { appId: app.appId, clientId: app.clientId, clientSecret: app.clientSecret, channels: app.channels };
  console.log(`Application  ${c.CIBA_APP.padEnd(34)} ${app.created ? 'created' : 'exists '}  clientId=${app.clientId}  channels=${app.channels.join('+')}`);

  const agent = await idem.ensureApiClient(c.AGENT_CLIENT, c.AGENT_ENTITLEMENTS);
  out.agent = { id: agent.id, clientId: agent.clientId, clientSecret: agent.clientSecret };
  console.log(`API client   ${c.AGENT_CLIENT.padEnd(34)} ${agent.created ? 'created' : 'exists '}  entitlements=${agent.entitlements.join(',')}`);

  // 3. Customers. The password is only known to us if it is in the state file; otherwise reset it (no history conflict: random value).
  for (const [key, def] of Object.entries(c.CUSTOMERS)) {
    const existing = await idem.findUser(def.userName);
    const kept = existing && prev.users && prev.users[key] && prev.users[key].id === existing.id ? prev.users[key].password : null;
    const password = kept || c.newPassword();
    let id;
    if (!existing) {
      const { user } = await idem.ensureUser({ userName: def.userName, email: mailbox, given: def.given, family: def.family, password });
      id = user.id;
      console.log(`User         ${def.userName.padEnd(34)} created  id=${id}  mailbox=${mask(mailbox)}`);
    } else {
      id = existing.id;
      if (!kept) {
        const r = await api('PATCH', `/v2.0/Users/${id}`, {
          headers: { usershouldnotneedtoresetpassword: 'true' },
          body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'password', value: password }] },
        });
        if (r.status !== 204) throw new Error(`reset password of ${def.userName}: HTTP ${r.status} cid=${r.cid}`);
      }
      console.log(`User         ${def.userName.padEnd(34)} exists   id=${id}${kept ? '' : '  (password reset, value unknown before)'}`);
    }
    if (def.entitled) await idem.ensureAppEntitlement(app.appId, id);
    out.users[key] = { id, userName: def.userName, password };
  }

  // 4. Portal stand-in (password grant), reused when its registration still resolves
  const portal = await idem.ensureDcrClient(c.PORTAL_APP, {
    grant_types: ['password'], all_users_entitled: true, scope: 'openid', response_types: ['code'],
    redirect_uris: ['http://localhost:4140/callback'], consent_action: 'never_prompt',
  }, prev.portal || null);
  out.portal = { clientId: portal.clientId, clientSecret: portal.clientSecret, registrationUri: portal.registrationUri, registrationToken: portal.registrationToken };
  console.log(`Application  ${c.PORTAL_APP.padEnd(34)} ${portal.created ? 'created' : 'exists '}  clientId=${portal.clientId}`);

  c.state.write(out);
  console.log(`\nState saved (secrets kept local, mode 0600): ${c.state.file}`);
  console.log('Next: node demo/uc14-ciba/run.js            (automated checks)');
  console.log('      node demo/uc14-ciba/run.js --approve  (adds the real e-mail approval: you read your mailbox)');
  console.log('      node demo/uc14-ciba/serve.js          (agent console on http://localhost:4140)');
}

if (require.main === module) {
  main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });
}

module.exports = { main };

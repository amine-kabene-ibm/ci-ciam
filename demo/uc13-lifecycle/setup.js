'use strict';
// UC-13 setup (Broker Identity Lifecycle & Immediate Revocation). Idempotent.
//   node demo/uc13-lifecycle/setup.js
// Creates on the tenant:
//   - application  ifc-demo-uc13-broker-portal (DCR password-grant client for broker sign-in)
//   - sts client   ifc-demo-uc13-resource-sts  (resource server token introspection)
//   - users        ifc-demo-uc13-broker-elena, ifc-demo-uc13-broker-marcus (SCIM users with enterprise attributes)
//   - webhook      ifc-demo-uc13-ops-webhook   (Verify notifications webhook)
// Secrets and credentials stay local in demo/out/uc13.state.json (gitignored, mode 0600).
const { api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const c = require('./common');

async function main() {
  const prev = c.state.read() || {};
  const out = { app: null, sts: null, users: {}, webhook: null };

  console.log('UC-13 Setup (Broker Lifecycle & Immediate Revocation)\n');

  // 1. Broker portal application (password grant)
  const app = await idem.ensureDcrClient(c.BROKER_APP, {
    grant_types: ['password'],
    all_users_entitled: true,
    scope: 'openid email profile',
    redirect_uris: ['http://localhost:4040/callback'],
    response_types: ['code'],
    consent_action: 'never_prompt',
  }, prev.app || null);
  out.app = {
    clientId: app.clientId,
    clientSecret: app.clientSecret,
    registrationUri: app.registrationUri,
    registrationToken: app.registrationToken,
  };
  console.log(`Application  ${c.BROKER_APP.padEnd(30)} ${app.created ? 'created' : 'exists'}  clientId=${app.clientId}`);

  // 2. STS client for resource introspection
  const stsSecret = (prev.sts && prev.sts.secret) || c.randomSecret(24);
  const sts = await idem.ensureStsClient(c.STS_CLIENT, {
    secret: stsSecret,
    accessTokenLifetime: 900,
    actorRequired: false,
  });
  out.sts = { clientId: sts.clientId, secret: stsSecret };
  console.log(`STS client   ${c.STS_CLIENT.padEnd(30)} ${sts.created ? 'created' : 'exists'}  clientId=${sts.clientId}`);

  // 3. Broker users via SCIM with enterprise extension attributes
  for (const [key, def] of Object.entries(c.BROKERS)) {
    const existing = await idem.findUser(def.userName);
    const keptPw = existing && prev.users && prev.users[key] && prev.users[key].id === existing.id && prev.users[key].password
      ? prev.users[key].password
      : null;
    if (existing && !keptPw) {
      await idem.deleteUser(existing.id);
      console.log(`User         ${def.userName} password unknown in state: recreated`);
    }
    const password = keptPw || c.newUserCredential();

    // Ensure user exists
    let userId;
    if (!existing || !keptPw) {
      const body = {
        schemas: [c.SCIM_CORE, c.SCIM_ENTERPRISE],
        userName: def.userName,
        name: { givenName: def.given, familyName: def.family, formatted: `${def.given} ${def.family}` },
        displayName: `${def.given} ${def.family}`,
        emails: [{ type: 'work', value: def.email, primary: true }],
        title: def.title,
        externalId: def.externalId,
        active: true,
        password,
        [c.SCIM_ENTERPRISE]: {
          department: def.department,
          employeeNumber: def.employeeNumber,
        },
      };
      const r = await api('POST', '/v2.0/Users', { body, headers: { usershouldnotneedtoresetpassword: 'true' } });
      if (r.status !== 201) throw new Error(`create broker ${def.userName}: HTTP ${r.status} cid=${r.cid}`);
      userId = r.data.id;
      console.log(`User         ${def.userName.padEnd(30)} created  id=${userId}  dept=${def.department}`);
    } else {
      userId = existing.id;
      // Ensure enterprise attributes and active status are in place
      const patchBody = {
        schemas: [c.SCIM_PATCH],
        Operations: [
          { op: 'replace', path: 'active', value: true },
          { op: 'add', path: `${c.SCIM_ENTERPRISE}:department`, value: def.department },
          { op: 'add', path: `${c.SCIM_ENTERPRISE}:employeeNumber`, value: def.employeeNumber },
          { op: 'add', path: 'title', value: def.title },
        ],
      };
      await api('PATCH', `/v2.0/Users/${userId}`, { body: patchBody, quiet: true });
      console.log(`User         ${def.userName.padEnd(30)} exists   id=${userId}  (synced active=true)`);
    }

    out.users[key] = {
      id: userId,
      userName: def.userName,
      email: def.email,
      given: def.given,
      family: def.family,
      title: def.title,
      department: def.department,
      employeeNumber: def.employeeNumber,
      externalId: def.externalId,
      password,
    };
  }

  // 4. Verify Webhook (Notifications)
  const webhookUrl = process.env.OPS_QUEUE_PUBLIC_URL || 'https://ifc-ops.example.com/webhook';
  const wh = await idem.ensureWebhook(c.WEBHOOK_NAME, {
    type: 'notification',
    purpose: ['notifications'],
    urls: [webhookUrl],
    notification: {
      enabled: true,
      interests: [{ name: 'user', clauses: [{ operation: 'include', key: 'action', value: '*' }] }],
    },
  });
  out.webhook = { id: wh.id, name: c.WEBHOOK_NAME, url: webhookUrl };
  console.log(`Webhook      ${c.WEBHOOK_NAME.padEnd(30)} ${wh.created ? 'created' : 'exists'}  id=${wh.id}`);

  // Save state
  c.state.write(out);
  console.log(`\nState saved (secrets kept local, mode 0600): ${c.state.file}`);
  console.log('Next: run the end-to-end test   node demo/uc13-lifecycle/run.js');
}

if (require.main === module) {
  main().catch((e) => {
    console.error('SETUP FAILED:', e.message);
    process.exit(1);
  });
}

module.exports = { main };

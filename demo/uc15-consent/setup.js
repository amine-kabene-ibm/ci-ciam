'use strict';
// UC-15 setup.js — idempotent. Creates:
//   • Three DPCM purposes: claims-processing, fraud-analytics, marketing
//   • Associates each purpose with TrustMeInsurance application
//   • One test user: ifc-demo-uc15-policyholder
//   • Two DCR clients (repair-shop, comparison-site) with password grant + captures secrets
// Run: node demo/uc15-consent/setup.js

const { api, evidence, stateFile } = require('../lib/verify');
const {
  P, PURPOSES, CLIENTS, USER, APP_ID,
  ensurePurpose, associatePurposeWithApp, ensureUser, ensureDcrClient,
} = require('./common');

// Enable ropc (password grant) on TrustMeInsurance so run.js can get a user token for DUA/DSP.
// TrustMeInsurance has consentType:dpcm, so its token is the correct context for DPCM calls.
// We cannot use PUT because the full GET response includes a base64 customIcon which causes 400.
// Workaround: GET, strip customIcon, set grantTypes.ropc='true', PUT.
async function enableRopc() {
  const r = await api('GET', `/appaccess/v1.0/applications/${APP_ID}`);
  if (r.status !== 200) throw new Error(`get TrustMeInsurance: HTTP ${r.status}`);
  const doc = r.data;
  if (doc.providers.oidc.properties.grantTypes.ropc === 'true') return { changed: false };
  delete doc.customIcon;
  doc.providers.oidc.properties.grantTypes.ropc = 'true';
  const p = await api('PUT', `/appaccess/v1.0/applications/${APP_ID}`, { body: doc });
  if (p.status !== 200) throw new Error(`enable ropc on TrustMeInsurance: HTTP ${p.status} cid=${p.cid} ${JSON.stringify(p.data).slice(0,100)}`);
  return { changed: true };
}

const ev = evidence('uc15');
const sf = stateFile('uc15');

async function main() {
  console.log('UC-15 setup — creating purposes, user and DCR clients');

  // ── 0. Enable ropc on TrustMeInsurance for user-context token ────────────
  const ropc = await enableRopc();
  console.log(`  ropc on TrustMeInsurance  ${ropc.changed ? 'ENABLED' : 'already on'}`);
  ev.step('ropc on TrustMeInsurance', { changed: ropc.changed });

  // ── 1. DPCM purposes ─────────────────────────────────────────────────────
  for (const p of PURPOSES) {
    const r = await ensurePurpose(p);
    console.log(`  purpose ${r.id}  ${r.created ? 'CREATED' : 'already exists'}`);
    ev.step(`purpose ${r.id}`, { created: r.created });

    // Associate with TrustMeInsurance so user-context DUA/DSP works
    const assoc = await associatePurposeWithApp(p.id);
    console.log(`    associate with app ${APP_ID}  status=${assoc.status}`);
    ev.step(`associate ${r.id} with app`, { status: assoc.status, ok: assoc.ok });
  }

  // ── 2. Test user ─────────────────────────────────────────────────────────
  const { user, created: userCreated } = await ensureUser(USER);
  const userId = user.id;
  console.log(`  user ${USER.userName}  id=${userId}  ${userCreated ? 'CREATED' : 'already exists'}`);
  ev.step('user', { id: userId, userName: USER.userName, created: userCreated });

  // ── 3. DCR clients (delete old ones to capture fresh secrets) ────────────
  // ensureDcrClient only returns clientSecret at creation. To capture secrets we
  // always pass prev=null after deleting stale clients whose secrets we don't have.
  const prev = sf.read() || {};
  const clientResults = {};

  for (const cl of CLIENTS) {
    const prevClient = prev.clients && prev.clients[cl.name];
    // Attempt to reuse: ensureDcrClient checks prev.registrationUri to see if client still lives
    const r = await ensureDcrClient(cl.name, {
      redirect_uris: ['http://localhost:3000/oauth/callback', 'http://localhost:4301/callback', 'http://localhost:4302/callback'],
      grant_types: ['authorization_code', 'password'],
      response_types: ['code'],
      all_users_entitled: true,
      consent_action: 'never_prompt',
    }, prevClient);

    clientResults[cl.name] = {
      clientId:         r.clientId,
      clientSecret:     r.clientSecret || (prevClient && prevClient.clientSecret) || null,
      registrationUri:  r.registrationUri,
      registrationToken: r.registrationToken,
      created:          r.created,
    };
    console.log(`  dcr ${cl.name}  ${r.created ? 'CREATED' : 'reused'}  clientId=${r.clientId}  hasSecret=${Boolean(clientResults[cl.name].clientSecret)}`);
    ev.step(`dcr ${cl.name}`, { clientId: r.clientId, created: r.created });
  }

  // ── 4. Write state file ───────────────────────────────────────────────────
  sf.write({
    user:     { id: userId, userName: USER.userName, password: USER.password, email: USER.email },
    purposes: PURPOSES.map((p) => p.id),
    appId:    APP_ID,
    clients:  clientResults,
  });
  console.log('  state written → demo/out/uc15.state.json');
  ev.step('state saved', {});

  const file = ev.save({ summary: 'UC-15 setup complete', counts: { purposes: PURPOSES.length, clients: CLIENTS.length } });
  console.log(`\nDone. Evidence → ${file}`);
}

main().catch((e) => { console.error('[SETUP ERROR]', e.message); process.exit(1); });

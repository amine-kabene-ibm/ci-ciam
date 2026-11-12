'use strict';
// UC-15 verify.js — checks that all tenant objects are in the expected state.
// Run: node demo/uc15-consent/verify.js

const { api, evidence, stateFile, oauthClient } = require('../lib/verify');
const {
  PURPOSES, CLIENTS, USER,
  listPurposesByPrefix, listConsents, checkDUA, getDSP,
} = require('./common');

const ev = evidence('uc15-verify');
const sf = stateFile('uc15');
let passed = 0, failed = 0, human = 0;

function ok(title, cond, info) {
  const pass = Boolean(cond);
  if (pass) passed++; else failed++;
  console.log(`  ${pass ? 'PASS' : 'FAIL'} ${title}`);
  ev.step(title, { pass, ...info });
  return pass;
}
function humanStep(title, info) {
  human++;
  console.log(`  HUMAN ${title}`);
  ev.step(title, { pass: 'HUMAN', ...info });
}

async function main() {
  const st = sf.read();
  if (!st) throw new Error('No state file — run setup.js first.');

  const userId = st.user.id;
  console.log('\nUC-15 verify\n');

  // 1. Purposes on tenant
  const purposes = await listPurposesByPrefix('ifc-demo-uc15-');
  ok('Purposes: 3 UC-15 purposes exist',
    purposes.length >= 3, { count: purposes.length });

  for (const p of PURPOSES) {
    const found = purposes.find((x) => x.id === p.id);
    ok(`Purpose ${p.id}: state=1 published`,
      found && found.state === 1, { state: found && found.state });
    ok(`Purpose ${p.id}: has attributes`,
      found && found.attributes && found.attributes.length > 0, { attrCount: found && found.attributes && found.attributes.length });
    ok(`Purpose ${p.id}: defaultConsentDuration = ${p.duration}`,
      found && found.defaultConsentDuration === p.duration, { duration: found && found.defaultConsentDuration });
  }

  // 2. DCR clients registered
  for (const cl of CLIENTS) {
    const clientData = st.clients && st.clients[cl.name];
    ok(`DCR ${cl.name}: registered (has clientId)`,
      Boolean(clientData && clientData.clientId), { clientId: clientData && clientData.clientId });

    // Verify the client still exists on the tenant via GET /oauth2/register/{id}
    if (clientData && clientData.clientId) {
      const g = await api('GET', `/oauth2/register/${clientData.clientId}`);
      ok(`DCR ${cl.name}: client still alive on tenant`,
        g.status === 200, { status: g.status });
    }
  }

  // 3. Test user exists
  const ur = await api('GET', '/v2.0/Users', {
    query: { filter: `userName eq "${st.user.userName}"`, attributes: 'id,userName,active' },
  });
  const userRec = (ur.data && ur.data.Resources && ur.data.Resources[0]) || null;
  ok(`User ${st.user.userName}: exists and active`,
    userRec && userRec.active, { id: userRec && userRec.id });

  // 4. ropc enabled on TrustMeInsurance
  const appR = await api('GET', '/appaccess/v1.0/applications/3258669560154975753');
  const ropc = appR.data && appR.data.providers && appR.data.providers.oidc &&
    appR.data.providers.oidc.properties && appR.data.providers.oidc.properties.grantTypes &&
    appR.data.providers.oidc.properties.grantTypes.ropc;
  ok('TrustMeInsurance: ropc (password grant) enabled',
    ropc === 'true', { ropc });

  // 5. Password-grant token for user
  const oidcClientId = process.env.OIDC_CLIENT_ID;
  const oidcClientSecret = process.env.OIDC_CLIENT_SECRET;
  const oc = oauthClient(oidcClientId, oidcClientSecret);
  const tokR = await oc.passwordGrant(st.user.userName, st.user.password);
  const userToken = tokR.data && tokR.data.access_token;
  ok('Test user: password grant succeeds',
    tokR.status === 200 && Boolean(userToken), { status: tokR.status });

  // 6. DSP returns purpose metadata for all 3 UC-15 purposes
  if (userToken) {
    const dsp = await getDSP(userToken, userId, PURPOSES.map((p) => p.id));
    ok('DSP: returns purpose metadata for all 3 purposes',
      dsp.status === 200 && dsp.data && dsp.data.purposes &&
        Object.keys(dsp.data.purposes).length >= 3,
      { status: dsp.status, purposeCount: dsp.data && dsp.data.purposes && Object.keys(dsp.data.purposes).length });

    // 7. DUA: denied when no consent record exists
    const duaR = await checkDUA(userToken, userId, PURPOSES[0].id);
    ok('DUA: claims-processing correctly denied when no consent present',
      duaR.status === 207 && duaR.approved === false, { status: duaR.status, approved: duaR.approved });
  }

  // 8. Admin consent ledger API accessible
  const allConsents = await listConsents(userId);
  ok('Admin consent ledger: API accessible (returns array)',
    Array.isArray(allConsents), { count: allConsents.length });

  // 9. Browser consent grant (human step)
  humanStep('Browser consent grant: sign in, toggle preferences, verify consent history', {
    url: 'http://localhost:3000',
    user: st.user.userName,
    steps: ['Sign in', 'My Profile → Communication preferences', 'Toggle on: paperless billing + marketing', 'Save'],
    note: 'After browser grant, re-run verify.js — step 10 (DUA post-grant) will then PASS',
  });

  // 10. DUA post-browser-grant (only runs if consent records exist)
  const consentsNow = await listConsents(userId);
  if (consentsNow.length > 0 && userToken) {
    const duaPost = await checkDUA(userToken, userId, PURPOSES[2].id);
    ok('DUA marketing: approved after browser consent grant',
      duaPost.approved === true, { approved: duaPost.approved, status: duaPost.status });
  } else {
    humanStep('DUA post-grant: complete step 9 first, then re-run', { consents: consentsNow.length });
  }

  const file = ev.save({
    summary: `UC-15 verify: ${passed} PASS / ${failed} FAIL / ${human} HUMAN`,
    user: { id: userId, userName: st.user.userName },
  });
  console.log(`\n  ${passed} PASS  ${failed} FAIL  ${human} HUMAN`);
  console.log(`Evidence → ${file}`);
  if (failed > 0) process.exitCode = 1;
}

main().catch((e) => { console.error('[VERIFY ERROR]', e.message); process.exit(1); });

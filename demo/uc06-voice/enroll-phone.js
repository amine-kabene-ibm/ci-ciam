'use strict';
// [HUMAN] Registers a phone (IBM Verify app) for Marie so the push step-up can be demonstrated.
//   node demo/uc06-voice/enroll-phone.js          create the QR code and wait for you to scan it
//   node demo/uc06-voice/enroll-phone.js --status just print the registrations
// Steps for you:
//   1. Install "IBM Verify" on the phone (App Store / Google Play).
//   2. Run this script. It writes demo/out/uc06-enroll-qr.png and opens it.
//   3. In the app: Add account -> Scan QR code -> scan it. Allow notifications and (optionally) biometrics.
//   4. The script polls until the registration appears, then prints the next command.
// The QR contains a one-time registration code: it is written to the gitignored demo/out/ folder only.
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { api, OUT_DIR, sleep } = require('../lib/verify');
const { state, VERIFY_PROFILE_CLIENT_ID, customer } = require('./common');

async function registrations(userId) {
  const a = await api('GET', '/v1.0/authenticators', { query: { search: `owner="${userId}"` } });
  const sg = await api('GET', '/v1.0/authnmethods/signatures', { query: { search: `owner="${userId}"` } });
  return { authenticators: (a.data && a.data.authenticators) || [], signatures: (sg.data && sg.data.signatures) || [] };
}
const show = (r) => {
  console.log(`  authenticator registrations: ${r.authenticators.length}`);
  r.authenticators.forEach((x) => console.log(`    - ${x.id}  state=${x.state}  device=${x.attributes && x.attributes.deviceName}  enabled=${x.enabled}`));
  console.log(`  signature (push/approve) methods: ${r.signatures.length}`);
  r.signatures.forEach((x) => console.log(`    - ${x.id}  enabled=${x.enabled}  subType=${x.subType}  validated=${x.validated}`));
};

(async () => {
  const st = state.read();
  if (!st) { console.error('Run setup first: node demo/uc06-voice/setup.js'); process.exit(1); }
  const userId = st.user.id;
  let before = await registrations(userId);
  if (process.argv.includes('--status')) { show(before); return; }
  if (before.authenticators.length) { console.log('A phone is already registered for this user:'); show(before); return; }

  const r = await api('POST', '/v1.0/authenticators/initiation', {
    body: { owner: userId, clientId: VERIFY_PROFILE_CLIENT_ID, accountName: `Intact (${customer.policyNumber})` },
    headers: { Accept: 'image/png' }, binary: true,
  });
  if (r.status !== 200) { console.error('Initiation failed:', r.status, r.cid, JSON.stringify(r.data)); process.exit(1); }
  const file = path.join(OUT_DIR, 'uc06-enroll-qr.png');
  fs.writeFileSync(file, r.data, { mode: 0o600 });
  console.log(`QR code written to ${file}  (initiation ${r.status}, ${r.ms} ms, cid ${r.cid})`);
  if (process.platform === 'darwin') execFile('open', [file]);
  console.log('Scan it now with the IBM Verify app (Add account > Scan QR code). Waiting up to 5 minutes...');

  const t0 = Date.now();
  while (Date.now() - t0 < 300000) {
    await sleep(3000);
    const now = await registrations(userId);
    if (now.authenticators.length) {
      console.log(`\nRegistered after ${Math.round((Date.now() - t0) / 1000)} s:`);
      show(now);
      try { fs.unlinkSync(file); } catch (e) { /* ignore */ }
      console.log('\nNext: node demo/uc06-voice/run.js --push     (or node demo/uc06-voice/caller.js)');
      return;
    }
    process.stdout.write('.');
  }
  console.log('\nTimed out: no registration seen. Re-run this script to get a new QR code.');
  process.exit(1);
})().catch((e) => { console.error(e); process.exit(2); });

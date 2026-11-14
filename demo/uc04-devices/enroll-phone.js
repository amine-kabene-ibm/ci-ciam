'use strict';
// [HUMAN] Registers a REAL phone (IBM Verify app) as a trusted device of ifc-demo-uc04-marie, then (optionally) sends a REAL push.
//   node demo/uc04-devices/enroll-phone.js            QR code for the next phone; run it once per phone (2 phones = 2 trusted devices)
//   node demo/uc04-devices/enroll-phone.js --status   list the registered devices
//   node demo/uc04-devices/enroll-phone.js --push     send a real push to every registered device and wait for you to tap Approve/Deny
// Steps for you:
//   1. Install "IBM Verify" on the phone (App Store / Google Play).
//   2. Run this script. It writes demo/out/uc04-enroll-qr.png and opens it (the customer's own token requests it, as "Register Device" would).
//   3. In the app: Add account -> Scan QR code -> scan it. Allow notifications and (optionally) biometrics.
//   4. The script polls until a new registration appears, then prints the next command.
// The QR contains a one-time registration code: it is written to the gitignored demo/out/ folder only and deleted after use.
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { OUT_DIR, sleep } = require('../lib/verify');
const { createDeviceService } = require('../../stubs/device-portal/devices');
const c = require('./common');

const show = (l) => {
  console.log(`  registered devices: ${l.length}`);
  l.forEach((x) => console.log(`    - ${x.id}  ${x.state}  ${x.deviceName}  (${x.platformType} ${x.deviceType || ''})  enabled=${x.enabled}`));
};

(async () => {
  const st = c.state.read();
  if (!st) { console.error('Run setup first: node demo/uc04-devices/setup.js'); process.exit(1); }
  const marie = st.users.marie;
  const svc = createDeviceService({ userName: marie.userName, password: marie.password, consoleClientId: st.console.clientId, consoleClientSecret: st.console.clientSecret });
  const before = (await svc.list()).devices || [];
  if (process.argv.includes('--status')) { show(before); return; }

  if (process.argv.includes('--push')) {
    if (!before.length) { console.error('No device registered. Run enroll-phone.js first.'); process.exit(1); }
    for (const d of before) {
      const p = await svc.push(d.id, { message: 'IFC demo: tap Approve to confirm this push reached your phone.', location: 'Montreal, QC, Canada', type: 'UC-04 demo' });
      if (p.error) { console.log(`  ${d.deviceName}: push failed: ${p.error}`); continue; }
      console.log(`  ${d.deviceName}: push accepted (HTTP 202, ${p.ms} ms). Look at the phone: a notification should arrive, tap Approve. Waiting up to 90 s...`);
      const done = await svc.waitFor(d.id, p.txn.id, { timeoutMs: 90000 });
      console.log(`  ${d.deviceName}: result ${done.txn ? done.txn.state : done.error} after ${Math.round(done.waitedMs / 1000)} s`);
    }
    return;
  }

  const r = await svc.initiate(`Intact (${marie.userName})`, { format: 'png' });
  if (r.error) { console.error('Initiation failed:', r.error, r.cid || ''); process.exit(1); }
  const file = path.join(OUT_DIR, 'uc04-enroll-qr.png');
  fs.writeFileSync(file, r.png, { mode: 0o600 });
  console.log(`QR code written to ${file}  (cid ${r.cid}). ${before.length} device(s) registered so far.`);
  if (process.platform === 'darwin') execFile('open', [file]);
  console.log('Scan it now with the IBM Verify app (Add account > Scan QR code). Waiting up to 5 minutes...');
  const t0 = Date.now();
  while (Date.now() - t0 < 300000) {
    await sleep(3000);
    const now = (await svc.list()).devices || [];
    if (now.length > before.length) {
      console.log(`\nNew device registered after ${Math.round((Date.now() - t0) / 1000)} s:`);
      show(now);
      try { fs.unlinkSync(file); } catch (e) { /* ignore */ }
      console.log('\nNext: run this script again for a second phone, then:  node demo/uc04-devices/enroll-phone.js --push');
      return;
    }
    process.stdout.write('.');
  }
  console.log('\nTimed out: no registration seen. Re-run this script to get a new QR code.');
  process.exit(1);
})().catch((e) => { console.error(e.message || e); process.exit(2); });

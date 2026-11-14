'use strict';
// A software "IBM Verify app" (UC-04). It plays what the mobile app does after a user scans the registration QR, so the server side of
// trusted-device registration and push approval can be exercised from a script without a phone. Protocol taken from the open-source
// IBM Verify MFA SDK for iOS (Sources/mfa/CloudRegistrationProvider.swift, CloudAuthenticatorService.swift).
//   register : POST <registrationUri>?skipTotpEnrollment=false {code, attributes}  -> {id, accessToken, refreshToken, metadata}
//   enrol    : POST <signature enrollmentUri> [{subType:'userPresence', attributes:{signedData, publicKey (SPKI), algorithm:'RSASHA256', ...}}]
//   finalize : POST <registrationUri>?metadataInResponse=false {refreshToken, attributes}  (ENROLLING -> ACTIVE)
//   poll     : GET  <registrationUri with 'registration' -> '<id>/verifications'>?search=state="PENDING"
//   answer   : POST <transactionUri>/<txnId> [{id: factorId, userAction: VERIFY_ATTEMPT | USER_DENIED, signedData}]
// It is NOT the real app: there is no APNs/FCM push channel, no Face ID / Touch ID, no secure enclave. A real phone stays [HUMAN].
// Nothing here logs codes, tokens, private keys or signatures. Device state (keys, tokens) lives in the gitignored demo/out/ state file.
const crypto = require('crypto');
const { BASE, send } = require('./verify');

const VERIFY_PROFILE_CLIENT_ID = '5280f51a-9699-4d96-9dd9-bcc0fdfdf9dd'; // "Verify Profile" authenticator client [LIVE]

// Exported: one HTTP call with an optional Bearer token (also used to act as the signed-in customer with their own token).
async function call(method, url, { body, token, query } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const t0 = Date.now();
  const r = await send({ method, url, headers, data: body === undefined ? undefined : JSON.stringify(body), params: query, validateStatus: () => true, transformResponse: (x) => x });
  let data = r.data;
  if (typeof data === 'string' && data.length) { try { data = JSON.parse(data); } catch (e) { /* raw */ } }
  if (data === '') data = null;
  return { status: r.status, data, cid: r.headers['x-correlation-id'] || null, ms: Date.now() - t0 };
}

class VerifyDevice {
  // profile: what the phone says about itself (shows in the authenticator's attributes). saved: a previous toJSON() to resume.
  constructor(profile = {}, saved = null) {
    this.profile = {
      applicationId: 'com.ibm.security.verifyapp', applicationVersion: '3.1.7 (1)', platformType: 'IOS', deviceType: 'iPhone',
      osVersion: '17.5', faceSupport: true, fingerprintSupport: false, frontCameraSupport: true, deviceInsecure: false,
      verifySdkVersion: '3.1.7', deviceName: 'Simulated iPhone', deviceId: crypto.randomUUID(), ...profile,
    };
    Object.assign(this, saved || {});
  }

  toJSON() { return { profile: this.profile, id: this.id, accessToken: this.accessToken, refreshToken: this.refreshToken, privateKey: this.privateKey, factorId: this.factorId, keyLabel: this.keyLabel, registrationUri: this.registrationUri, algorithm: this.algorithm }; }
  static fromJSON(o) { const d = new VerifyDevice(o.profile, o); return d; }

  // Step 1 of the app: redeem the QR payload (the JSON `code`/`registrationUri` from POST /v1.0/authenticators/initiation).
  async register(qr, accountName, { enrolPush = true } = {}) {
    const steps = {};
    const attributes = { ...this.profile, accountName, pushToken: '' };
    const r1 = await call('POST', `${qr.registrationUri}?skipTotpEnrollment=false`, { body: { code: qr.code, attributes } });
    steps.redeem = { status: r1.status, ms: r1.ms, cid: r1.cid };
    if (r1.status !== 200 && r1.status !== 201) return { ok: false, steps, error: r1.data };
    const info = r1.data;
    this.id = info.id; this.accessToken = info.accessToken; this.refreshToken = info.refreshToken; this.registrationUri = info.metadata.registrationUri;
    this.methods = Object.keys(info.metadata.authenticationMethods || {});
    steps.methods = this.methods;
    if (enrolPush) {
      const m = info.metadata.authenticationMethods.signature_userPresence;
      if (!m || !m.enabled) { steps.enrol = { skipped: 'signature_userPresence not enabled on the tenant' }; return { ok: false, steps }; }
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      this.privateKey = privateKey.export({ type: 'pkcs8', format: 'pem' });
      this.algorithm = 'RSASHA256';
      this.keyLabel = `${this.id}.userPresence`;
      const signedData = crypto.sign('sha256', Buffer.from(this.id), privateKey).toString('base64');
      const r2 = await call('POST', m.enrollmentUri, {
        token: this.accessToken,
        body: [{ subType: 'userPresence', enabled: true, attributes: {
          signedData, publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), deviceSecurity: false,
          algorithm: this.algorithm, additionalData: [{ name: 'name', value: this.keyLabel }] } }],
      });
      steps.enrol = { status: r2.status, ms: r2.ms, cid: r2.cid };
      if (r2.status >= 300) { steps.enrol.error = r2.data; return { ok: false, steps }; }
      const f = (Array.isArray(r2.data) ? r2.data : []).find((x) => x.subType === 'userPresence');
      this.factorId = f && f.id;
    }
    // finalize: the token refresh flips the authenticator from ENROLLING to ACTIVE
    const r3 = await call('POST', `${this.registrationUri}?metadataInResponse=false`, { token: this.accessToken, body: { refreshToken: this.refreshToken, attributes: { ...attributes } } });
    steps.finalize = { status: r3.status, ms: r3.ms, cid: r3.cid };
    if (r3.status === 200 && r3.data && r3.data.accessToken) { this.accessToken = r3.data.accessToken; this.refreshToken = r3.data.refreshToken || this.refreshToken; }
    return { ok: r3.status === 200, steps, id: this.id };
  }

  get transactionUri() { return this.registrationUri.replace('registration', `${this.id}/verifications`); }

  async refresh() {
    const r = await call('POST', this.registrationUri, { token: this.accessToken, body: { refreshToken: this.refreshToken, attributes: { ...this.profile, pushToken: '' } } });
    if (r.status === 200 && r.data && r.data.accessToken) { this.accessToken = r.data.accessToken; this.refreshToken = r.data.refreshToken || this.refreshToken; }
    return r;
  }

  // What the app does when a push arrives (or when opened): list the pending transactions for this registration.
  async pending() {
    const q = { filter: 'id,creationTime,transactionData,correlationEnabled,correlationValue,expiryTime,authenticationMethods', search: 'state="PENDING"', sort: '-creationTime' };
    let r = await call('GET', this.transactionUri, { token: this.accessToken, query: q });
    if (r.status === 401) { await this.refresh(); r = await call('GET', this.transactionUri, { token: this.accessToken, query: q }); }
    return r;
  }

  // Answer a pending transaction. action: 'approve' signs transactionData with the device key (what a tap on Approve does), 'deny' does not.
  async answer(txn, action) {
    const method = (txn.authenticationMethods || [])[0] || {};
    const factorId = (method.id || this.factorId || '').toLowerCase();
    let item;
    if (action === 'approve') {
      const signedData = crypto.sign('sha256', Buffer.from(txn.transactionData), crypto.createPrivateKey(this.privateKey)).toString('base64');
      item = { id: factorId, userAction: 'VERIFY_ATTEMPT', signedData };
    } else if (action === 'fraud') item = { id: factorId, userAction: 'USER_FRAUDULENT' };
    else item = { id: factorId, userAction: 'USER_DENIED' };
    const url = `${this.transactionUri}/${txn.id}`;
    let r = await call('POST', url, { token: this.accessToken, body: [item] });
    if (r.status === 401) { await this.refresh(); r = await call('POST', url, { token: this.accessToken, body: [item] }); }
    return r;
  }

  // Poll until a transaction shows up, then answer it. Returns {txn, answer, seenMs}.
  async handleNext(action, { timeoutMs = 30000, intervalMs = 1000 } = {}) {
    const t0 = Date.now();
    for (;;) {
      const p = await this.pending();
      const txn = p.status === 200 && p.data && (p.data.verifications || [])[0];
      if (txn) { const a = await this.answer(txn, action); return { txn, answer: a, seenMs: Date.now() - t0 }; }
      if (Date.now() - t0 > timeoutMs) return { txn: null, status: p.status, seenMs: Date.now() - t0 };
      await new Promise((res) => setTimeout(res, intervalMs));
    }
  }
}

module.exports = { VerifyDevice, VERIFY_PROFILE_CLIENT_ID, BASE, call };

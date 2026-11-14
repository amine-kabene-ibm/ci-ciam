'use strict';
// UC-04 device logic: what IFC's mobile app / self-service portal does with IBM Verify trusted devices. Used by the web page (server.js)
// and by demo/uc04-devices/run.js, so both behave the same.
//   list      GET    /v1.0/authenticators                         the customer's registered devices (their own only, with their own token)
//   initiate  POST   /v1.0/authenticators/initiation              "Register Device": returns the QR payload (JSON) or the QR image (PNG)
//   push      POST   /v1.0/authenticators/{id}/verifications      push to ONE device, with a message and a location the app shows
//   txn       GET    /v1.0/authenticators/{id}/verifications/{t}  state of that push (PENDING, VERIFY_SUCCESS, USER_DENIED, TIMEOUT, ...)
//   revoke    DELETE /v1.0/authenticators/{id}                    the customer removes a device
// Two ways to call it [LIVE 2026-11-13]:
//   - as the signed-in customer (password-grant token, no `owner`): can only see, push to and delete their own devices;
//   - as a back-end "device service" (API client with 4 entitlements, `owner` = the customer's id).
// A simulated phone (demo/lib/verifyDevice.js) can stand in for the IBM Verify app. It is NOT a real phone: no APNs/FCM, no Face ID.
const { BASE, send, oauthClient } = require('../../demo/lib/verify');
const { VerifyDevice, VERIFY_PROFILE_CLIENT_ID, call } = require('../../demo/lib/verifyDevice');

const PUSH_BODY = (sigId, o) => ({
  transactionData: {
    message: o.message, originIpAddress: o.ip || '203.0.113.7', originUserAgent: o.userAgent || 'IFC Mobile App',
    additionalData: [{ name: 'originLocation', value: o.location || 'Montreal, QC, Canada' }, { name: 'type', value: o.type || 'IFC notification' }],
  },
  pushNotification: { title: o.title || 'Intact Financial', message: o.message, send: true },
  authenticationMethods: [{ id: sigId, methodType: 'signature' }],
  logic: 'OR', // without it: 400 CSIAK2802E
  expiresIn: o.expiresIn || 120,
});

// cfg: { userName, password, consoleClientId, consoleClientSecret }  -> acts as the signed-in customer
//      { request(method, path, body) -> {status,data,cid,ms}, owner }  -> acts as the device service (API client) for one customer
function createDeviceService(cfg) {
  let tok = null;
  const sims = new Map(); // authenticator id -> VerifyDevice (simulated phones registered through this object)
  async function userToken(force) {
    if (!force && tok && tok.exp > Date.now() + 30000) return tok.token;
    const r = await oauthClient(cfg.consoleClientId, cfg.consoleClientSecret).passwordGrant(cfg.userName, cfg.password);
    if (r.status !== 200) throw new Error(`customer sign-in failed: HTTP ${r.status}`);
    tok = { token: r.data.access_token, exp: Date.now() + (r.data.expires_in || 3600) * 1000 };
    return tok.token;
  }
  async function req(method, path, body, query) {
    if (cfg.request) return cfg.request(method, path, body, query);
    let r = await call(method, BASE + path, { token: await userToken(false), body, query });
    if (r.status === 401) r = await call(method, BASE + path, { token: await userToken(true), body, query });
    return r;
  }
  const ownerQuery = () => (cfg.owner ? { search: `owner="${cfg.owner}"` } : undefined);

  async function list() {
    const r = await req('GET', '/v1.0/authenticators', undefined, ownerQuery());
    if (r.status !== 200) return { error: `list devices: HTTP ${r.status}`, httpStatus: r.status, cid: r.cid };
    const devices = ((r.data && r.data.authenticators) || []).map((x) => ({
      id: x.id, deviceName: x.attributes.deviceName, platformType: x.attributes.platformType, deviceType: x.attributes.deviceType, osVersion: x.attributes.osVersion,
      state: x.state, enabled: x.enabled, created: x.creationTime, clientId: x.clientId, simulated: sims.has(x.id),
    }));
    return { devices, ms: r.ms };
  }

  // "Register Device": the QR payload. {format:'json'} for the simulated phone, {format:'png'} for a real phone (QR image, Buffer).
  async function initiate(accountName, { format = 'json', clientId = VERIFY_PROFILE_CLIENT_ID } = {}) {
    const body = { clientId, accountName, ...(cfg.owner ? { owner: cfg.owner } : {}) };
    if (format === 'png') {
      const t = cfg.request ? null : await userToken(false);
      const headers = { Accept: 'image/png', 'Content-Type': 'application/json', ...(t ? { Authorization: `Bearer ${t}` } : {}) };
      if (cfg.request) return { error: 'png initiation needs the customer token' };
      const r = await send({ method: 'POST', url: `${BASE}/v1.0/authenticators/initiation`, headers, data: JSON.stringify(body), responseType: 'arraybuffer', validateStatus: () => true });
      return r.status === 200 ? { png: Buffer.from(r.data), cid: r.headers['x-correlation-id'] } : { error: `initiation: HTTP ${r.status}`, httpStatus: r.status };
    }
    const r = await req('POST', '/v1.0/authenticators/initiation', body);
    if (r.status !== 200) return { error: `initiation: HTTP ${r.status}`, httpStatus: r.status, cid: r.cid, data: r.data };
    return { qr: r.data, ms: r.ms, cid: r.cid };
  }

  // Simulated phone scans the QR (== the app's "Add account" flow). Returns the registered device and the step timings.
  async function simulateScan({ deviceName, platformType = 'IOS', deviceType = 'iPhone', osVersion, clientId, applicationId } = {}) {
    const ini = await initiate(`Intact (${deviceName})`, { clientId });
    if (ini.error) return ini;
    const dev = new VerifyDevice({ deviceName, platformType, deviceType, ...(osVersion ? { osVersion } : {}), ...(applicationId ? { applicationId } : {}), ...(platformType === 'Android' ? { faceSupport: false, fingerprintSupport: true } : {}) });
    const t0 = Date.now();
    const r = await dev.register(ini.qr, `Intact (${deviceName})`);
    if (!r.ok) return { error: 'registration failed', steps: r.steps, httpStatus: ini.httpStatus };
    sims.set(dev.id, dev);
    return { device: dev, id: dev.id, steps: r.steps, initiationMs: ini.ms, registerMs: Date.now() - t0 };
  }

  async function signatureOf(id) {
    const r = await req('GET', '/v1.0/authnmethods/signatures', undefined, ownerQuery());
    if (r.status !== 200) return { error: `signatures: HTTP ${r.status}`, httpStatus: r.status, cid: r.cid };
    const s = ((r.data && r.data.signatures) || []).find((x) => x.attributes && x.attributes.authenticatorId === id);
    return s ? { id: s.id } : { error: 'no push (signature) method on this device', httpStatus: 404 };
  }

  // Push to one device. o: {message, title, location, type, expiresIn, ip}. Returns {txn:{id,state,...}} or {error, httpStatus, data}.
  async function push(id, o = {}) {
    const sig = o.signatureId ? { id: o.signatureId } : await signatureOf(id);
    if (sig.error) return sig;
    const r = await req('POST', `/v1.0/authenticators/${id}/verifications`, PUSH_BODY(sig.id, { message: 'Please confirm', ...o }));
    if (r.status !== 202) return { error: `push: HTTP ${r.status}`, httpStatus: r.status, cid: r.cid, data: r.data };
    return { txn: { id: r.data.id, state: r.data.state, expiryTime: r.data.expiryTime }, ms: r.ms, cid: r.cid, sigId: sig.id };
  }

  async function txn(id, txnId) {
    const r = await req('GET', `/v1.0/authenticators/${id}/verifications/${txnId}`);
    if (r.status !== 200) return { error: `txn: HTTP ${r.status}`, httpStatus: r.status, cid: r.cid };
    return { txn: { id: r.data.id, state: r.data.state, userActions: r.data.userActions, creationTime: r.data.creationTime, completionTime: r.data.completionTime } };
  }

  async function waitFor(id, txnId, { timeoutMs = 20000 } = {}) {
    const t0 = Date.now();
    for (;;) {
      const t = await txn(id, txnId);
      if (t.error || t.txn.state !== 'PENDING') return { ...t, waitedMs: Date.now() - t0 };
      if (Date.now() - t0 > timeoutMs) return { ...t, waitedMs: Date.now() - t0 };
      await new Promise((res) => setTimeout(res, 500));
    }
  }

  async function revoke(id) {
    const r = await req('DELETE', `/v1.0/authenticators/${id}`);
    sims.delete(id);
    return r.status === 204 ? { revoked: true, ms: r.ms, cid: r.cid } : { error: `revoke: HTTP ${r.status}`, httpStatus: r.status, cid: r.cid, data: r.data };
  }

  return { list, initiate, simulateScan, push, txn, waitFor, revoke, req, sims };
}

module.exports = { createDeviceService, PUSH_BODY };

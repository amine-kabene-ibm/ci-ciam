'use strict';
// STUB just-in-time (JIT) migration login gateway for UC-11. It stands where IFC's login page would stand on cut-over day.
// IBM Verify has no native "verify against the legacy store on first login" switch we could use on this tenant
// (Flow designer is not enabled; the Verify Bridge / external-authentication agent is not provisioned: see DEMO-BUILD-GUIDE.md UC-11),
// so the JIT pattern is built in front of Verify, with Verify's own APIs:
//
//   POST /login {username, password[, newPassword]}
//     1. Verify first: password grant against the new platform. Success = a native (already migrated) user, the legacy store is NOT asked.
//     2. If Verify says "password must be changed" (a bulk-imported user flagged for reset) -> 403 password_change_required.
//     3. If the user already exists in Verify, a wrong password is final: the legacy store is NOT asked (Verify is authoritative once migrated).
//     4. Only an unknown user is checked against the legacy store (POST /password-verify). Invalid -> 401, same answer as step 3.
//     5. Legacy says valid -> the user is created in Verify with the PLAINTEXT password just verified, so Verify hashes it itself
//        ("re-hashes into the new platform"), together with the linkage attributes (externalId, policy number, brokerage, broker id).
//        If Verify's password policy rejects it -> 422 new_password_required (nothing is created); the caller resends with newPassword.
//     6. The legacy store is told the user is migrated (cut-over tracking), and the gateway signs the user in against Verify.
//   GET  /            a small sign-in page (for the demo)       GET /portal-login, /callback   the standard Verify hosted page (code + PKCE)
//   GET  /_events     what the gateway did (no passwords, no tokens)
// The migrator API client has only readUsers + manageUsers; it is NOT the admin client. Tokens and passwords are never logged or rendered.
const express = require('express');
const crypto = require('crypto');
const { BASE, oauthClient, send } = require('../../demo/lib/verify');
const { verifyJwt, tenantJwks, ISSUER } = require('../rp-sso/server');

const ENDPOINT = `${BASE}/v1.0/endpoint/default`;
const rand = (n) => crypto.randomBytes(n).toString('base64url');
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const SCIM_USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_ENT = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const SCIM_IBM = 'urn:ietf:params:scim:schemas:extension:ibm:2.0:User';

// cfg: {legacyUrl, migrator: {api}, login: {clientId, clientSecret}, portal: {clientId, clientSecret}, origin, log}
function createGateway(cfg) {
  const { legacyUrl, migrator, login, portal, origin, log = () => {} } = cfg;
  const ropc = oauthClient(login.clientId, login.clientSecret);
  const getJwks = tenantJwks();
  const events = [];
  const txns = new Map();
  const note = (e) => { events.push({ at: new Date().toISOString(), ...e }); log(`[gateway] ${JSON.stringify(e)}`); };

  const legacy = async (path, body) => {
    try {
      const r = await send({ method: 'post', url: `${legacyUrl}${path}`, data: body, validateStatus: () => true, timeout: 5000 });
      return { status: r.status, data: r.data };
    } catch (e) { return { status: 0, data: null }; }
  };
  const errOf = (r) => `${(r.data && (r.data.error_description || r.data.messageDescription)) || ''}`;

  async function signedIn(r, source, extra) {
    let claims = {};
    try { claims = await verifyJwt(r.data.id_token, getJwks, { iss: ISSUER, aud: login.clientId }); } catch (e) { claims = {}; }
    return { status: 200, body: { outcome: 'signed_in', source, sub: claims.sub || null, amr: claims.amr || null, tokenIssued: !!r.data.access_token, ...extra } };
  }

  async function signIn({ username, password, newPassword }) {
    const t0 = Date.now();
    const done = (status, body) => { note({ type: 'login', username, outcome: body.outcome, source: body.source || null, status, ms: Date.now() - t0 }); return { status, body: { ...body, ms: Date.now() - t0 } }; };
    if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) return done(400, { outcome: 'bad_request' });

    // 1. Verify first
    const first = await ropc.passwordGrant(username, password);
    if (first.status === 200) { const s = await signedIn(first, 'verify'); return done(s.status, s.body); }
    if (/CSIAQ0267E/.test(errOf(first))) return done(403, { outcome: 'password_change_required', source: 'verify', hint: 'open /portal-login: the Verify hosted page asks for a new password' });
    if (/CSIAQ0281E/.test(errOf(first))) return done(401, { outcome: 'refused', reason: 'account_inactive' });
    if (!/CSIAQ0264E/.test(errOf(first))) return done(502, { outcome: 'verify_error', verifyStatus: first.status });

    // 2. Is the user already in Verify? Then Verify is authoritative and the wrong password is final.
    const found = await migrator.api('GET', '/v2.0/Users', { query: { filter: `userName eq "${username.replace(/"/g, '\\"')}"`, attributes: 'id' }, quiet: true });
    if (found.status !== 200) return done(502, { outcome: 'verify_error', verifyStatus: found.status });
    if ((found.data.Resources || []).length) return done(401, { outcome: 'refused' });

    // 3. Unknown to Verify: ask the legacy store
    const lv = await legacy('/password-verify', { username, password });
    if (lv.status === 0 || lv.status === 503) return done(503, { outcome: 'legacy_unavailable' });
    if (lv.status !== 200 || !lv.data.valid) return done(401, { outcome: 'refused' });
    const a = lv.data.attributes || {};

    // 3b. Do not create a second account for a legacy customer who already has one under another login
    if (a.externalId) {
      const dup = await migrator.api('GET', '/v2.0/Users', { query: { filter: `externalId eq "${String(a.externalId).replace(/"/g, '\\"')}"`, attributes: 'id,userName' }, quiet: true });
      if (dup.status === 200 && (dup.data.Resources || []).length) return done(409, { outcome: 'account_conflict' });
    }

    // 4. Create the user with the verified plaintext password (or the new one the caller chose)
    const chosen = typeof newPassword === 'string' && newPassword ? newPassword : password;
    const body = {
      schemas: [SCIM_USER, SCIM_ENT, SCIM_IBM], userName: username, externalId: a.externalId,
      name: { givenName: a.givenName, familyName: a.familyName, formatted: `${a.givenName} ${a.familyName}` }, displayName: `${a.givenName} ${a.familyName}`,
      emails: [{ type: 'work', value: a.email }], preferredLanguage: a.preferredLanguage, password: chosen, active: true,
      ...(a.department || a.employeeNumber ? { [SCIM_ENT]: { ...(a.department ? { department: a.department } : {}), ...(a.employeeNumber ? { employeeNumber: a.employeeNumber } : {}) } } : {}),
      ...(a.accountId ? { [SCIM_IBM]: { customAttributes: [{ name: 'accountId', values: [a.accountId] }] } } : {}),
    };
    const c = await migrator.api('POST', '/v2.0/Users', { body, headers: { usershouldnotneedtoresetpassword: 'true' }, quiet: true });
    if (c.status === 400 && /CSIAI0020E|CSIAI0021E|password/i.test(JSON.stringify(c.data))) {
      return done(422, { outcome: 'new_password_required', reason: 'the legacy password no longer meets the new password policy', policyMessage: String((c.data && c.data.detail) || '').slice(0, 80) });
    }
    if (c.status !== 201 && c.status !== 409) return done(502, { outcome: 'verify_error', verifyStatus: c.status });

    // 5. Cut-over tracking in the legacy store, then sign the user in against Verify
    await legacy('/migrated', { username });
    const again = await ropc.passwordGrant(username, chosen);
    if (again.status !== 200) return done(502, { outcome: 'verify_error', verifyStatus: again.status, detail: 'created but sign-in failed' });
    const s = await signedIn(again, 'legacy->verify', { migrated: c.status === 201, passwordChanged: chosen !== password });
    return done(s.status, s.body);
  }

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));
  const page = (res, status, body) => res.status(status).set('Cache-Control', 'no-store').type('html').send(
    `<!doctype html><html><head><meta charset="utf-8"><title>IFC sign-in (migration gateway stub)</title></head><body style="font-family:system-ui,sans-serif;margin:0">` +
    `<header style="background:#0f62fe;color:#fff;padding:14px 24px;font-size:20px">IFC customer portal (new platform) <small>[stub: migration gateway]</small></header><main style="padding:24px;max-width:640px">${body}</main></body></html>`);
  const form = (extra = '', username = '') => `<form method="POST" action="/login"><p><label>User name<br><input name="username" value="${esc(username)}" autocomplete="username"></label></p>` +
    `<p><label>Password<br><input type="password" name="password" autocomplete="current-password"></label></p>${extra}<p><button>Sign in</button></p></form>` +
    `<p><a href="/portal-login">Sign in with the standard Verify page (customers already migrated)</a></p>`;

  app.get('/', (req, res) => page(res, 200, `<p>Sign in with your <b>existing</b> IFC password. You are never asked to reset it.</p>${form()}`));
  app.get('/health', (req, res) => res.json({ ok: true }));
  app.get('/_events', (req, res) => res.json({ events }));

  app.post('/login', async (req, res) => {
    const r = await signIn(req.body || {});
    const wantsHtml = /text\/html/.test(req.headers.accept || '') && !/json/.test(req.headers['content-type'] || '');
    if (!wantsHtml) return res.status(r.status).json(r.body);
    const o = r.body;
    if (o.outcome === 'signed_in') return page(res, 200, `<h2>Signed in</h2><table cellpadding="4"><tr><td>Source of the password check</td><td><b>${esc(o.source)}</b></td></tr>` +
      `<tr><td>Account (sub)</td><td>${esc(o.sub)}</td></tr><tr><td>Methods (amr)</td><td>${esc((o.amr || []).join(', '))}</td></tr>` +
      `<tr><td>Migrated just now</td><td>${o.migrated ? 'yes: created in Verify at this sign-in' : 'no: already a Verify user'}</td></tr></table><p><a href="/">Back</a></p>`);
    if (o.outcome === 'new_password_required') return page(res, 422, `<h2>Choose a new password</h2><p>Your current password is correct, but it is shorter than the new platform allows. Choose a new one.</p>` +
      form(`<p><label>New password<br><input type="password" name="newPassword" autocomplete="new-password"></label></p>`, req.body.username));
    if (o.outcome === 'password_change_required') return page(res, 403, `<h2>Choose a new password</h2><p>Your account was migrated with a required password change. <a href="/portal-login">Continue on the Verify page</a>.</p>`);
    if (o.outcome === 'legacy_unavailable') return page(res, 503, `<h2>Temporarily unavailable</h2><p>Please try again in a few minutes.</p>${form('', req.body.username)}`);
    return page(res, r.status, `<h2>Sign-in failed</h2><p>The user name or password is not valid.</p>${form('', req.body.username)}`);
  });

  // The standard Verify hosted login (for users already migrated; also where the forced-reset customers choose a new password)
  app.get('/portal-login', (req, res) => {
    const state = rand(16); const nonce = rand(16); const verifier = rand(32);
    txns.set(state, { nonce, verifier });
    res.redirect(`${ENDPOINT}/authorize?${new URLSearchParams({
      response_type: 'code', client_id: portal.clientId, redirect_uri: `${origin}/callback`, scope: 'openid', state, nonce,
      code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
    })}`);
  });
  app.get('/callback', async (req, res) => {
    const txn = txns.get(req.query.state); txns.delete(req.query.state);
    if (req.query.error) return page(res, 400, `<h2>Sign-in did not complete</h2><p>${esc(req.query.error)}</p>`);
    if (!txn || !req.query.code) return page(res, 400, '<h2>Unknown or replayed sign-in request</h2>');
    const t = await send({
      method: 'post', url: `${ENDPOINT}/token`, validateStatus: () => true, auth: { username: portal.clientId, password: portal.clientSecret },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: new URLSearchParams({ grant_type: 'authorization_code', code: req.query.code, redirect_uri: `${origin}/callback`, code_verifier: txn.verifier }).toString(),
    });
    if (t.status !== 200) return page(res, 502, `<h2>Token exchange failed</h2><p>HTTP ${t.status}</p>`);
    let claims;
    try { claims = await verifyJwt(t.data.id_token, getJwks, { iss: ISSUER, aud: portal.clientId }); if (claims.nonce !== txn.nonce) throw new Error('nonce mismatch'); } catch (e) { return page(res, 400, `<h2>ID token rejected</h2><p>${esc(e.message)}</p>`); }
    note({ type: 'hosted_login', sub: claims.sub, amr: claims.amr });
    page(res, 200, `<h2 data-signed-in="true">Signed in on the Verify hosted page</h2><table cellpadding="4"><tr><td>Account (sub)</td><td>${esc(claims.sub)}</td></tr>` +
      `<tr><td>Methods (amr)</td><td>${esc((claims.amr || []).join(', '))}</td></tr></table><p><a href="/">Back</a></p>`);
  });

  return { app, events, signIn };
}

const listen = (gw, port) => new Promise((resolve, reject) => {
  const srv = gw.app.listen(port, () => resolve(srv));
  srv.on('error', (e) => reject(e.code === 'EADDRINUSE' ? new Error(`port ${port} is busy (is demo/uc11-migration/serve.js running?)`) : e));
});

module.exports = { createGateway, listen };

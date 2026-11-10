'use strict';
// STUB relying party (RP) for UC-08 "SSO across apps and global logout". One factory, three instances (portal / claims / quote).
// A plain OIDC authorization-code RP with PKCE against the real IBM Verify tenant. It owns its OWN session cookie and enforces its OWN authorization.
//   GET  /                      what this app knows about the signed-in user (or "Not signed in")
//   GET  /login[?prompt=&max_age=]  start the OIDC flow
//   GET  /callback              code exchange; ID token verified offline (RS256 via the tenant JWKS, iss, aud, exp, nonce);
//                               then THIS app's authorization: optional required group claim -> 403 if missing
//   GET  /protected             JSON, 401 without a session. If introspectEachRequest, also asks Verify "is this access token still alive?"
//   GET  /logout                RP-initiated logout: drop the local session, then send the browser to Verify's rplogout (global logout)
//   GET  /local-logout          what many apps do today: drop ONLY this app's session. Verify's single sign-on session stays alive (the anti-pattern)
//   GET  /frontchannel-logout   called by the browser (iframe) from Verify's logout page with ?iss&sid: drop sessions of that Verify session
//   POST /backchannel-logout    called server-to-server by Verify with a logout_token (needs a public URL): validate, drop sessions
//   POST /bc/:name              same handler, reachable through one tunnel for all three apps (registry dispatch)
//   GET  /_events               what logout notifications this app received
// Sessions live in memory. Nothing secret is rendered: no tokens, no client secret.

const express = require('express');
const crypto = require('crypto');
const { BASE, send, oauthClient } = require('../../demo/lib/verify');

const ISSUER = `${BASE}/oidc/endpoint/default`;
const ENDPOINT = `${BASE}/v1.0/endpoint/default`;
const BCL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

const rand = (n) => crypto.randomBytes(n).toString('base64url');
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const cookiesOf = (req) => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((c) => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));

// JWKS of the tenant, cached; refetched once when a kid is unknown (key rotation).
function tenantJwks() {
  let cache = null;
  return async (force) => {
    if (!cache || force) {
      const r = await send({ method: 'get', url: `${ENDPOINT}/jwks`, validateStatus: () => true });
      if (r.status !== 200) throw new Error(`JWKS HTTP ${r.status}`);
      cache = r.data;
    }
    return cache;
  };
}

// Offline JWT check: RS256 signature against the JWKS, issuer, audience, expiry. Throws on any problem.
async function verifyJwt(token, getJwks, { iss, aud }) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('not a JWT');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  if (header.alg !== 'RS256') throw new Error(`alg ${header.alg} not accepted`);
  let jwk = ((await getJwks()).keys || []).find((k) => k.kid === header.kid);
  if (!jwk) jwk = ((await getJwks(true)).keys || []).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('unknown signing key');
  const ok = crypto.verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(parts[2], 'base64url'));
  if (!ok) throw new Error('bad signature');
  if (claims.iss !== iss) throw new Error('issuer mismatch');
  if (![].concat(claims.aud).includes(aud)) throw new Error('audience mismatch');
  if (claims.exp && claims.exp * 1000 < Date.now() - 30000) throw new Error('expired');
  return claims;
}

// cfg: {key, title, colour, port, clientId, clientSecret, requireGroup, introspectEachRequest, registry, getJwks, issuer, log}
function createRp(cfg) {
  const { key, title, colour = '#0f62fe', port, clientId, clientSecret, requireGroup = null, introspectEachRequest = false,
    registry = {}, getJwks = tenantJwks(), issuer = ISSUER, log = () => {} } = cfg;
  const origin = `http://localhost:${port}`;
  const sessionCookie = `ifc_${key}_sid`;
  const sessions = new Map(); // local id -> {user, sub, groups, amr, authTime, idpSid, expiresIn, idToken, accessToken, at}
  const txns = new Map();     // state -> {nonce, verifier}
  const events = [];
  const note = (e) => { const x = { at: new Date().toISOString(), ...e }; events.push(x); log(`[rp-${key}] ${JSON.stringify(x)}`); return x; };
  const introspect = oauthClient(clientId, clientSecret).introspect;

  const current = (req) => { const id = cookiesOf(req)[sessionCookie]; return id && sessions.has(id) ? { id, s: sessions.get(id) } : null; };
  const setCookie = (res, v, maxAge) => res.append('Set-Cookie', `${sessionCookie}=${v}; Path=/; HttpOnly; SameSite=Lax${maxAge === 0 ? '; Max-Age=0' : ''}`);
  const dropWhere = (fn) => { let n = 0; for (const [id, s] of sessions) if (fn(s)) { sessions.delete(id); n++; } return n; };
  const html = (res, status, body) => res.status(status).set('Cache-Control', 'no-store').type('html').send(
    `<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title></head><body style="font-family:system-ui,sans-serif;margin:0">` +
    `<div style="background:${colour};color:#fff;padding:14px 24px;font-size:20px">${esc(title)} <small style="opacity:.8">(${esc(key)}, :${port})</small></div>` +
    `<div style="padding:24px;max-width:720px">${body}</div></body></html>`);

  const app = express();
  app.disable('x-powered-by');

  app.get('/', (req, res) => {
    const c = current(req);
    if (!c) return html(res, 200, '<h2>Not signed in</h2><p><a href="/login">Sign in with IBM Verify</a></p>');
    const s = c.s;
    html(res, 200, `<h2>Signed in</h2><table cellpadding="4">` +
      `<tr><td>User</td><td><b>${esc(s.user)}</b></td></tr><tr><td>Subject</td><td>${esc(s.sub)}</td></tr>` +
      `<tr><td>Groups</td><td>${esc(s.groups.join(', '))}</td></tr><tr><td>Login methods (amr)</td><td>${esc((s.amr || []).join(', '))}</td></tr>` +
      `<tr><td>Verify session (sid)</td><td>${esc(s.idpSid)}</td></tr><tr><td>Access token lifetime</td><td>${esc(s.expiresIn)} s</td></tr></table>` +
      `<p><a href="/protected">/protected</a> &nbsp; <a href="/logout">Log out (global)</a> &nbsp; <a href="/local-logout">Local logout (this app only)</a></p>`);
  });

  app.get('/login', (req, res) => {
    const state = rand(16); const nonce = rand(16); const verifier = rand(32);
    txns.set(state, { nonce, verifier });
    const q = new URLSearchParams({
      response_type: 'code', client_id: clientId, redirect_uri: `${origin}/callback`, scope: 'openid profile email', state, nonce,
      code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
    });
    if (req.query.prompt) q.set('prompt', String(req.query.prompt));
    if (req.query.max_age) q.set('max_age', String(req.query.max_age));
    res.redirect(`${ENDPOINT}/authorize?${q}`);
  });

  app.get('/callback', async (req, res) => {
    const { code, state, error, error_description: desc } = req.query;
    const txn = txns.get(state); txns.delete(state);
    if (error) { note({ type: 'login_error', error }); return html(res, error === 'login_required' ? 401 : 400, `<h2>Sign-in did not complete</h2><p>${esc(error)}: ${esc(desc)}</p>`); }
    if (!txn || !code) return html(res, 400, '<h2>Unknown or replayed sign-in request</h2>');
    const t = await send({
      method: 'post', url: `${ENDPOINT}/token`, validateStatus: () => true, auth: { username: clientId, password: clientSecret },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: `${origin}/callback`, code_verifier: txn.verifier }).toString(),
    });
    if (t.status !== 200) { note({ type: 'token_error', status: t.status }); return html(res, 502, `<h2>Token exchange failed</h2><p>HTTP ${t.status}</p>`); }
    let claims;
    try {
      claims = await verifyJwt(t.data.id_token, getJwks, { iss: issuer, aud: clientId });
      if (claims.nonce !== txn.nonce) throw new Error('nonce mismatch');
    } catch (e) { note({ type: 'id_token_rejected', reason: e.message }); return html(res, 400, `<h2>ID token rejected</h2><p>${esc(e.message)}</p>`); }
    const groups = [].concat(claims.groupIds || []);
    if (requireGroup && !groups.includes(requireGroup)) {
      note({ type: 'access_denied', sub: claims.sub, sid: claims.sid, needs: requireGroup });
      return html(res, 403, `<h2>Access denied by this application</h2><p>IBM Verify authenticated you (single sign-on worked), but ${esc(title)} only admits members of <b>${esc(requireGroup)}</b>. Each application enforces its own authorization from the claims.</p>`);
    }
    const id = rand(24);
    sessions.set(id, {
      user: claims.preferred_username || claims.name, sub: claims.sub, groups, amr: claims.amr, authTime: claims.auth_time, idpSid: claims.sid,
      expiresIn: t.data.expires_in, idToken: t.data.id_token, accessToken: t.data.access_token, at: Date.now(),
    });
    note({ type: 'signed_in', sub: claims.sub, sid: claims.sid });
    setCookie(res, id);
    res.redirect('/');
  });

  app.get('/protected', async (req, res) => {
    const c = current(req);
    if (!c) return res.status(401).json({ rp: key, error: 'no_session' });
    if (introspectEachRequest) {
      const r = await introspect(c.s.accessToken);
      if (r.status !== 200 || !r.data || r.data.active !== true) {
        sessions.delete(c.id); note({ type: 'session_dropped_by_introspection', sid: c.s.idpSid });
        return res.status(401).json({ rp: key, error: 'session_revoked_at_idp' });
      }
    }
    res.json({ rp: key, user: c.s.user, groups: c.s.groups, amr: c.s.amr, checkedWithVerify: introspectEachRequest });
  });

  app.get('/logout', (req, res) => {
    const c = current(req);
    const idToken = c && c.s.idToken;
    if (c) sessions.delete(c.id);
    setCookie(res, '', 0);
    note({ type: 'rp_initiated_logout', hadSession: !!c });
    if (!idToken) return res.redirect('/');
    res.redirect(`${ENDPOINT}/rplogout?${new URLSearchParams({ id_token_hint: idToken, post_logout_redirect_uri: `${origin}/`, state: rand(12) })}`);
  });

  app.get('/local-logout', (req, res) => {
    const c = current(req);
    if (c) sessions.delete(c.id);
    setCookie(res, '', 0);
    note({ type: 'local_logout_only', hadSession: !!c });
    res.redirect('/');
  });

  app.get('/frontchannel-logout', (req, res) => {
    const { iss, sid } = req.query;
    if (iss !== issuer || !sid) { note({ type: 'frontchannel_rejected', iss }); return res.status(400).send('bad request'); }
    const removed = dropWhere((s) => s.idpSid === sid);
    note({ type: 'frontchannel', sid, removed });
    res.set('Cache-Control', 'no-store').status(200).send('ok');
  });

  // OIDC Back-Channel Logout 1.0: the logout token is a signed JWT from the OP, with the logout event, sid and/or sub, and NO nonce.
  const backchannel = async (req, res) => {
    const reject = (reason) => { note({ type: 'backchannel_rejected', reason }); return res.status(400).set('Cache-Control', 'no-store').json({ error: 'invalid_request', error_description: reason }); };
    try {
      const c = await verifyJwt(req.body && req.body.logout_token, getJwks, { iss: issuer, aud: clientId });
      if (!c.events || !(BCL_EVENT in c.events)) return reject('no backchannel-logout event');
      if ('nonce' in c) return reject('nonce must not be present');
      if (!c.sid && !c.sub) return reject('neither sid nor sub');
      const removed = dropWhere((s) => (c.sid ? s.idpSid === c.sid : s.sub === c.sub));
      note({ type: 'backchannel', sid: c.sid, sub: c.sub, removed });
      return res.status(200).set('Cache-Control', 'no-store').send('');
    } catch (e) { return reject(e.message); }
  };
  app.post('/backchannel-logout', express.urlencoded({ extended: false }), backchannel);
  app.post('/bc/:name', express.urlencoded({ extended: false }), (req, res) => {
    const target = registry[req.params.name];
    if (!target) return res.status(404).json({ error: 'unknown_rp' });
    return target.backchannel(req, res);
  });

  app.get('/_events', (req, res) => res.json({ rp: key, sessions: sessions.size, events }));

  return { key, port, app, sessions, events, sessionCookie, backchannel };
}

// No host: listen dual-stack so a browser's `localhost` works whether it resolves to ::1 or 127.0.0.1.
const listen = (rp) => new Promise((resolve, reject) => {
  const srv = rp.app.listen(rp.port, () => resolve(srv));
  srv.on('error', (e) => reject(e.code === 'EADDRINUSE' ? new Error(`port ${rp.port} is busy (is demo/uc08-sso/serve.js running?)`) : e));
});

module.exports = { createRp, listen, verifyJwt, tenantJwks, ISSUER, BCL_EVENT };

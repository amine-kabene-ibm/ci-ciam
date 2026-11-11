'use strict';
// STUB brand portal for UC-10 "Per-brand login". One factory, one instance per brand, each on its own host name.
// A plain OIDC authorization-code relying party with PKCE against the real IBM Verify tenant. It stands in for a brand's customer site.
//   GET /                         the brand's own page (brand colour, name, legal text, support link) in ?lang=en|fr (default = the brand's language)
//   GET /login[?lang=&max_age=]   start sign-in at Verify with ui_locales=<lang>: Verify renders its login page in that language
//   GET /callback                 code exchange; ID token verified offline (RS256 via the tenant JWKS, iss, aud, exp, nonce)
//   GET /logout                   drop the local session, then Verify's rplogout
//   GET /_sessions                what this portal holds (no tokens)
// Sessions live in memory. Nothing secret is rendered: no tokens, no client secret.
// The Verify-hosted pages (login, second factor, errors) are NOT this stub's: the stub only chooses the language and the client.

const express = require('express');
const crypto = require('crypto');
const { BASE, send } = require('../../demo/lib/verify');
const { verifyJwt, tenantJwks, ISSUER } = require('../rp-sso/server');

const ENDPOINT = `${BASE}/v1.0/endpoint/default`;
const rand = (n) => crypto.randomBytes(n).toString('base64url');
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const cookiesOf = (req) => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((c) => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
const LANGS = ['en', 'fr'];

// cfg: {brand, clientId, clientSecret, log}. brand: see demo/uc10-brands/common.js (key, name, host, port, colour, dark, defaultLocale, text, supportUrl)
function createBrandPortal(cfg) {
  const { brand, clientId, clientSecret, log = () => {} } = cfg;
  const origin = `http://${brand.host}:${brand.port}`;
  const cookie = `ifc_${brand.key}_sid`;
  const sessions = new Map();
  const txns = new Map();
  const getJwks = tenantJwks();
  const events = [];
  const note = (e) => { events.push({ at: new Date().toISOString(), ...e }); log(`[portal-${brand.key}] ${JSON.stringify(e)}`); };
  const langOf = (req) => (LANGS.includes(req.query.lang) ? req.query.lang : brand.defaultLocale);
  const current = (req) => { const id = cookiesOf(req)[cookie]; return id && sessions.has(id) ? { id, s: sessions.get(id) } : null; };
  const setCookie = (res, v, maxAge) => res.append('Set-Cookie', `${cookie}=${v}; Path=/; HttpOnly; SameSite=Lax${maxAge === 0 ? '; Max-Age=0' : ''}`);

  const app = express();
  app.disable('x-powered-by');

  app.get('/', (req, res) => {
    const lang = langOf(req); const t = brand.text[lang]; const c = current(req);
    const other = lang === 'en' ? 'fr' : 'en';
    const signed = c
      ? `<h2>${esc(t.signIn)} OK</h2><table cellpadding="4">` +
        `<tr><td>Brand</td><td><b>${esc(brand.name)}</b></td></tr><tr><td>Account (sub)</td><td>${esc(c.s.sub)}</td></tr>` +
        `<tr><td>Sign-in methods (amr)</td><td>${esc((c.s.amr || []).join(', '))}</td></tr><tr><td>Verify session (sid)</td><td>${esc(c.s.sid)}</td></tr>` +
        `<tr><td>Language requested</td><td>${esc(c.s.lang)}</td></tr></table><p><a href="/logout">${esc(t.signOut)}</a></p>`
      : `<p><a href="/login?lang=${lang}" style="background:${brand.colour};color:#fff;padding:10px 20px;text-decoration:none">${esc(t.signIn)}</a></p>`;
    res.status(200).set('Cache-Control', 'no-store').type('html').send(
      `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><title>${esc(brand.name)}</title></head><body style="font-family:system-ui,sans-serif;margin:0">` +
      `<header style="background:${brand.colour};color:#fff;padding:16px 24px;font-size:22px">${esc(brand.name)}` +
      `<span style="float:right;font-size:14px"><a style="color:#fff" href="/?lang=en">EN</a> | <a style="color:#fff" href="/?lang=fr">FR</a></span></header>` +
      `<main data-brand="${brand.key}" data-lang="${lang}" data-signed-in="${c ? 'true' : 'false'}" style="padding:24px;max-width:720px">` +
      `<p style="font-size:18px;color:${brand.dark}">${esc(t.tagline)}</p>${signed}</main>` +
      `<footer style="border-top:3px solid ${brand.colour};padding:12px 24px;font-size:13px;color:#555">${esc(t.legal)} ` +
      `<a href="${esc(brand.supportUrl)}">${esc(t.support)}</a> &middot; <a href="/?lang=${other}">${other.toUpperCase()}</a></footer></body></html>`);
  });

  app.get('/login', (req, res) => {
    const state = rand(16); const nonce = rand(16); const verifier = rand(32); const lang = langOf(req);
    txns.set(state, { nonce, verifier, lang });
    const q = new URLSearchParams({
      response_type: 'code', client_id: clientId, redirect_uri: `${origin}/callback`, scope: 'openid profile email', state, nonce, ui_locales: lang,
      code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
    });
    if (req.query.max_age) q.set('max_age', String(req.query.max_age));
    if (req.query.prompt) q.set('prompt', String(req.query.prompt));
    res.redirect(`${ENDPOINT}/authorize?${q}`);
  });

  app.get('/callback', async (req, res) => {
    const { code, state, error, error_description: desc } = req.query;
    const txn = txns.get(state); txns.delete(state);
    const page = (status, body) => res.status(status).set('Cache-Control', 'no-store').type('html').send(`<!doctype html><meta charset="utf-8"><body style="font-family:system-ui">${body}`);
    if (error) { note({ type: 'login_error', error }); return page(400, `<h2>Sign-in did not complete</h2><p>${esc(error)}: ${esc(desc)}</p>`); }
    if (!txn || !code) return page(400, '<h2>Unknown or replayed sign-in request</h2>');
    const t = await send({
      method: 'post', url: `${ENDPOINT}/token`, validateStatus: () => true, auth: { username: clientId, password: clientSecret },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: `${origin}/callback`, code_verifier: txn.verifier }).toString(),
    });
    if (t.status !== 200) { note({ type: 'token_error', status: t.status }); return page(502, `<h2>Token exchange failed</h2><p>HTTP ${t.status}</p>`); }
    let claims;
    try {
      claims = await verifyJwt(t.data.id_token, getJwks, { iss: ISSUER, aud: clientId });
      if (claims.nonce !== txn.nonce) throw new Error('nonce mismatch');
    } catch (e) { note({ type: 'id_token_rejected', reason: e.message }); return page(400, `<h2>ID token rejected</h2><p>${esc(e.message)}</p>`); }
    const id = rand(24);
    sessions.set(id, { sub: claims.sub, amr: claims.amr, sid: claims.sid, lang: txn.lang, idToken: t.data.id_token, at: Date.now() });
    note({ type: 'signed_in', sub: claims.sub, sid: claims.sid, amr: claims.amr, lang: txn.lang });
    setCookie(res, id);
    res.redirect(`/?lang=${txn.lang}`);
  });

  app.get('/logout', (req, res) => {
    const c = current(req);
    if (c) sessions.delete(c.id);
    setCookie(res, '', 0);
    if (!c) return res.redirect('/');
    res.redirect(`${ENDPOINT}/rplogout?${new URLSearchParams({ id_token_hint: c.s.idToken, post_logout_redirect_uri: `${origin}/`, state: rand(12) })}`);
  });

  app.get('/_sessions', (req, res) => res.json({ brand: brand.key, sessions: [...sessions.values()].map((s) => ({ sub: s.sub, amr: s.amr, sid: s.sid, lang: s.lang })), events }));

  return { key: brand.key, port: brand.port, app, sessions, events, cookie };
}

// No host: listen dual-stack so *.localhost works whether it resolves to ::1 or 127.0.0.1.
const listen = (portal) => new Promise((resolve, reject) => {
  const srv = portal.app.listen(portal.port, () => resolve(srv));
  srv.on('error', (e) => reject(e.code === 'EADDRINUSE' ? new Error(`port ${portal.port} is busy (is demo/uc10-brands/serve.js running?)`) : e));
});

module.exports = { createBrandPortal, listen };

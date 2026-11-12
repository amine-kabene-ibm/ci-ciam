'use strict';
// STUB customer portal for UC-02 "Passkeys, OTP and authenticator-app fallback". One instance per assurance level (AAL1 / AAL2 / AAL3).
// It is the OIDC relying party from stubs/rp-sso (code + PKCE, ID token verified offline) PLUS the three things IFC's own digital team builds around Verify:
//   GET /settings          account settings: lists the customer's passkeys (Verify FIDO2 registrations API), nudges to enroll one, links to where it is added
//   GET /api/nudge         {passkeys, nudge}: the UX-nudge decision, so any screen can show "Add a passkey" when the signed-in customer has none
//   GET /api/methods?username=   identifier-first: which sign-in methods does this customer have? (passkey, authenticator app, e-mail). Admin API behind the portal.
// Passkeys are created on the Verify host (https://<tenant>/usc/ or the FIDO2 APIs): a browser only lets rpId = the page's own domain use a credential,
// so a page on localhost cannot register a passkey for the tenant's relying party [DOCS: WebAuthn rpId rules].
// Sessions in memory. Nothing secret is rendered: no tokens, no client secret.
const { createRp, listen } = require('../rp-sso/server');
const { api, BASE } = require('../../demo/lib/verify');

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const cookiesOf = (req) => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((c) => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
const q = (s) => String(s).replace(/"/g, '\\"');

async function passkeysOf(userId) {
  const r = await api('GET', '/v2.0/factors/fido2/registrations', { query: { search: `userId="${userId}"` }, quiet: true });
  return (r.data && r.data.fido2) || [];
}

function createPortal(cfg) {
  const rp = createRp({ ...cfg, title: cfg.title });
  const { app } = rp;
  const session = (req) => { const id = cookiesOf(req)[rp.sessionCookie]; return id && rp.sessions.has(id) ? rp.sessions.get(id) : null; };
  const page = (res, status, body) => res.status(status).set('Cache-Control', 'no-store').type('html').send(
    `<!doctype html><html><head><meta charset="utf-8"><title>${esc(cfg.title)}</title></head><body style="font-family:system-ui,sans-serif;margin:0">` +
    `<div style="background:${cfg.colour || '#0f62fe'};color:#fff;padding:14px 24px;font-size:20px">${esc(cfg.title)}</div><div style="padding:24px;max-width:720px">${body}</div></body></html>`);

  app.get('/settings', async (req, res) => {
    const s = session(req);
    if (!s) return page(res, 401, '<h2>Not signed in</h2><p><a href="/login">Sign in</a></p>');
    const keys = await passkeysOf(s.sub);
    const nudge = keys.length === 0
      ? `<div data-nudge="true" style="border-left:4px solid #f1c21b;background:#fcf4d6;padding:12px">Sign in faster and more safely: <b>add a passkey</b> on this device.</div>`
      : '<div data-nudge="false">Passkey enrolled. You can sign in without a password code.</div>';
    const rows = keys.map((k) => `<tr><td>${esc(k.attributes && k.attributes.nickname || k.id)}</td><td>${esc(k.created || '')}</td></tr>`).join('');
    page(res, 200, `<h2>Account settings</h2>${nudge}<h3>Your passkeys (${keys.length})</h3><table cellpadding="4">${rows}</table>` +
      `<p><a href="${esc(BASE)}/usc/">Add a passkey or a new device (IBM Verify self-care)</a></p><p><a href="/">Back</a></p>`);
  });

  app.get('/api/nudge', async (req, res) => {
    const s = session(req);
    if (!s) return res.status(401).json({ error: 'no_session' });
    const n = (await passkeysOf(s.sub)).length;
    res.json({ passkeys: n, nudge: n === 0 });
  });

  app.get('/api/methods', async (req, res) => {
    const name = String(req.query.username || '');
    if (!name) return res.status(400).json({ error: 'username required' });
    const u = await api('GET', '/v2.0/Users', { query: { filter: `userName eq "${q(name)}"`, attributes: 'id,emails' }, quiet: true });
    const user = u.data && u.data.Resources && u.data.Resources[0];
    // Same answer shape for an unknown identifier (no account enumeration): password is always offered.
    if (!user) return res.json({ methods: ['password'], passkeyFirst: false });
    const [keys, totp] = await Promise.all([passkeysOf(user.id), api('GET', '/v2.0/factors/totp', { query: { search: `userId="${user.id}"` }, quiet: true })]);
    const methods = ['password'];
    if (keys.length) methods.push('passkey');
    if (((totp.data && totp.data.totp) || []).some((t) => t.validated)) methods.push('authenticator-app');
    if ((user.emails || []).length) methods.push('email-otp');
    res.json({ methods, passkeyFirst: keys.length > 0 });
  });

  return rp;
}

module.exports = { createPortal, listen, passkeysOf };

'use strict';
// UC-03: plays what the customer does in the browser during the hosted "Forgot password" flow, and what the customer's mail client shows.
// [LIVE 2026-11-12] The flow is the Cloud Directory login's own: login page -> "Forgot password" -> user name -> e-mail with a 30-minute link ->
// "set new password" page. Every message code below was read from the real pages.
const { BASE, sleep } = require('../lib/verify');
const { Browser, attr, decode } = require('../uc08-sso/browser');
const uc01 = require('../uc01-registration/common');

const codes = (html) => [...new Set(String(html).match(/CSI[A-Z]{2}\d{4}[EWI]/g) || [])];
// The page reports its outcome in <meta name="errorMessage"> (a rejected attempt) or in the page body (done/expired). The template's own title,
// CSIAH0315I, is ALSO the code of "New password does not meet the password policy requirements" [LIVE], so the meta text is read first.
const errorMeta = (html) => (String(html).match(/<meta name="errorMessage" content="([^"]*)"/) || [])[1] || '';
const code = (html) => (errorMeta(html).match(/CSI[A-Z]{2}\d{4}[EWI]/) || codes(html).filter((x) => x !== 'CSIAH0315I'))[0] || (codes(html).includes('CSIAH0315I') ? 'CSIAH0315I' : null);

// Opens the portal's sign-in page, follows "Forgot password", submits the user name. Returns {code, ms}.
// CSIAH0323I = "If your account is valid and has a registered email address, a password reset email was sent" (same answer for unknown users).
async function requestReset(portalClientId, redirectUri, userName) {
  const t0 = Date.now();
  const url = `${BASE}/v1.0/endpoint/default/authorize?` + new URLSearchParams({ client_id: portalClientId, response_type: 'code', redirect_uri: redirectUri, scope: 'openid', state: 'ifcdemo03state0001', nonce: 'ifcdemo03nonce0001' });
  const b = new Browser(); const p = await b.get(url);
  const meta = p.html.match(/id="idSourcesMeta" content='([^']*)'/);
  if (!meta) return { code: null, error: 'sign-in page not recognised', ms: Date.now() - t0 };
  const cd = JSON.parse(meta[1].replace(/\\u003d/g, '=').replace(/\\u0026/g, '&')).find((s) => s.type === 'CLOUDDIRECTORY');
  const fp = cd.forgotPasswordOptions || {};
  if (!fp.enabled || !fp.forgotPasswordUrl) return { code: null, error: 'Forgot password is not enabled on the sign-in page', enabled: !!fp.enabled, ms: Date.now() - t0 };
  const f = await b.get(BASE + fp.forgotPasswordUrl);
  const form = f.html.match(/<form[^>]*login-main-form[^>]*>/);
  if (!form) return { code: code(f.html), error: 'forgot-password page not recognised', ms: Date.now() - t0 };
  const post = await b.post(new URL(attr(form[0], 'action'), f.url).href, { operation: 'verify', username: userName });
  return { code: code(post.html), enabled: true, ms: Date.now() - t0 };
}

// Waits for a message whose subject matches `subject`, newer than `sinceMs`, not in `seen` (a Set of message ids). Returns {msg, ms} or null.
async function waitForMail(inbox, subject, { sinceMs, seen = new Set(), timeoutMs = 120000 } = {}) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const ms = await uc01.readMessages(inbox);
    const hit = (ms || []).find((m) => subject.test(m.subject) && !seen.has(m.id) && (!sinceMs || m.at >= sinceMs - 2000));
    if (hit) { seen.add(hit.id); return { msg: hit, ms: Date.now() - t0 }; }
    await sleep(2500);
  }
  return null;
}
const resetLink = (msg) => { const m = msg.text.match(/https:\/\/[^\s\]]*stage=reset[^\s\]]*/); return m ? m[0] : null; };

// Opens the e-mailed link. Returns {browser, page, ok, code, action}. ok = the "set new password" form is shown.
async function openLink(link) {
  const b = new Browser(); const page = await b.get(link);
  const m = page.html.match(/<meta name="action" content="([^"]*)"/);
  return { browser: b, page, ok: !!m, code: code(page.html), action: m ? new URL(decode(m[1]), page.url).href : null };
}
// Submits the new password (field names are lowercase [LIVE]). CSIAH0324I = reset done; CSIAH0332I = rejected by the password policy.
// [LIVE] after a rejected attempt the page carries a NEW form action: posting to the old one again fails silently. We follow the new one.
async function setPassword(opened, newPassword, confirm = newPassword) {
  const r = await opened.browser.post(opened.action, { operation: 'verify', username: '', oldpassword: '', newpassword: newPassword, confirmpassword: confirm });
  const m = r.html.match(/<meta name="action" content="([^"]*)"/);
  if (m) opened.action = new URL(decode(m[1]), r.url).href;
  return { code: code(r.html), codes: codes(r.html), message: errorMeta(r.html).replace(/^CSI[A-Z]{2}\d{4}[EWI]\s*/, '').trim() || null, status: r.status };
}

module.exports = { requestReset, waitForMail, resetLink, openLink, setPassword, code, codes };

'use strict';
// A scripted "browser" for UC-08: cookie jars per origin, manual redirects, no JavaScript engine. It plays what a person does in a tab:
//   - follows redirects across the tenant and the local relying parties (RPs)
//   - IBM Verify hosted login: POSTs username/password to the `loginUrl` in the page's idSourcesMeta (basicldapuser policy)
//   - hosted TOTP page: POSTs {otp, operation:verify} to <meta name="action"> (the page's script copies it into the form)
//   - front-channel logout page: loads each iframe URL (as a browser would, WITHOUT the RP's cookies, because an iframe from the
//     tenant to localhost is cross-site) and posts the status form, which is what logout_frontchannel.min.js does on iframe load
// Deviation from a real browser: cookies are kept per origin (host:port); real browsers key by host only, so the RPs use distinct cookie names.
// Nothing here prints cookies, passwords or one-time codes.
const { send } = require('../lib/verify');

const decode = (s) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#x3[dD];/g, '=').replace(/&#39;/g, "'");
const attr = (tag, name) => { const m = tag.match(new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)')`, 'i')); return m ? decode(m[2] !== undefined ? m[2] : m[3]) : null; };
const title = (html) => ((html.match(/<title[^>]*>([^<]*)/i) || [])[1] || '').trim();

class Browser {
  constructor() { this.jars = new Map(); }
  jar(origin) { if (!this.jars.has(origin)) this.jars.set(origin, {}); return this.jars.get(origin); }
  cookieNames(origin) { return Object.keys(this.jar(origin)); }
  hasCookie(origin, name) { return !!this.jar(origin)[name]; }
  clear() { this.jars.clear(); }

  store(url, res) {
    const jar = this.jar(new URL(url).origin);
    for (const c of res.headers['set-cookie'] || []) {
      const [kv, ...attrs] = c.split(';');
      const i = kv.indexOf('=');
      const k = kv.slice(0, i); const v = kv.slice(i + 1);
      const gone = v === '' || attrs.some((a) => /^\s*max-age\s*=\s*(0|-)/i.test(a)) || attrs.some((a) => /^\s*expires\s*=/i.test(a) && new Date(a.split('=')[1]) < new Date());
      if (gone) delete jar[k]; else jar[k] = v;
    }
  }
  cookieHeader(url, topOrigin) {
    const origin = new URL(url).origin;
    if (topOrigin && topOrigin !== origin) return ''; // cross-site subresource: SameSite=Lax cookies are not sent
    return Object.entries(this.jar(origin)).map(([k, v]) => `${k}=${v}`).join('; ');
  }

  // One HTTP exchange chain: follows redirects (max 20). Returns {status, url, html, hops, ms}.
  async fetch(method, url, form, { topOrigin } = {}) {
    const t0 = Date.now(); const hops = [];
    let m = method; let u = url; let body = form;
    for (let i = 0; i < 20; i++) {
      const r = await send({
        method: m, url: u, maxRedirects: 0, validateStatus: () => true, transformResponse: (x) => x, timeout: 20000,
        headers: { Cookie: this.cookieHeader(u, topOrigin), ...(body ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {}) },
        data: body ? new URLSearchParams(body).toString() : undefined,
      });
      this.store(u, r);
      if (r.status >= 300 && r.status < 400 && r.headers.location) {
        hops.push(`${r.status} ${new URL(u).host}${new URL(u).pathname}`);
        u = new URL(r.headers.location, u).href; m = 'GET'; body = undefined;
        continue;
      }
      return { status: r.status, url: u, html: typeof r.data === 'string' ? r.data : JSON.stringify(r.data || ''), hops, ms: Date.now() - t0 };
    }
    throw new Error(`too many redirects from ${url}`);
  }
  get(url, opts) { return this.fetch('GET', url, undefined, opts); }
  post(url, form, opts) { return this.fetch('POST', url, form, opts); }

  classify(page) {
    const h = page.html;
    if (/id="idSourcesMeta"/.test(h) && /cloud-directory-form/.test(h)) return 'login';
    if (/name="consentForm"/.test(h)) return 'consent';
    if (/<form[^>]*name="statusForm"/.test(h)) return 'logout_frontchannel';
    if (/name="otp"/.test(h) && /<meta name="action"/.test(h)) return 'totp';
    if (/Template File Name: authentication\/(mfa|oidc)\/error/.test(h)) return 'tenant_error';
    return 'page';
  }
  tenantError(page) {
    const m = page.html.match(/(CSI[A-Z]{2}\d{4}[EWI][^<"]{0,160})/);
    return m ? m[1] : title(page.html);
  }

  // Front-channel logout, as done by the tenant's logout page in a real browser.
  async frontChannelLogout(page) {
    const iframes = [...page.html.matchAll(/<iframe[^>]*src="([^"]*)"/g)].map((m) => decode(m[1]));
    const topOrigin = new URL(page.url).origin;
    const loaded = [];
    for (const src of iframes) {
      try {
        const r = await this.get(src, { topOrigin });
        loaded.push({ url: src.replace(/\?.*/, ''), status: r.status, ms: r.ms });
      } catch (e) { loaded.push({ url: src.replace(/\?.*/, ''), status: 0, error: e.message.slice(0, 60) }); }
    }
    const form = {};
    for (const tag of page.html.match(/<input[^>]*>/g) || []) { const n = attr(tag, 'name'); if (n) form[n] = attr(tag, 'value') || ''; }
    for (const k of Object.keys(form)) if (/^status\d+$/.test(k)) form[k] = 'success'; // updateStatus() in logout_frontchannel.min.js sets the value to "success" on iframe load
    const action = new URL(attr(page.html.match(/<form[^>]*name="statusForm"[^>]*>/)[0], 'action'), page.url).href;
    const done = await this.post(action, form);
    return { iframes: loaded, final: done };
  }

  // Opens a URL like a person would and handles the Verify pages on the way.
  // creds: {username, password, totp: async () => code}. Without creds the walk stops at the page that needs them.
  // Returns {status, url, html, kind, steps, ms, logout?}. `steps` lists the Verify pages shown (login, totp, consent, ...).
  async open(url, creds = {}) {
    const t0 = Date.now(); const steps = [];
    let page = await this.get(url); let logout = null;
    for (let i = 0; i < 10; i++) {
      const kind = this.classify(page);
      if (kind === 'login') {
        steps.push('login');
        if (!creds.username) return { ...page, kind, steps, ms: Date.now() - t0, logout };
        const meta = page.html.match(/id="idSourcesMeta" content='([^']*)'/);
        const src = JSON.parse(meta[1].replace(/\\u003d/g, '=').replace(/\\u0026/g, '&'));
        const loginUrl = src.find((s) => s.type === 'CLOUDDIRECTORY').loginUrl;
        page = await this.post(loginUrl, { username: creds.username, password: creds.password, operation: 'verify', error_redirect_support: 'true' });
        if (this.classify(page) === 'login') return { ...page, kind: 'login_failed', steps, ms: Date.now() - t0, logout };
      } else if (kind === 'consent') {
        steps.push('consent');
        const form = {};
        for (const tag of page.html.match(/<input[^>]*>/g) || []) { const n = attr(tag, 'name'); if (n && attr(tag, 'type') === 'hidden') form[n] = attr(tag, 'value') || ''; }
        const action = attr(page.html.match(/<form[^>]*name="consentForm"[^>]*>/)[0], 'action');
        page = await this.post(new URL(action, page.url).href, form);
      } else if (kind === 'totp') {
        steps.push('totp');
        if (!creds.totp) return { ...page, kind, steps, ms: Date.now() - t0, logout };
        const meta = page.html.match(/<meta name="action" content="([^"]*)"/);
        page = await this.post(new URL(decode(meta[1]), page.url).href, { otp: String(await creds.totp()), operation: 'verify' });
        if (this.classify(page) === 'totp') return { ...page, kind: 'totp_failed', steps, ms: Date.now() - t0, logout };
      } else if (kind === 'logout_frontchannel') {
        steps.push('logout_frontchannel');
        logout = await this.frontChannelLogout(page);
        page = logout.final;
      } else {
        return { ...page, kind, steps, ms: Date.now() - t0, logout };
      }
    }
    return { ...page, kind: 'too_many_steps', steps, ms: Date.now() - t0, logout };
  }
}

module.exports = { Browser, attr, decode, title };

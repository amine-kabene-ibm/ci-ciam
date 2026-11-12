'use strict';
// Shared helper for the IFC demo scripts. See DEMO-BUILD-GUIDE.md section 1.2 for why each rule exists.
//  - reads .env (never prints secret values)
//  - caches the client_credentials token (about 2 h lifetime), refreshes on 401
//  - SCIM paths get Content-Type + Accept: application/scim+json
//  - never throws on HTTP errors: returns {status, data, cid, ms} and logs the x-correlation-id
//  - axios exposes .status, never .statusCode
//  - createClient(id, secret) gives the same API bound to another API client (least-privilege demos)

const path = require('path');
const fs = require('fs');
const axios = require('axios');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });

const BASE = (process.env.OIDC_CI_BASE_URI || '').replace(/\/+$/, '');
const OUT_DIR = path.join(__dirname, '..', 'out');
const PREFIX = 'ifc-demo-';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isScim = (p) => /^\/v2\.0\/(Users|Groups|Me|Schema)/.test(p);

// The laptop resolver sometimes fails for a few seconds (ENOTFOUND / EAI_AGAIN) [LIVE, 2026-11-10]. Retry those, and never let an
// axios error escape: it carries the request config, i.e. the client secret, into logs. Rethrow a message-only error instead.
const TRANSIENT = new Set(['ENOTFOUND', 'EAI_AGAIN', 'ECONNRESET', 'ETIMEDOUT', 'ECONNREFUSED']);
async function send(config) {
  for (let i = 0; ; i++) {
    try { return await axios(config); } catch (e) {
      if (TRANSIENT.has(e.code) && i < 6) { await sleep(2000 * (i + 1)); continue; }
      throw new Error(`network error ${e.code || ''} ${config.method} ${String(config.url).replace(/\?.*/, '')}`);
    }
  }
}

function createClient(clientId, clientSecret) {
  let tokenCache = null; // {token, exp}

  async function getToken(force) {
    if (!force && tokenCache && tokenCache.exp > Date.now() + 60000) return tokenCache.token;
    const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret });
    const r = await send({
      method: 'post', url: `${BASE}/v1.0/endpoint/default/token`, data: body.toString(),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      validateStatus: () => true,
    });
    if (r.status !== 200 || !r.data.access_token) {
      throw new Error(`client_credentials failed: HTTP ${r.status} ${JSON.stringify(r.data).slice(0, 200)}`);
    }
    tokenCache = { token: r.data.access_token, exp: Date.now() + (r.data.expires_in || 3600) * 1000 };
    return tokenCache.token;
  }

  // opts: {body, form, headers, query, noAuth, quiet, binary}  (binary: data is returned as a Buffer, e.g. a QR PNG)
  async function api(method, p, opts = {}) {
    const run = async (force) => {
      const headers = { Accept: 'application/json', ...(opts.headers || {}) };
      if (!opts.noAuth) headers.Authorization = `Bearer ${await getToken(force)}`;
      let data;
      if (opts.form) {
        data = new URLSearchParams(opts.form).toString();
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
      } else if (opts.body !== undefined) {
        data = opts.body;
        headers['Content-Type'] = 'application/json';
      }
      if (isScim(p)) {
        headers.Accept = 'application/scim+json';
        if (data !== undefined) headers['Content-Type'] = 'application/scim+json';
      }
      const t0 = Date.now();
      const r = await send({
        method, url: BASE + p, headers, data, params: opts.query,
        validateStatus: () => true, transformResponse: (x) => x, ...(opts.binary ? { responseType: 'arraybuffer' } : {}),
      });
      let parsed = r.data;
      if (opts.binary) parsed = r.status < 300 ? Buffer.from(r.data) : (() => { try { return JSON.parse(Buffer.from(r.data).toString()); } catch (e) { return null; } })();
      else if (typeof parsed === 'string' && parsed.length) { try { parsed = JSON.parse(parsed); } catch (e) { /* keep raw */ } }
      if (parsed === '') parsed = null;
      return { status: r.status, data: parsed, cid: r.headers['x-correlation-id'] || null, ms: Date.now() - t0 };
    };
    let res = await run(false);
    if (res.status === 401 && !opts.noAuth) res = await run(true);
    if (res.status >= 400 && !opts.quiet) {
      console.log(`  ! ${method} ${p} -> ${res.status} cid=${res.cid} ${JSON.stringify(res.data || '').slice(0, 200)}`);
    }
    return res;
  }

  return { api, getToken };
}

// OAuth-client calls (HTTP Basic client auth) for token work: introspect, RFC 8693 exchange, revoke, password grant.
// Same return shape as api(): {status, data, cid, ms}. Tokens are never logged. [LIVE] 2026-11-10:
//   /oauth2/introspect accepts an STS client or the app's own client; /oauth2/token with grant_type token-exchange works with an STS client;
//   the password grant needs a DCR client with grant_types ["password"] and all_users_entitled (the app's default client refuses it).
function oauthClient(clientId, clientSecret) {
  const basic = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  async function post(p, form) {
    const t0 = Date.now();
    const r = await send({
      method: 'post', url: BASE + p, data: new URLSearchParams(form).toString(), validateStatus: () => true, transformResponse: (x) => x,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', Authorization: basic },
    });
    let data = r.data;
    if (typeof data === 'string') { try { data = data.length ? JSON.parse(data) : null; } catch (e) { data = { error: 'non_json_response' }; } }
    return { status: r.status, data, cid: r.headers['x-correlation-id'] || null, ms: Date.now() - t0 };
  }
  const TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
  return {
    introspect: (token) => post('/oauth2/introspect', { token, token_type_hint: 'access_token' }),
    revoke: (token) => post('/oauth2/revoke', { token, token_type_hint: 'access_token' }),
    exchange: (subjectToken) => post('/oauth2/token', {
      grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange', subject_token: subjectToken,
      subject_token_type: TOKEN_TYPE, requested_token_type: TOKEN_TYPE,
    }),
    passwordGrant: (username, password) => post('/oidc/endpoint/default/token', { grant_type: 'password', username, password, scope: 'openid' }),
    // CIBA (UC-14) [LIVE 2026-11-12]: /oauth2/ciba with HTTP Basic client auth -> {auth_req_id, expires_in, interval}; poll /oauth2/token.
    ciba: (form) => post('/oauth2/ciba', form),
    cibaToken: (authReqId) => post('/oauth2/token', { grant_type: 'urn:openid:params:grant-type:ciba', auth_req_id: authReqId }),
  };
}

// Default client = the privileged API client from .env
const admin = createClient(process.env.API_CLIENT_ID, process.env.API_SECRET);

// Evidence logger: demo/out/<name>.json. Never put secrets or OTP values in here.
function evidence(name) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const file = path.join(OUT_DIR, `${name}.json`);
  const doc = { name, tenant: BASE, startedAt: new Date().toISOString(), steps: [] };
  return {
    file,
    doc,
    step(title, info) {
      doc.steps.push({ at: new Date().toISOString(), title, ...info });
    },
    save(extra) {
      Object.assign(doc, extra || {});
      doc.savedAt = new Date().toISOString();
      fs.writeFileSync(file, JSON.stringify(doc, null, 2));
      return file;
    },
  };
}

// Private (gitignored) state such as generated client secrets: demo/out/<name>.state.json
function stateFile(name) {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const file = path.join(OUT_DIR, `${name}.state.json`);
  return {
    file,
    read() { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (e) { return null; } },
    write(obj) { fs.writeFileSync(file, JSON.stringify(obj, null, 2), { mode: 0o600 }); },
    remove() { try { fs.unlinkSync(file); } catch (e) { /* none */ } },
  };
}

module.exports = {
  BASE, PREFIX, OUT_DIR, api: admin.api, getToken: admin.getToken, createClient, oauthClient, evidence, stateFile, sleep, send,
};

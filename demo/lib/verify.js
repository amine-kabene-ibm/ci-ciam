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

function createClient(clientId, clientSecret) {
  let tokenCache = null; // {token, exp}

  async function getToken(force) {
    if (!force && tokenCache && tokenCache.exp > Date.now() + 60000) return tokenCache.token;
    const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret });
    const r = await axios.post(`${BASE}/v1.0/endpoint/default/token`, body.toString(), {
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
      const r = await axios({
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
  BASE, PREFIX, OUT_DIR, api: admin.api, getToken: admin.getToken, createClient, evidence, stateFile, sleep,
};

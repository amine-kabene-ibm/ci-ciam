'use strict';
// STUB of IFC's policy API behind the gateway (UC-12). It is the "application" in the PDF's main flow:
//   1. takes the bearer token, introspects it with Verify (POST /oauth2/introspect, with its OWN STS client, never the admin client)
//   2. 401 if the token is not active (expired, revoked, user deactivated)
//   3. asks the relationship engine (OpenFGA): "can user:<sub> view|edit policy:<n>?"  -> allow / deny
//   4. answers with the decision AND the reasoning path (which relationships were walked), and logs it
// Authentication is Verify's job; "may this broker see this policy" is the engine's job; the token carries no policy-level claim.
//
//   GET  /api/policies             "all resources this user can access" (engine list-objects)
//   GET  /api/policies/:n          read   (needs can_view)
//   PUT  /api/policies/:n          write  (needs can_edit): body {note}
//   GET  /api/policies/:n/access   who can view / edit this policy (engine list-users): the audit question
//   GET  /api/log                  every decision, newest last
// Local console for the presenter (no auth: this is a demo stub on 127.0.0.1, standing in for the source system's change feed):
//   GET /  console UI ; GET /console/state ; GET /console/matrix ; POST /console/signin ; POST /console/call ; POST /console/change
const express = require('express');
const path = require('path');
const { oauthClient } = require('../../demo/lib/verify');

const RELATION = { view: 'can_view', edit: 'can_edit' };

// opts: { introspectClient:{clientId,secret}, getFga:()=>FgaClient, source, subs:{key:sub}, signIn:async(key)=>{token,idClaims}, applyChange:async(mutate)=>result }
function buildApp(opts) {
  const { source, subs } = opts;
  const app = express();
  app.use(express.json());
  const introspect = oauthClient(opts.introspectClient.clientId, opts.introspectClient.secret);
  const keyOfSub = (sub) => Object.keys(subs).find((k) => subs[k] === sub) || null;
  const labelOf = (sub) => { const k = keyOfSub(sub); const b = k && source.brokers[k]; return b ? `${b.given} ${b.family}` : sub; };
  const log = [];
  const notes = {}; // writes land here (the stub has no database)
  const tokens = {}; // console only: broker key -> {token, sub, iat, exp, idClaims}

  // ---- the reasoning path: which relationships were walked for this request. The DECISION comes from the engine's check;
  // this only explains it (run.js asserts the explanation always agrees with the engine and with the source system). ----
  async function explain(fga, sub, action, policyNumber) {
    const user = `user:${sub}`; const steps = [];
    const pol = `policy:${policyNumber}`;
    const c = (await fga.read({ object: pol, relation: 'client' }))[0];
    if (!c) return { steps: [{ fact: `${pol} is not in the relationship graph`, ok: false }], viaManager: false, viaServicing: false };
    steps.push({ fact: `${pol} belongs to ${c.user}`, ok: true });
    const b = (await fga.read({ object: c.user, relation: 'brokerage' }))[0];
    steps.push({ fact: `${c.user} is held by ${b ? b.user : 'no brokerage'}`, ok: !!b });
    const placed = (await fga.read({ object: c.user, relation: 'placed_by' })).some((t) => t.user === user);
    steps.push({ fact: `${labelOf(sub)} ${placed ? 'placed' : 'did not place'} ${c.user}`, ok: placed });
    const member = b ? (await fga.check(user, 'member', b.user)).allowed : false;
    steps.push({ fact: `${labelOf(sub)} ${member ? 'is' : 'is not'} a broker of ${b ? b.user : 'any brokerage'} today`, ok: member });
    const manager = b ? (await fga.check(user, 'manager', b.user)).allowed : false;
    steps.push({ fact: `${labelOf(sub)} ${manager ? 'is' : 'is not'} a manager of ${b ? b.user : 'any brokerage'}`, ok: manager });
    const viaServicing = placed && member; // servicing = placed_by AND member of the client's brokerage
    const viaManager = manager && action === 'view';
    return { steps, viaServicing, viaManager, conclusion: viaServicing || viaManager };
  }

  async function authenticate(req, res, path) {
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
    if (!m) { log.push({ at: new Date().toISOString(), path, decision: 'deny', reason: 'no_token', status: 401 }); res.status(401).json({ error: 'invalid_token', reason: 'no bearer token' }); return null; }
    const i = await introspect.introspect(m[1].trim());
    if (i.status !== 200 || !i.data || i.data.active !== true) {
      log.push({ at: new Date().toISOString(), path, decision: 'deny', reason: 'token_not_active', status: 401, introspectHttp: i.status, introspectMs: i.ms });
      res.status(401).json({ error: 'invalid_token', reason: 'token is not active (expired, revoked, or the user is deactivated)' });
      return null;
    }
    return { sub: i.data.sub, introspectMs: i.ms, username: i.data.preferred_username };
  }

  app.get('/health', (req, res) => res.json({ ok: true, service: 'policy-api-stub' }));
  app.get('/api/log', (req, res) => res.json(log));
  app.post('/api/log/reset', (req, res) => { log.length = 0; res.json({ ok: true }); });

  async function decide(req, res, action) {
    const policyNumber = req.params.n;
    const a = await authenticate(req, res, req.path); if (!a) return null;
    const fga = opts.getFga();
    const t0 = Date.now();
    const chk = await fga.check(`user:${a.sub}`, RELATION[action], `policy:${policyNumber}`);
    const why = await explain(fga, a.sub, action, policyNumber);
    const entry = {
      at: new Date().toISOString(), path: req.path, method: req.method, action, policy: policyNumber, sub: a.sub, who: labelOf(a.sub),
      decision: chk.allowed ? 'allow' : 'deny', reason: chk.allowed ? (why.viaServicing ? 'servicing_broker' : 'brokerage_manager') : 'no_relationship',
      path_taken: why.steps, introspectMs: a.introspectMs, checkMs: chk.ms, totalMs: Date.now() - t0 + a.introspectMs,
      consistent: why.conclusion === chk.allowed,
    };
    log.push(entry);
    return { a, chk, why, entry };
  }

  app.get('/api/policies/:n', async (req, res) => {
    const d = await decide(req, res, 'view'); if (!d) return;
    const p = source.policyInfo(req.params.n);
    if (!d.chk.allowed) return res.status(403).json({ error: 'forbidden', decision: 'deny', policy: req.params.n, reasoning: d.why.steps });
    if (!p) return res.status(404).json({ error: 'not_found' });
    res.json({ decision: 'allow', ...p, note: notes[req.params.n] || null, reasoning: d.why.steps, checkMs: d.entry.checkMs });
  });

  app.put('/api/policies/:n', async (req, res) => {
    const d = await decide(req, res, 'edit'); if (!d) return;
    if (!d.chk.allowed) return res.status(403).json({ error: 'forbidden', decision: 'deny', policy: req.params.n, reasoning: d.why.steps });
    notes[req.params.n] = String((req.body || {}).note || '').slice(0, 200);
    res.json({ decision: 'allow', policy: req.params.n, note: notes[req.params.n], reasoning: d.why.steps });
  });

  app.get('/api/policies', async (req, res) => {
    const a = await authenticate(req, res, req.path); if (!a) return;
    const fga = opts.getFga();
    const view = await fga.listObjects(`user:${a.sub}`, 'can_view', 'policy');
    const edit = await fga.listObjects(`user:${a.sub}`, 'can_edit', 'policy');
    const strip = (o) => o.replace(/^policy:/, '');
    const canEdit = new Set(edit.objects.map(strip));
    const items = view.objects.map(strip).sort().map((n) => ({ ...source.policyInfo(n), canEdit: canEdit.has(n) }));
    log.push({ at: new Date().toISOString(), path: req.path, method: 'GET', action: 'list', sub: a.sub, who: labelOf(a.sub), decision: 'allow', reason: 'list_objects', count: items.length, checkMs: view.ms, introspectMs: a.introspectMs });
    res.json({ user: labelOf(a.sub), count: items.length, policies: items, listMs: view.ms });
  });

  app.get('/api/policies/:n/access', async (req, res) => {
    const a = await authenticate(req, res, req.path); if (!a) return;
    const fga = opts.getFga();
    const [v, e] = [await fga.listUsers(`policy:${req.params.n}`, 'can_view', 'user'), await fga.listUsers(`policy:${req.params.n}`, 'can_edit', 'user')];
    const name = (u) => labelOf(u.replace(/^user:/, ''));
    res.json({ policy: req.params.n, canView: v.users.map(name).sort(), canEdit: e.users.map(name).sort() });
  });

  // ------------------------------- presenter console -------------------------------
  app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'console.html')));

  app.get('/console/state', (req, res) => {
    res.json({
      brokerages: source.brokerages,
      brokers: Object.entries(source.brokers).map(([key, b]) => ({ key, ...b, sub: subs[key], signedIn: tokens[key] ? { iat: tokens[key].iat, exp: tokens[key].exp, department: tokens[key].idClaims.department || null } : null })),
      clients: source.clients, policies: source.policies,
    });
  });

  // The engine's own answer for every broker x policy (no token involved): shows the whole picture change at once.
  app.get('/console/matrix', async (req, res) => {
    const fga = opts.getFga(); const t0 = Date.now(); const out = {};
    for (const key of Object.keys(source.brokers)) {
      out[key] = {};
      for (const n of Object.keys(source.policies)) {
        out[key][n] = { view: (await fga.check(`user:${subs[key]}`, 'can_view', `policy:${n}`)).allowed, edit: (await fga.check(`user:${subs[key]}`, 'can_edit', `policy:${n}`)).allowed };
      }
    }
    res.json({ matrix: out, ms: Date.now() - t0, tuples: (await fga.read()).length });
  });

  app.post('/console/signin', async (req, res) => {
    const key = (req.body || {}).broker;
    if (!subs[key]) return res.status(400).json({ error: 'unknown broker' });
    try {
      const r = await opts.signIn(key);
      tokens[key] = r;
      res.json({ broker: key, sub: r.sub, iat: r.iat, exp: r.exp, idTokenClaims: { department: r.idClaims.department || null, title: r.idClaims.job_title || null, preferred_username: r.idClaims.preferred_username } });
    } catch (e) { res.status(502).json({ error: String(e.message).slice(0, 200) }); }
  });

  // Calls the gateway's own /api with the stored token, like a front-end would. The token itself is never returned.
  app.post('/console/call', async (req, res) => {
    const { broker, action, policy, note } = req.body || {};
    if (!subs[broker]) return res.status(400).json({ error: 'unknown broker' });
    let autoSignIn = false;
    if (!tokens[broker] || tokens[broker].exp * 1000 < Date.now() + 30000) { // no token yet, or about to expire: sign in for real
      try { tokens[broker] = await opts.signIn(broker); autoSignIn = true; } catch (e) { return res.status(502).json({ error: String(e.message).slice(0, 200) }); }
    }
    const axios = require('axios');
    const method = action === 'edit' ? 'put' : 'get';
    const url = action === 'list' ? '/api/policies' : action === 'who' ? `/api/policies/${policy}/access` : `/api/policies/${policy}`;
    const t0 = Date.now();
    const r = await axios({ method, url: `http://127.0.0.1:${req.socket.localPort}${url}`, data: action === 'edit' ? { note: note || 'note added from the console' } : undefined, headers: { Authorization: `Bearer ${tokens[broker].token}` }, validateStatus: () => true });
    res.json({ request: `${method.toUpperCase()} ${url}  Authorization: Bearer <token of ${broker}, iat ${tokens[broker].iat}${autoSignIn ? ', signed in just now' : ''}>`, status: r.status, body: r.data, ms: Date.now() - t0 });
  });

  app.post('/console/change', async (req, res) => {
    const b = req.body || {};
    try {
      const mutate = {
        move: (s) => s.moveBroker(b.broker, b.brokerage, !!b.withBook),
        leave: (s) => s.leaveBrokerage(b.broker),
        transfer: (s) => s.transferClient(b.client, b.broker),
        reset: (s) => s.reset(),
      }[b.type];
      if (!mutate) return res.status(400).json({ error: 'type must be move, leave, transfer or reset' });
      res.json(await opts.applyChange(mutate));
    } catch (e) { res.status(400).json({ error: String(e.message).slice(0, 200) }); }
  });

  return app;
}

function start(port, opts) {
  const app = buildApp(opts);
  return new Promise((resolve, reject) => {
    const server = app.listen(port, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

module.exports = { buildApp, start, RELATION };

'use strict';
// STUB of IFC's legacy credential store (UC-11). Stands in for the ISM / legacy IAM that holds policyholder and broker passwords as hashes.
//   GET  /health                 {ok, online, users}      always answers
//   GET  /export                 every record WITH its password hash (what a migration extract looks like)
//   POST /password-verify        {username, password} -> {valid, attributes}   the contract a just-in-time migration calls
//   POST /migrated               {username} or {username, clear:true}          cut-over tracking: when was this user copied to the new IdP
//   GET  /_stats                 {verifyCalls, exportCalls, migrated}          lets a test prove the legacy store was (not) consulted
//   POST /_admin/offline         {offline: true|false}                         simulate an outage / the cut-over "switch it off"
// While offline every route except /health, /_stats and /_admin answers 503. Only hashes are kept in memory, never the plaintext passwords.
const express = require('express');
const H = require('./hashes');

// records: [{login, scheme, password, lastLoginYear, attrs}]  (password is hashed at start-up and dropped)
function createLegacyStore(records) {
  const db = new Map();
  for (const r of records) {
    db.set(r.login, { login: r.login, scheme: r.scheme, hash: H.make(r.scheme, r.password), lastLoginYear: r.lastLoginYear, attrs: r.attrs, migratedAt: null });
  }
  const stats = { verifyCalls: 0, exportCalls: 0 };
  let online = true;

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());
  const gate = (req, res, next) => (online ? next() : res.status(503).json({ error: 'legacy_store_offline' }));

  app.get('/health', (req, res) => res.json({ ok: true, online, users: db.size }));
  app.get('/_stats', (req, res) => res.json({ ...stats, migrated: [...db.values()].filter((r) => r.migratedAt).length }));
  app.post('/_admin/offline', (req, res) => { online = !req.body.offline; res.json({ online }); });

  app.get('/export', gate, (req, res) => {
    stats.exportCalls++;
    res.json([...db.values()].map((r) => ({ ...r, schemeName: H.schemeOf(r.hash) })));
  });

  app.post('/password-verify', gate, (req, res) => {
    stats.verifyCalls++;
    const { username, password } = req.body || {};
    const r = db.get(username);
    // Same answer for "no such user" and "wrong password": a login service must not reveal which one it was.
    if (!r || typeof password !== 'string' || !H.check(r.hash, password)) return res.json({ valid: false });
    res.json({ valid: true, attributes: { ...r.attrs, scheme: H.schemeOf(r.hash) } });
  });

  app.post('/migrated', gate, (req, res) => {
    const r = db.get((req.body || {}).username);
    if (!r) return res.status(404).json({ error: 'unknown_user' });
    r.migratedAt = req.body.clear ? null : new Date().toISOString();
    res.json({ username: r.login, migratedAt: r.migratedAt });
  });

  return { app, db, stats, setOnline: (v) => { online = v; } };
}

const listen = (store, port) => new Promise((resolve, reject) => {
  const srv = store.app.listen(port, '127.0.0.1', () => resolve(srv));
  srv.on('error', (e) => reject(e.code === 'EADDRINUSE' ? new Error(`port ${port} is busy (is demo/uc11-migration/serve.js running?)`) : e));
});

module.exports = { createLegacyStore, listen };

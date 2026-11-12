'use strict';
// Client 360 stand-in (UC-01). IFC's real Client 360 is the system of record for the customer profile; this stub only
// answers the one question the registration needs: "which Client 360 id belongs to this person?".
//   GET /client360?email=<e>[&policy=<no>&postalCode=<code>]   -> {client360_id, segment, policyMatched, policyNumber?, reason}
//   GET /stats                                                  -> {calls}   (how many lookups were made: proves no call at sign-in)
// Deterministic: a prospect gets an id derived from the e-mail hash; a known policy returns its customer's id, but only when the
// postal code matches (the "knowledge factor" for linking). Names, addresses and e-mails are never returned.
const express = require('express');
const crypto = require('crypto');

const POLICIES = {
  'AUTO-31877': { client360_id: 'C360-100231', postalCode: 'H2X1Y4', segment: 'auto-customer' },
  'HOME-40412': { client360_id: 'C360-100877', postalCode: 'M5V2T6', segment: 'home-customer' },
};

const norm = (s) => String(s || '').replace(/\s+/g, '').toUpperCase();
const prospectId = (email) => `C360-P${crypto.createHash('sha256').update(String(email || '').trim().toLowerCase()).digest('hex').slice(0, 8).toUpperCase()}`;

function lookup({ email, policy, postalCode }) {
  const prospect = { client360_id: prospectId(email), segment: 'prospect', policyMatched: false };
  if (!policy) return { ...prospect, reason: null };
  const p = POLICIES[norm(policy)];
  if (!p) return { ...prospect, reason: 'unknown_policy' };
  if (norm(postalCode) !== p.postalCode) return { ...prospect, reason: 'postal_code_mismatch' };
  return { client360_id: p.client360_id, segment: p.segment, policyMatched: true, policyNumber: norm(policy), reason: null };
}

function startServer(port = 4010) {
  const app = express();
  app.disable('x-powered-by');
  let calls = 0;
  app.get('/client360', (req, res) => {
    calls += 1;
    if (!req.query.email) return res.status(400).json({ error: 'email_required' });
    res.json(lookup({ email: req.query.email, policy: req.query.policy, postalCode: req.query.postalCode }));
  });
  app.get('/stats', (req, res) => res.json({ calls }));
  app.get('/health', (req, res) => res.json({ ok: true }));
  return new Promise((resolve, reject) => {
    const server = app.listen(port, '127.0.0.1', () => resolve({
      url: `http://127.0.0.1:${server.address().port}`, calls: () => calls, close: () => new Promise((r) => server.close(r)),
    }));
    server.on('error', reject);
  });
}

module.exports = { startServer, lookup, prospectId, POLICIES };

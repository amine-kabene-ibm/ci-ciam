'use strict';
// UC-15 serve.js — minimal Express server that shows the consent lifecycle for the demo.
// This supplements the main demo app: it provides an admin-view dashboard of purposes and consents.
// Port 4151. Start the main app on :3000 first (node ./bin/www).
//
// Routes:
//   GET /          — dashboard: list purposes, DCR clients, consent records
//   GET /dsp/:uid  — data-subject presentation for a user
//   GET /dua/:uid/:purposeId — DUA check for a user + purpose
//   GET /export    — full consent audit export (JSON)
//
// Run: node demo/uc15-consent/serve.js

const http    = require('http');
const express = require('express');
const { api, oauthClient, stateFile, BASE } = require('../lib/verify');
const { PURPOSES, CLIENTS, USER, listConsents, getDSP, checkDUA } = require('./common');

const app = express();
const PORT = 4151;
const sf   = stateFile('uc15');

app.set('x-powered-by', false);
app.use(express.json());

// ── helpers ───────────────────────────────────────────────────────────────────
async function getUserToken(userName, password) {
  const oc = oauthClient(process.env.OIDC_CLIENT_ID, process.env.OIDC_CLIENT_SECRET);
  const tok = await oc.passwordGrant(userName, password);
  return tok.status === 200 ? tok.data.access_token : null;
}

// ── routes ────────────────────────────────────────────────────────────────────
app.get('/', async (req, res) => {
  try {
    const st = sf.read() || {};
    const userId = st.user && st.user.id;

    // Purposes
    const pr = await api('GET', '/dpcm-mgmt/config/v1.0/privacy/purposes');
    const uc15Purposes = (pr.data && pr.data.purposes || []).filter((p) => p.id.startsWith('ifc-demo-uc15-'));

    // Consents
    const consents = userId ? await listConsents(userId) : [];

    // DCR clients
    const clients = st.clients || {};

    res.json({
      title:     'UC-15 Consent Management Dashboard',
      tenant:    BASE,
      user:      st.user ? { id: userId, userName: st.user.userName } : null,
      purposes:  uc15Purposes.map((p) => ({
        id:       p.id,
        state:    p.state,
        duration: p.defaultConsentDuration,
        attrCount: (p.attributes || []).length,
      })),
      dcrClients: Object.entries(clients).map(([name, c]) => ({
        name,
        clientId: c.clientId,
      })),
      consents:  consents.map((c) => ({
        purposeId: c.purposeId,
        state:     c.state,
        endTime:   c.endTime ? new Date(c.endTime * 1000).toISOString() : null,
      })),
      links: {
        dsp:    `/dsp/${userId}`,
        export: '/export',
        dua:    `/dua/${userId}/${PURPOSES[0].id}`,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/dsp/:uid', async (req, res) => {
  const st = sf.read();
  if (!st) return res.status(400).json({ error: 'run setup.js first' });
  try {
    const tok = await getUserToken(st.user.userName, st.user.password);
    if (!tok) return res.status(401).json({ error: 'password grant failed' });
    const dsp = await getDSP(tok, req.params.uid, PURPOSES.map((p) => p.id));
    res.json({ status: dsp.status, purposes: dsp.data && dsp.data.purposes });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/dua/:uid/:purposeId', async (req, res) => {
  const st = sf.read();
  if (!st) return res.status(400).json({ error: 'run setup.js first' });
  try {
    const tok = await getUserToken(st.user.userName, st.user.password);
    if (!tok) return res.status(401).json({ error: 'password grant failed' });
    const dua = await checkDUA(tok, req.params.uid, req.params.purposeId);
    res.json(dua);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/export', async (req, res) => {
  const st = sf.read();
  if (!st) return res.status(400).json({ error: 'run setup.js first' });
  try {
    const consents = await listConsents(st.user && st.user.id);
    res.json({
      exportedAt:  new Date().toISOString(),
      subject:     st.user,
      totalCount:  consents.length,
      consents:    consents,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── start ─────────────────────────────────────────────────────────────────────
http.createServer(app).listen(PORT, () => {
  const st = sf.read();
  console.log(`\nUC-15 consent dashboard on http://localhost:${PORT}`);
  console.log(`  GET /           — purposes, clients, consents`);
  console.log(`  GET /export     — full audit export (JSON)`);
  if (st) {
    console.log(`  GET /dsp/${st.user.id}  — DSP for test user`);
    console.log(`  GET /dua/${st.user.id}/${PURPOSES[0].id}`);
    console.log(`\n  Consent write path: http://localhost:3000 → sign in as ${USER.userName}`);
  }
  console.log('\n  Ctrl-C to stop\n');
});

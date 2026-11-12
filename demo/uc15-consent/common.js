'use strict';
// UC-15 Consent Management (PIPEDA) — shared constants and helpers.
// Every tenant object name starts with "ifc-demo-uc15-" so teardown-all.js finds it.
//
// KEY FINDING [LIVE 2026-11-12]:
//   CSIBT0032E "This API client can be used to create global consents only."
//   User-scoped consent WRITE via PATCH /dpcm/v1.0/privacy/consents requires a real browser
//   OIDC session (cookie). Password-grant tokens also get CSIBT0032E for per-user consent writes.
//   Global consents (not scoped to a user) are not meaningful for the PIPEDA demo.
//   DEMO PATH: consent write happens in the browser (existing /consent route in the demo app).
//   Everything else (purpose lifecycle, DCR, DSP, DUA, audit export) is fully scriptable.

const { api, PREFIX, stateFile, sleep } = require('../lib/verify');
const { ensureUser, deleteUsersByPrefix, ensureDcrClient, deleteApplicationsByPrefix } = require('../lib/idempotent');

const UC = 'uc15';
const P = `${PREFIX}${UC}-`;
const APP_ID = '3258669560154975753';  // TrustMeInsurance application id (from /setup) [LIVE]

// ── DPCM purpose definitions ────────────────────────────────────────────────
// Attribute IDs come from GET /v1.0/attributes/ on this tenant [LIVE 2026-11-12].
//   id=3  → email
//   id=6  → given_name
//   id=7  → family_name
//   id=11 → mobile_number
//   id=27 → work_postalcode
//
// Purpose defaultConsentDuration is in days.
const PURPOSES = [
  {
    id:          `${P}claims-processing`,
    description: 'IFC processes claims data to adjudicate insurance claims under your policy.',
    attrIds:     ['3', '6', '7'],  // email, given_name, family_name
    duration:    365,              // 1 year
  },
  {
    id:          `${P}fraud-analytics`,
    description: 'IFC shares selected data with its fraud-analytics engine to detect suspicious activity.',
    attrIds:     ['3', '27'],      // email, postal code
    duration:    180,              // 6 months
  },
  {
    id:          `${P}marketing`,
    description: 'IFC may contact you with personalised offers and product updates.',
    attrIds:     ['3', '11'],      // email, mobile
    duration:    90,               // 90 days
  },
];

// DCR clients that request consent for a specific purpose
const CLIENTS = [
  {
    name:      `${P}repair-shop`,
    purposeId: `${P}claims-processing`,
    scopes:    ['openid', 'profile', 'email'],
    label:     'Trusted Repair Shop',
  },
  {
    name:      `${P}comparison-site`,
    purposeId: `${P}marketing`,
    scopes:    ['openid', 'email'],
    label:     'Comparison Site',
  },
];

// Test user
const USER = {
  userName: `${P}policyholder`,
  email:    'ifc-demo-uc15@mailinator.com',
  given:    'Consent',
  family:   'Demo',
  password: 'Demo@IFIC2026!',
};

const state = stateFile(UC);

// ── DPCM helpers ─────────────────────────────────────────────────────────────

/**
 * Ensure a purpose exists and is published (state=1).
 * Idempotent: skips creation if the purpose already exists.
 */
async function ensurePurpose({ id, description, attrIds, duration }) {
  const g = await api('GET', `/dpcm-mgmt/config/v1.0/privacy/purposes/${encodeURIComponent(id)}`, { quiet: true });
  if (g.status === 200) return { id, created: false };

  const body = {
    id, name: id, description, category: 'default',
    defaultConsentDuration: duration || null,
    previousConsentApply: false, tags: [], customAttributes: [],
    accessTypes: [{ id: 'default' }, { id: 'read' }],
    attributes: attrIds.map((aid) => ({
      id: String(aid), mandatory: true, retentionPeriod: null,
      accessTypes: [{ id: 'read' }],
    })),
  };

  const c = await api('POST', '/dpcm-mgmt/config/v1.0/privacy/purposes', { body });
  if (c.status !== 201) throw new Error(`create purpose ${id}: HTTP ${c.status} cid=${c.cid} ${JSON.stringify(c.data).slice(0, 200)}`);

  const pub = await api('PATCH', `/dpcm-mgmt/config/v1.0/privacy/purposes/${encodeURIComponent(id)}/0`, {
    body: { op: 'replace', path: 'state', value: 1 },
  });
  if (pub.status !== 204) throw new Error(`publish purpose ${id}: HTTP ${pub.status} cid=${pub.cid}`);
  return { id, created: true };
}

/**
 * Associate a purpose with the TrustMeInsurance application.
 * Uses /dpcm-mgmt/config/v1.0/privacy/purpose-relationships [LIVE].
 * Tolerates 207 when the relationship already exists.
 */
async function associatePurposeWithApp(purposeId) {
  const r = await api('PATCH', '/dpcm-mgmt/config/v1.0/privacy/purpose-relationships', {
    body: [{ op: 'add', value: { extCategory: 'app', extId: APP_ID, purposeId } }],
  });
  // 204 = success, 207 with CSIBT0023E = already associated (both are OK)
  const ok = r.status === 204 || (r.status === 207 && JSON.stringify(r.data).includes('already'));
  return { status: r.status, ok };
}

/**
 * Dissociate a purpose from an application (must be done before delete).
 * 204 = removed; tolerates 207 (already dissociated).
 */
async function dissociatePurposeFromApp(purposeId, appId) {
  const r = await api('PATCH', '/dpcm-mgmt/config/v1.0/privacy/purpose-relationships', {
    body: [{ op: 'remove', value: { extCategory: 'app', extId: appId, purposeId } }],
    quiet: true,
  });
  return r.status;
}

/**
 * Delete a purpose by id. Dissociates from TrustMeInsurance first, then deletes. 404 = success.
 */
async function deletePurpose(id) {
  await dissociatePurposeFromApp(id, APP_ID);
  const r = await api('DELETE', `/dpcm-mgmt/config/v1.0/privacy/purposes/${encodeURIComponent(id)}`, { quiet: true });
  return r.status;
}

/**
 * List purposes whose id starts with a given prefix.
 */
async function listPurposesByPrefix(prefix) {
  const r = await api('GET', '/dpcm-mgmt/config/v1.0/privacy/purposes');
  if (r.status !== 200) return [];
  return (r.data.purposes || []).filter((p) => p.id.startsWith(prefix));
}

/**
 * List all consent records from the admin view (optionally filtered by userId).
 * Note: admin GET returns counts/metadata; per-user records require userId param [LIVE].
 */
async function listConsents(userId) {
  const query = userId ? { userId } : {};
  const r = await api('GET', '/dpcm-mgmt/config/v1.0/privacy/consents', { query });
  if (r.status !== 200) throw new Error(`list consents: HTTP ${r.status} cid=${r.cid}`);
  return r.data.consents || [];
}

/**
 * DUA check — needs a user token (password grant from a DCR client or TrustMeInsurance with ropc).
 * Returns {purposeId, approved, reason} for each item.
 * accessTypeId should match the attribute's accessType ('read' for our purposes).
 */
async function checkDUA(userToken, subjectId, purposeId) {
  const r = await api('POST', '/dpcm/v1.0/privacy/data-usage-approval', {
    body: { trace: false, items: [{ purposeId, accessTypeId: 'read' }], subjectId },
    headers: { Authorization: `Bearer ${userToken}` },
  });
  if (r.status !== 207 && r.status !== 200) return { approved: null, status: r.status, data: r.data };
  const items = Array.isArray(r.data) ? r.data : (r.data.items || []);
  const approved = items.length > 0 && items.every((i) =>
    (i.result || []).length > 0 && (i.result || []).every((x) => x.approved !== false)
  );
  return { approved, status: r.status, items };
}

/**
 * DSP (data subject presentation) — returns what Verify knows about this user's consent state.
 */
async function getDSP(userToken, subjectId, purposeIds) {
  const r = await api('POST', '/dpcm/v1.0/privacy/data-subject-presentation', {
    body: { purposeId: purposeIds, subjectId },
    headers: { Authorization: `Bearer ${userToken}` },
  });
  return { status: r.status, data: r.data };
}

/**
 * Delete all consent records for a user (admin DELETE).
 */
async function deleteConsentsForUser(userId) {
  const all = await listConsents(userId);
  const ids = all.map((c) => c.id).filter(Boolean);
  if (!ids.length) return { status: 204, deleted: 0 };
  const r = await api('DELETE', '/dpcm-mgmt/config/v1.0/privacy/consents', { body: ids, quiet: true });
  return { status: r.status, deleted: ids.length };
}

module.exports = {
  UC, P, APP_ID, PURPOSES, CLIENTS, USER, state,
  ensurePurpose, associatePurposeWithApp, dissociatePurposeFromApp, deletePurpose, listPurposesByPrefix,
  listConsents, checkDUA, getDSP, deleteConsentsForUser,
  ensureUser, deleteUsersByPrefix, ensureDcrClient, deleteApplicationsByPrefix,
  api, sleep,
};

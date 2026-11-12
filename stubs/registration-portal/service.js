'use strict';
// IFC registration service (UC-01). This is the "B2C systems trigger parts of the registration flow" API and the orchestration that
// Verify's Flow designer would host (Flow designer is NOT enabled on this tenant, so the orchestration lives here, in IFC code).
// Everything that is identity is done by Verify through its own APIs:
//   duplicate detection  -> SCIM filters (emails.value, phoneNumbers.value, custom attribute policyNumber)
//   verify the e-mail    -> /v2.0/factors/emailotp/transient/verifications (Verify sends the e-mail)
//   create the identity  -> POST /v2.0/Users (minimal data), group membership, Client 360 id stored on the identity
//   progressive profile  -> SCIM PATCH on later visits
// Verify never sees the Client 360 profile; this service asks the Client 360 stub once, at registration.
// Every method returns {status, ...} where status is the HTTP status the web layer should answer with. It never throws on a Verify error.
const crypto = require('crypto');
const axios = require('axios');

const CORE = 'urn:ietf:params:scim:schemas:core:2.0:User';
const ENT = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const IBM = 'urn:ietf:params:scim:schemas:extension:ibm:2.0:User';
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const q = (s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');

// ---- normalisation and validation (the "customizable duplicate-detection logic" lives here) ----
const normEmail = (s) => String(s || '').trim().toLowerCase();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const normPolicy = (s) => String(s || '').trim().toUpperCase().replace(/\s+/g, '');
const POLICY_RE = /^[A-Z]{2,6}-\d{4,8}$/;
const normPostal = (s) => String(s || '').toUpperCase().replace(/[\s-]+/g, '');
const POSTAL_RE = /^[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\d[ABCEGHJ-NPRSTV-Z]\d$/; // Canadian format
const fmtPostal = (s) => `${s.slice(0, 3)} ${s.slice(3)}`;
function normPhone(s) {
  const d = String(s || '').replace(/[^\d+]/g, '');
  if (/^\+\d{10,15}$/.test(d)) return d;
  if (/^\d{10}$/.test(d)) return `+1${d}`;
  if (/^1\d{10}$/.test(d)) return `+${d}`;
  return null;
}
const maskPhone = (p) => (p ? `${p.slice(0, 5)}***${p.slice(-4)}` : null);
const LANGS = ['fr-CA', 'en-CA'];

// Duplicate rules, switchable per IFC policy. IFC's PDF: "email, phone and matched policyholder ID".
const DEFAULT_RULES = { email: true, phone: true, policy: true };

// Progressive profiling stages. Stage 1 is the signup itself (e-mail + password). A stage is asked on a LATER sign-in, only while its
// required fields are empty, and only one stage at a time.
const STAGES = [
  { id: 'address', title: 'Where do you live?', required: ['postalCode', 'preferredLanguage'], optional: [], done: (s) => !!s.postalCode && !!s.preferredLanguage },
  { id: 'about', title: 'Tell us about your vehicle', required: ['hasVehicle'], optional: ['mobile'], done: (s) => !!s.hasVehicle },
];

// OTP API errors carry `messageId`; SCIM errors carry the code inside `detail` ("CSIAI0020E Password is too short.") [LIVE 2026-11-12].
const msgId = (d) => (d && (d.messageId || ((String(d.detail || '').match(/\b(CSI[A-Z]{2}\d{4}[A-Z])\b/) || [])[1]))) || null;
const customOf = (u) => Object.fromEntries((((u || {})[IBM] || {}).customAttributes || []).map((a) => [a.name, (a.values || [])[0]]));
function summarise(u) {
  const c = customOf(u); const a = (u.addresses || [])[0] || {}; const ph = (u.phoneNumbers || [])[0] || {};
  return {
    id: u.id, userName: u.userName, email: (u.emails || [])[0] ? u.emails[0].value : null,
    hasName: !!(u.name && (u.name.givenName || u.name.familyName)),
    postalCode: a.postalCode || null, preferredLanguage: u.preferredLanguage || null, mobile: ph.value || null,
    hasVehicle: c.hasVehicle || null, client360Id: c.client360Id || null, policyNumber: c.policyNumber || null,
    employeeNumber: (u[ENT] || {}).employeeNumber || null,
  };
}
const nextStageOf = (s) => STAGES.find((st) => !st.done(s)) || null;
const completeness = (s) => {
  const fields = [s.email, s.postalCode, s.preferredLanguage, s.hasVehicle];
  return Math.round((fields.filter(Boolean).length / fields.length) * 100);
};
const publicSummary = (s) => ({ ...s, mobile: maskPhone(s.mobile) });

function createRegistrationService({ api, client360Url, groupId, rules = DEFAULT_RULES, otpTtlMs = 5 * 60 * 1000, log = () => {} }) {
  const txns = new Map(); // local txn id -> {email, c360, verifyTxnId, correlation, retries, attempts, verified, used, expiresAt}

  // ----- directory lookups -----
  async function count(filter) {
    const r = await api('GET', '/v2.0/Users', { query: { filter, attributes: 'id,userName', count: 5 }, quiet: true });
    if (r.status !== 200) throw new Error(`directory lookup failed: HTTP ${r.status} cid=${r.cid}`);
    return { n: r.data.totalResults || 0, ids: (r.data.Resources || []).map((x) => x.id) };
  }
  // Which existing accounts match? Returns the identifiers that matched (never the accounts themselves).
  async function findDuplicates({ email, phone, policy, excludeUserId }) {
    const matchedOn = [];
    const check = async (kind, filter) => {
      const r = await count(filter);
      if (r.ids.filter((id) => id !== excludeUserId).length) matchedOn.push(kind);
    };
    if (rules.email && email) await check('email', `emails.value eq "${q(email)}"`);
    if (rules.phone && phone) await check('phone', `phoneNumbers.value eq "${q(phone)}"`);
    if (rules.policy && policy) await check('policy', `${IBM}:customAttributes.policyNumber eq "${q(policy)}"`);
    return matchedOn;
  }

  // ----- Client 360 (external system of record), called ONCE here, never at sign-in -----
  async function lookupClient360({ email, policy, postalCode }) {
    const t0 = Date.now();
    try {
      const r = await axios.get(`${client360Url}/client360`, { params: { email, ...(policy ? { policy, postalCode } : {}) }, timeout: 3000, validateStatus: () => true });
      if (r.status !== 200) return { available: false, ms: Date.now() - t0 };
      return { available: true, ms: Date.now() - t0, ...r.data };
    } catch (e) { return { available: false, ms: Date.now() - t0, error: e.code || 'error' }; }
  }

  // ----- step 1: minimal identifier -> duplicate check -> verification challenge -----
  async function start({ email: rawEmail, policyNumber, postalCode }) {
    const t0 = Date.now();
    const email = normEmail(rawEmail);
    if (!EMAIL_RE.test(email)) return { status: 400, error: 'invalid_email' };
    let policy = null;
    if (policyNumber) { policy = normPolicy(policyNumber); if (!POLICY_RE.test(policy)) return { status: 400, error: 'invalid_policy_number' }; }
    const c360 = await lookupClient360({ email, policy, postalCode });
    const policyLinked = !!(c360.available && c360.policyMatched);
    const matchedOn = await findDuplicates({ email, policy: policyLinked ? policy : null });
    if (matchedOn.length) return { status: 409, error: 'duplicate', matchedOn, next: 'sign_in_or_recover', ms: Date.now() - t0 };
    const correlation = String(crypto.randomInt(1000, 10000));
    const o = await api('POST', '/v2.0/factors/emailotp/transient/verifications', { body: { correlation, emailAddress: email }, quiet: true });
    if (o.status !== 201) {
      const id = o.data && o.data.messageId;
      return { status: id === 'CSIBN0075E' ? 422 : 502, error: id === 'CSIBN0075E' ? 'email_not_deliverable' : 'otp_not_sent', verifyMessageId: id || null, httpStatus: o.status };
    }
    const txn = crypto.randomBytes(12).toString('base64url');
    txns.set(txn, { email, c360, policy: policyLinked ? policy : null, verifyTxnId: o.data.id, correlation, retries: o.data.retries, attempts: 0, verified: false, used: false, expiresAt: Date.parse(o.data.expiry) || Date.now() + otpTtlMs });
    log(`start ${email} otp=${o.data.id} c360=${c360.available ? c360.segment : 'unavailable'}`);
    return {
      status: 200, txn, correlation, expiresAt: o.data.expiry, attemptsAllowed: o.data.retries + 1, policyLinked,
      client360: c360.available ? 'ok' : 'unavailable', otpSentMs: o.ms, ms: Date.now() - t0,
    };
  }

  // ----- step 2: prove the e-mail, set the password, create the identity with minimal data -----
  async function complete({ txn: txnId, code, password }) {
    const t0 = Date.now();
    const t = txns.get(txnId);
    if (!t) return { status: 404, error: 'unknown_transaction' };
    if (t.used) return { status: 409, error: 'already_used' };
    if (Date.now() > t.expiresAt) return { status: 410, error: 'code_expired' };
    if (!t.verified) {
      const digits = String(code || '').includes('-') ? String(code).split('-').pop().replace(/\D/g, '') : String(code || '').replace(/\D/g, '');
      const r = await api('POST', `/v2.0/factors/emailotp/transient/verifications/${t.verifyTxnId}`, { body: { otp: digits }, quiet: true });
      t.attempts += 1;
      if (r.status !== 204) {
        const id = r.data && r.data.messageId;
        if (id === 'CSIBN0080E') { t.used = true; return { status: 423, error: 'too_many_attempts', verifyMessageId: id }; }
        if (id === 'CSIBN0025E' || id === 'CSIBN0028E') return { status: 410, error: 'code_expired', verifyMessageId: id };
        return { status: 401, error: 'wrong_code', verifyMessageId: id || null, attemptsLeft: Math.max(t.retries + 1 - t.attempts, 0) };
      }
      t.verified = true; // ownership of the address is proven; a password problem below does not cost a new e-mail
    }
    // The account is not final yet: re-run the duplicate rules (two people can both be mid-registration).
    const matchedOn = await findDuplicates({ email: t.email, policy: t.policy });
    if (matchedOn.length) { t.used = true; return { status: 409, error: 'duplicate', matchedOn, stage: 'finalisation' }; }
    const custom = [];
    if (t.c360.available) custom.push({ name: 'client360Id', values: [t.c360.client360_id] });
    if (t.policy) custom.push({ name: 'policyNumber', values: [t.policy] });
    const body = {
      schemas: [CORE, ENT, IBM], userName: t.email, emails: [{ type: 'work', value: t.email }], password, active: true,
      ...(t.c360.available ? { [ENT]: { employeeNumber: t.c360.client360_id } } : {}), // the only way an attribute reaches the ID token (as employee_id) [LIVE]
      ...(custom.length ? { [IBM]: { customAttributes: custom } } : {}),
    };
    const c = await api('POST', '/v2.0/Users', { body, headers: { usershouldnotneedtoresetpassword: 'true' }, quiet: true });
    if (c.status !== 201) {
      const id = msgId(c.data);
      if (c.status === 409) { t.used = true; return { status: 409, error: 'duplicate', matchedOn: ['email'], stage: 'finalisation' }; }
      if (id === 'CSIAI0020E') return { status: 400, error: 'weak_password', verifyMessageId: id, otpStillValid: true };
      // CSIAI0313E "value ... already exists" is the tenant's `unique` constraint on policyNumber firing [LIVE]: the last line of defence behind the SCIM filter.
      if (c.status === 400 && id === 'CSIAI0313E' && t.policy) { t.used = true; return { status: 409, error: 'duplicate', matchedOn: ['policy'], stage: 'finalisation', note: 'unique constraint on policyNumber' }; }
      return { status: c.status === 400 ? 400 : 502, error: 'create_failed', verifyMessageId: id || null, httpStatus: c.status, otpStillValid: true };
    }
    t.used = true;
    const userId = c.data.id;
    const g = await api('PATCH', `/v2.0/Groups/${groupId}`, { body: { schemas: [PATCH], Operations: [{ op: 'add', path: 'members', value: [{ value: userId, type: 'user' }] }] }, quiet: true });
    log(`registered ${t.email} id=${userId} group=${g.status}`);
    return {
      status: 201, userId, client360Id: t.c360.available ? t.c360.client360_id : null, segment: t.c360.available ? t.c360.segment : null,
      policyLinked: !!t.policy, client360: t.c360.available ? 'ok' : 'unavailable', groupStatus: g.status, createMs: c.ms, ms: Date.now() - t0,
      nextStage: STAGES[0].id,
    };
  }

  // ----- later sign-in: what does the profile still need? -----
  async function getProfile(userId) {
    const r = await api('GET', `/v2.0/Users/${userId}`, { quiet: true });
    if (r.status !== 200) return { status: r.status === 404 ? 404 : 502, error: 'user_not_found', httpStatus: r.status };
    const s = summarise(r.data);
    const st = nextStageOf(s);
    return { status: 200, profile: s, nextStage: st ? { id: st.id, title: st.title, required: st.required, optional: st.optional } : null, completeness: completeness(s), ms: r.ms };
  }

  async function saveStage(userId, stageId, values = {}) {
    const stage = STAGES.find((x) => x.id === stageId);
    if (!stage) return { status: 400, error: 'unknown_stage' };
    const errors = {}; const ops = [];
    if (stageId === 'address') {
      const pc = normPostal(values.postalCode);
      if (!POSTAL_RE.test(pc)) errors.postalCode = 'invalid_postal_code';
      if (!LANGS.includes(values.preferredLanguage)) errors.preferredLanguage = 'invalid_language';
      if (!Object.keys(errors).length) {
        ops.push({ op: 'replace', path: 'addresses', value: [{ type: 'work', postalCode: fmtPostal(pc) }] });
        ops.push({ op: 'replace', path: 'preferredLanguage', value: values.preferredLanguage });
      }
    } else if (stageId === 'about') {
      if (!['yes', 'no'].includes(values.hasVehicle)) errors.hasVehicle = 'invalid_choice';
      let phone = null;
      if (values.mobile) {
        phone = normPhone(values.mobile);
        if (!phone) errors.mobile = 'invalid_phone';
        else if ((await findDuplicates({ phone, excludeUserId: userId })).includes('phone')) return { status: 409, error: 'duplicate', matchedOn: ['phone'] };
      }
      if (!Object.keys(errors).length) {
        ops.push({ op: 'add', path: `${IBM}:customAttributes`, value: [{ name: 'hasVehicle', values: [values.hasVehicle] }] });
        if (phone) ops.push({ op: 'replace', path: 'phoneNumbers', value: [{ type: 'mobile', value: phone }] });
      }
    }
    if (Object.keys(errors).length) return { status: 400, error: 'validation', fields: errors };
    const r = await api('PATCH', `/v2.0/Users/${userId}`, { body: { schemas: [PATCH], Operations: ops }, quiet: true });
    if (r.status !== 204) return { status: 502, error: 'save_failed', httpStatus: r.status, verifyMessageId: msgId(r.data) };
    const after = await getProfile(userId);
    return { status: 200, saved: stageId, patchMs: r.ms, nextStage: after.nextStage, completeness: after.completeness, profile: after.profile };
  }

  return { start, complete, getProfile, saveStage, findDuplicates, _txns: txns };
}

module.exports = {
  createRegistrationService, summarise, publicSummary, nextStageOf, completeness, customOf, normEmail, normPhone, normPostal, normPolicy,
  STAGES, DEFAULT_RULES, IBM, ENT, CORE, PATCH, maskPhone,
};

'use strict';
// Names, seed data and helpers shared by all UC-11 scripts. Everything on the tenant starts with "ifc-demo-uc11-".
// The legacy credential store is a STUB: eleven fictional policyholders and brokers, each with a legacy password-hash format.
const crypto = require('crypto');
const axios = require('axios');
const { PREFIX, BASE, stateFile, api: adminApi, createClient } = require('../lib/verify');

const UC = 'uc11';
const state = stateFile(UC);
const P = `${PREFIX}${UC}-`;
const LEGACY_PORT = 4050;
const GATEWAY_PORT = 4051;
const LEGACY_URL = `http://127.0.0.1:${LEGACY_PORT}`;
const GATEWAY_ORIGIN = `http://localhost:${GATEWAY_PORT}`;

const MIGRATOR = `${P}migrator`; // least-privilege API client used by the gateway and the bulk tool (NOT the admin client)
const MIGRATOR_ENTITLEMENTS = ['readUsers', 'manageUsers']; // [LIVE] enough to find, create, import (CSV) and delete users
const LOGIN_APP = `${P}login-gateway`; // password-grant client: how the gateway turns a verified password into Verify tokens
const PORTAL_APP = `${P}portal`; // authorization-code client: the standard Verify hosted login page, for migrated users

const randomSecret = (n) => crypto.randomBytes(n).toString('base64url');
const newPassword = () => ['Ifc', randomSecret(9), '8b'].join('-') + '!';
const WEAK_PASSWORD = ['Hock', 'ey1'].join(''); // 7 characters: the new platform's minimum is 8 [LIVE], the legacy store never enforced it

// cohort: bulk  = legacy hash Verify's CSV import understands, imported with "no forced reset": same password keeps working
//         reset = same hash, imported WITHOUT the no-reset header: the customer must choose a new password at first login
//         jit   = legacy hash Verify's import cannot read (or a password the new policy rejects): migrates on first login via the gateway
//         bad   = a record with bad data: the bulk job must report it, not hide it
const SEED = [
  { key: 'marie', cohort: 'bulk', scheme: 'SSHA256', role: 'policyholder', given: 'Marie', family: 'Tremblay', policy: 'IFC-100001', lang: 'fr', customerId: 'LEG-C-0001' },
  { key: 'paul', cohort: 'bulk', scheme: 'SHA512', role: 'policyholder', given: 'Paul', family: 'Gagnon', policy: 'IFC-100002', lang: 'en', customerId: 'LEG-C-0002' },
  { key: 'lucie', cohort: 'bulk', scheme: 'MD5', role: 'policyholder', given: 'Lucie', family: 'Roy', policy: 'IFC-100003', lang: 'fr', customerId: 'LEG-C-0003' },
  { key: 'brenda', cohort: 'bulk', scheme: 'SSHA', role: 'broker', given: 'Brenda', family: 'Cote', brokerage: 'BRG-042', brokerId: 'BRK-0007', lang: 'en', customerId: 'LEG-B-0007' },
  { key: 'rene', cohort: 'reset', scheme: 'SSHA256', role: 'policyholder', given: 'Rene', family: 'Lavoie', policy: 'IFC-100004', lang: 'fr', customerId: 'LEG-C-0004' },
  { key: 'jean', cohort: 'jit', scheme: 'PBKDF2', role: 'policyholder', given: 'Jean', family: 'Bouchard', policy: 'IFC-100005', lang: 'fr', customerId: 'LEG-C-0005' },
  { key: 'sophie', cohort: 'jit', scheme: 'PBKDF2', role: 'broker', given: 'Sophie', family: 'Morin', brokerage: 'BRG-042', brokerId: 'BRK-0011', lang: 'fr', customerId: 'LEG-B-0011' },
  { key: 'omar', cohort: 'jit', scheme: 'SMD5', role: 'policyholder', given: 'Omar', family: 'Haddad', policy: 'IFC-100006', lang: 'en', customerId: 'LEG-C-0006' },
  { key: 'weak', cohort: 'jit', scheme: 'PBKDF2', role: 'policyholder', given: 'Walter', family: 'Eakins', policy: 'IFC-100007', lang: 'en', customerId: 'LEG-C-0007', weak: true },
  { key: 'late', cohort: 'jit', scheme: 'PBKDF2', role: 'policyholder', given: 'Laura', family: 'Pelletier', policy: 'IFC-100008', lang: 'fr', customerId: 'LEG-C-0008' },
  { key: 'baddata', cohort: 'bad', scheme: 'SSHA256', role: 'policyholder', given: 'Bob', family: 'Dupuis', policy: 'IFC-100009', lang: 'en', customerId: 'LEG-C-0009', badEmail: true },
];
const userNameOf = (s) => `${P}${s.key}`;
const emailOf = (s) => (s.badEmail ? 'not-an-email' : `uc11.${s.key}@ifc-demo.invalid`);
const seed = (key) => SEED.find((s) => s.key === key);
const cohort = (name) => SEED.filter((s) => s.cohort === name);

// What the legacy store knows about a person and what must follow them to Verify: the account-to-policy and account-to-brokerage links.
const attrsOf = (s) => ({
  externalId: s.customerId, givenName: s.given, familyName: s.family, email: emailOf(s), preferredLanguage: s.lang,
  accountId: s.policy || null, department: s.brokerage || null, employeeNumber: s.brokerId || null,
});

// Records for the legacy store, from the private state (which holds the original passwords the customers know).
function legacyRecords(st) {
  return SEED.map((s) => ({ login: userNameOf(s), scheme: s.scheme, password: st.users[s.key].password, lastLoginYear: 2026, attrs: attrsOf(s) }));
}

// ---- CSV (the extract format) ----
const csvCell = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
const CSV_HEADER = ['preferred_username', 'given_name', 'family_name', 'email', 'password', 'externalId', 'accountId', 'department', 'employee_id', 'preferredLanguage'];
function buildCsv(rows) { // rows: [{login, hash, attrs}]
  const lines = [CSV_HEADER.join(',')];
  for (const r of rows) {
    const a = r.attrs;
    lines.push([r.login, a.givenName, a.familyName, a.email, r.hash, a.externalId, a.accountId, a.department, a.employeeNumber, a.preferredLanguage].map(csvCell).join(','));
  }
  return lines.join('\n') + '\n';
}

// POST /v2.0/CSV/importUsers [LIVE]: multipart field "file", async job (202 {_id}), status at /v2.0/CSV/jobs/{id}.
// noReset=true sends usershouldnotneedtoresetpassword, so the imported hash is the password the customer keeps using.
// A job with a row that has NO user name is dropped by the tenant (the job id then 404s): reported as state 'GONE'.
function multipart(csv) {
  const b = `----ifc${crypto.randomBytes(8).toString('hex')}`;
  const body = Buffer.concat([
    Buffer.from(`--${b}\r\nContent-Disposition: form-data; name="file"; filename="legacy-extract.csv"\r\nContent-Type: text/csv\r\n\r\n`),
    Buffer.from(csv, 'utf8'), Buffer.from(`\r\n--${b}--\r\n`)]);
  return { body, type: `multipart/form-data; boundary=${b}` };
}
async function importUsersCsv(client, csv, { noReset = true } = {}) {
  const token = await client.getToken();
  const m = multipart(csv);
  const t0 = Date.now();
  const r = await axios.post(`${BASE}/v2.0/CSV/importUsers?notifyType=NONE`, m.body, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/json', 'Content-Type': m.type, ...(noReset ? { usershouldnotneedtoresetpassword: 'true' } : {}) },
    validateStatus: () => true,
  }).catch(() => ({ status: 0, data: null, headers: {} }));
  if (r.status !== 202) return { accepted: false, status: r.status, cid: r.headers['x-correlation-id'] || null };
  let last;
  for (let i = 0; i < 40; i++) {
    await new Promise((s) => setTimeout(s, 1000));
    last = await client.api('GET', `/v2.0/CSV/jobs/${r.data._id}`, { quiet: true });
    if (last.status === 404) return { accepted: true, status: 202, state: 'GONE', ms: Date.now() - t0 };
    if (last.status === 200 && last.data.state === 'COMPLETED') break;
  }
  const st = (last.data && last.data.statistics) || {};
  return {
    accepted: true, status: 202, state: last.data && last.data.state, ms: Date.now() - t0,
    total: st.totalCount, processed: st.processedCount, errors: (st.errors || []).map((e) => ({ id: e.id, reason: e.failureReason })),
  };
}

// The migration actor's own API client, from the state file.
const migratorClient = (st) => createClient(st.migrator.clientId, st.migrator.clientSecret);

// Verify user by userName. Returns the SCIM resource or null.
async function verifyUser(userName, client = null) {
  const call = client ? client.api : adminApi;
  const r = await call('GET', '/v2.0/Users', { query: { filter: `userName eq "${String(userName).replace(/"/g, '\\"')}"` }, quiet: true });
  if (r.status !== 200) throw new Error(`lookup ${userName}: HTTP ${r.status} cid=${r.cid}`);
  return (r.data.Resources || [])[0] || null;
}
const linkageOf = (u) => u && ({
  externalId: u.externalId || null,
  accountId: (((u['urn:ietf:params:scim:schemas:extension:ibm:2.0:User'] || {}).customAttributes || []).find((a) => a.name === 'accountId') || { values: [null] }).values[0],
  department: (u['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] || {}).department || null,
  employeeNumber: (u['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'] || {}).employeeNumber || null,
  preferredLanguage: u.preferredLanguage || null,
});
const expectedLinkage = (s) => ({ externalId: s.customerId, accountId: s.policy || null, department: s.brokerage || null, employeeNumber: s.brokerId || null, preferredLanguage: s.lang });

// Remove every ifc-demo-uc11-* user (the new platform "before cut-over" is empty). Returns how many were deleted.
async function purgeUsers() {
  const idem = require('../lib/idempotent');
  return (await idem.deleteUsersByPrefix(P)).length;
}

module.exports = {
  UC, BASE, PREFIX, P, state, LEGACY_PORT, GATEWAY_PORT, LEGACY_URL, GATEWAY_ORIGIN, MIGRATOR, MIGRATOR_ENTITLEMENTS, LOGIN_APP, PORTAL_APP,
  SEED, seed, cohort, userNameOf, emailOf, attrsOf, legacyRecords, newPassword, randomSecret, WEAK_PASSWORD, buildCsv, importUsersCsv,
  migratorClient, verifyUser, linkageOf, expectedLinkage, purgeUsers,
};

'use strict';
// UC-11 scenario runner: legacy IAM migration against the REAL Verify tenant.
//   node demo/uc11-migration/run.js
// The legacy credential store and the JIT gateway (stubs) run in this process. Evidence (status codes, ids, timings; never passwords,
// hashes of real secrets, tokens or codes): demo/out/uc11.json.  Checks titled "LIMIT" assert a documented limitation (not a product win).
//   A. Pre-cutover: the new platform is empty, the legacy store holds 11 records in 5 hash formats
//   B. Which legacy hash formats does Verify's CSV import turn into a working login? (a matrix, live)
//   C. Bulk migration: extract -> CSV -> import job -> same passwords work, linkage attributes preserved, bad row reported not hidden
//   D. Bulk with a forced reset: the customer must choose a new password at first login (hosted Verify page)
//   E. Just-in-time: first login with a legacy password verified against the legacy store, user created in Verify
//   F. After JIT: the legacy store is switched OFF and the user still signs in (the credential now lives in Verify)
//   G. Safety rules of the pattern: unknown user, wrong password, no legacy call for migrated users, outage, no duplicates
//   H. Weak legacy password: correct but below the new policy -> choose a new one, nothing created before that
//   I. Rollback and re-migration
//   J. Least privilege: the migration tooling cannot do admin work
const crypto = require('crypto');
const { evidence, api, oauthClient, createClient, BASE } = require('../lib/verify');
const H = require('../../stubs/legacy-auth-store/hashes');
const { createLegacyStore, listen: listenLegacy } = require('../../stubs/legacy-auth-store/server');
const { createGateway, listen: listenGateway } = require('../../stubs/migration-gateway/server');
const { Browser, attr, decode } = require('../uc08-sso/browser');
const { migrateBulk } = require('./bulk');
const { rollback } = require('./rollback');
const idem = require('../lib/idempotent');
const axios = require('axios');
const c = require('./common');

const ev = evidence('uc11');
const results = [];
const note = (s) => console.log(`    ${s}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const st = c.state.read();
  if (!st || !st.migrator) { console.error('Run setup first: node demo/uc11-migration/setup.js'); process.exit(1); }
  const check = (scenario, title, pass, extra = {}) => {
    results.push({ scenario, title, pass });
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${title}`);
    ev.step(`${scenario}: ${title}`, { pass, ...extra });
  };
  const mig = c.migratorClient(st);
  const pw = (key) => st.users[key].password;
  const name = (key) => c.userNameOf(c.seed(key));
  const ropc = oauthClient(st.login.clientId, st.login.clientSecret);
  const loginStatus = async (key, password) => {
    const r = await ropc.passwordGrant(name(key), password === undefined ? pw(key) : password);
    return { status: r.status, error: r.data && (r.data.error_description || '').slice(0, 10), ms: r.ms };
  };

  // ---- start from the pre-cutover state, then bring up the legacy store and the gateway in process ----
  await c.purgeUsers();
  const store = createLegacyStore(c.legacyRecords(st));
  const legacySrv = await listenLegacy(store, c.LEGACY_PORT);
  const gw = createGateway({ legacyUrl: c.LEGACY_URL, migrator: mig, login: st.login, portal: st.portal, origin: c.GATEWAY_ORIGIN });
  const gwSrv = await listenGateway(gw, c.GATEWAY_PORT);
  const gwLogin = (body) => axios.post(`${c.GATEWAY_ORIGIN}/login`, body, { validateStatus: () => true }).then((r) => ({ status: r.status, ...r.data }));
  const legacyStats = async () => (await axios.get(`${c.LEGACY_URL}/_stats`)).data;
  const migrated = async (key) => !!(await c.verifyUser(name(key)));

  // ================================================================================================================
  console.log('\nA. Pre-cutover: an empty new platform, a legacy store with different hash formats');
  const exp = (await axios.get(`${c.LEGACY_URL}/export`)).data;
  const schemes = [...new Set(exp.map((r) => r.schemeName))].sort();
  check('A', `the legacy store holds ${exp.length} records in ${schemes.length} hash formats (${schemes.join(', ')})`, exp.length === c.SEED.length && schemes.length >= 5, { count: exp.length, schemes });
  check('A', 'no stored value is a plaintext password: every record is a hash', exp.every((r) => r.hash !== pw(c.SEED.find((s) => c.userNameOf(s) === r.login).key) && /^(\{[A-Z0-9]+\}|\$pbkdf2-)/.test(r.hash)));
  const gone = await Promise.all(c.SEED.map((s) => c.verifyUser(c.userNameOf(s))));
  check('A', 'the new platform has none of these users yet', gone.every((u) => !u), { found: gone.filter(Boolean).length });
  check('A', 'before cutover a legacy customer cannot sign in to Verify (unknown user)', (await loginStatus('marie')).status === 400);

  // ================================================================================================================
  console.log('\nB. Which legacy hash formats does the Verify CSV import accept? (live matrix: import the hash, sign in with the original password)');
  const matrixSeed = ['SSHA256', 'SHA256', 'SSHA384', 'SHA384', 'SSHA512', 'SHA512', 'SSHA', 'SHA', 'MD5', 'SMD5', 'SHA1', 'PBKDF2'];
  const mx = matrixSeed.map((scheme) => ({ scheme, login: `${c.P}mx-${scheme.toLowerCase()}`, password: ['Mx', c.randomSecret(6), '9!'].join('-') }));
  const mxRows = mx.map((m) => ({ login: m.login, hash: H.make(m.scheme, m.password), attrs: { givenName: 'Matrix', familyName: m.scheme, email: `uc11.mx.${m.scheme.toLowerCase()}@ifc-demo.invalid`, externalId: null, accountId: null, department: null, employeeNumber: null, preferredLanguage: 'en' } }));
  const mxJob = await c.importUsersCsv(mig, c.buildCsv(mxRows));
  check('B', `the import job is accepted (HTTP 202) and completes without errors for all ${mx.length} formats (the tenant does not reject a hash it cannot read)`, mxJob.accepted && mxJob.state === 'COMPLETED' && mxJob.processed === mx.length && !(mxJob.errors || []).length, { job: mxJob });
  const matrix = {};
  for (const m of mx) {
    const r = await ropc.passwordGrant(m.login, m.password);
    matrix[m.scheme] = r.status === 200 ? 'works' : 'fails';
  }
  const good = ['SSHA256', 'SHA256', 'SSHA384', 'SHA384', 'SSHA512', 'SHA512', 'SSHA', 'SHA', 'MD5'];
  check('B', `formats that sign in with the original password after import: ${good.join(', ')}`, good.every((s) => matrix[s] === 'works'), { matrix });
  check('B', 'LIMIT: {SMD5}, {SHA1} (the spelling) and a modern PBKDF2 hash import "successfully" but the customer can NOT sign in: they are stored as a literal string. Use just-in-time for them', ['SMD5', 'SHA1', 'PBKDF2'].every((s) => matrix[s] === 'fails'), { matrix });
  check('B', 'every format of the isVerifyImportable list in the stub matches what the tenant did (the safety filter in bulk.js is evidence-based)', matrixSeed.every((s) => (matrix[s] === 'works') === H.isVerifyImportable(s)), { matrix });
  const mxUsers = await Promise.all(mx.map((m) => c.verifyUser(m.login)));
  for (const u of mxUsers) if (u) await mig.api('DELETE', `/v2.0/Users/${u.id}`, { quiet: true });
  note('The matrix users are removed again; the tenant is back to empty.');

  // ================================================================================================================
  console.log('\nC. Bulk migration: extract from the legacy store, import with the original hashes, no password reset');
  const bulkNoBad = async () => migrateBulk({ legacyUrl: c.LEGACY_URL, client: mig, resetLogins: c.cohort('reset').map(c.userNameOf), log: note });
  const rep = await bulkNoBad();
  const importable = c.SEED.filter((s) => H.isVerifyImportable(s.scheme));
  const bulkErrors = rep.batches.flatMap((b) => b.errors || []);
  check('C', `the extract holds ${rep.extracted} records; ${rep.importable} have a hash format Verify can import, ${rep.leftForJit.length} are left for just-in-time (${[...new Set(rep.leftForJit.map((x) => x.scheme))].join(', ')})`, rep.extracted === c.SEED.length && rep.importable === importable.length && rep.leftForJit.length === c.SEED.length - importable.length, { importable: rep.importable, leftForJit: rep.leftForJit });
  check('C', 'the bulk jobs completed (HTTP 202 then COMPLETED) with the migrator client, not the admin client', rep.batches.length === 2 && rep.batches.every((b) => b.accepted && b.state === 'COMPLETED'), { batches: rep.batches.map((b) => ({ label: b.label, state: b.state, total: b.total, processed: b.processed, ms: b.ms })) });
  check('C', 'the bad record is REPORTED by the job (invalid e-mail), not silently dropped, and the good rows in the same file still migrate', bulkErrors.length === 1 && bulkErrors[0].id === name('baddata') && /CSIAI0096E/.test(bulkErrors[0].reason) && rep.batches.reduce((n, b) => n + b.processed, 0) === importable.length - 1, { errors: bulkErrors });
  const noReset = c.cohort('bulk');
  const t0 = Date.now();
  const logins = [];
  for (const s of noReset) logins.push({ key: s.key, scheme: s.scheme, ...(await loginStatus(s.key)) });
  check('C', `the original passwords work on the new platform, no reset: ${noReset.map((s) => `${s.key} {${s.scheme}}`).join(', ')}`, logins.every((l) => l.status === 200), { logins: logins.map((l) => ({ key: l.key, scheme: l.scheme, status: l.status, ms: l.ms })), totalMs: Date.now() - t0 });
  check('C', 'a wrong password is still refused for a migrated user', (await loginStatus('marie', 'Not-the-password-1!')).status === 400);
  const link = {};
  for (const s of [...noReset, ...c.cohort('reset')]) link[s.key] = c.linkageOf(await c.verifyUser(c.userNameOf(s)));
  check('C', 'account-to-policy linkage preserved: legacy customer id (externalId), policy number (accountId), preferred language on every migrated policyholder', c.SEED.filter((s) => s.role === 'policyholder' && link[s.key]).every((s) => JSON.stringify(link[s.key]) === JSON.stringify(c.expectedLinkage(s))), { link });
  const br = c.seed('brenda');
  check('C', 'account-to-brokerage linkage preserved: a broker keeps brokerage (department BRG-042) and broker id (employeeNumber BRK-0007)', link.brenda && link.brenda.department === br.brokerage && link.brenda.employeeNumber === br.brokerId && link.brenda.externalId === br.customerId, { broker: link.brenda });
  const byExt = await api('GET', '/v2.0/Users', { query: { filter: `externalId eq "${c.seed('marie').customerId}"`, attributes: 'userName' } });
  const byPolicy = await api('GET', '/v2.0/Users', { query: { filter: 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "BRG-042"', attributes: 'userName' } });
  check('C', 'the links are queryable: find the customer by legacy id (externalId) and every broker of a brokerage (department) through SCIM filters', byExt.status === 200 && byExt.data.totalResults === 1 && byPolicy.status === 200 && byPolicy.data.totalResults >= 1, { byExternalId: byExt.data.totalResults, byBrokerage: byPolicy.data.totalResults });
  const idem2 = await bulkNoBad();
  const allErrs = idem2.batches.flatMap((b) => b.errors || []);
  check('C', 'the bulk job is re-runnable: a second run imports nothing, reports "already exists" (CSIAI0047E) per row, and existing passwords are not overwritten', idem2.batches.every((b) => b.accepted && b.processed === 0) && allErrs.filter((e) => /CSIAI0047E/.test(e.reason)).length === importable.length - 1 && (await loginStatus('marie')).status === 200, { second: idem2.batches.map((b) => ({ label: b.label, processed: b.processed, errors: (b.errors || []).length })) });
  const mk = await axios.get(`${c.LEGACY_URL}/export`);
  check('C', 'cut-over tracking: the legacy store marks the bulk-migrated records as migrated', mk.data.filter((r) => r.migratedAt).length === rep.batches.reduce((n, b) => n + b.processed, 0), { markedMigrated: mk.data.filter((r) => r.migratedAt).length });

  // ================================================================================================================
  console.log('\nD. Bulk import WITH a forced reset: the customer must choose a new password at the first login');
  const rene = c.seed('rene');
  const r1 = await loginStatus('rene');
  check('D', `the reset cohort (${rene.key}) cannot sign in with the legacy password through an API: "The password must be changed" (CSIAQ0267E)`, r1.status === 400 && r1.error === 'CSIAQ0267E', { status: r1.status, code: r1.error });
  const g1 = await gwLogin({ username: name('rene'), password: pw('rene') });
  check('D', 'the gateway does not fall back to the legacy store for a user who exists in Verify: it tells the client a password change is required', g1.status === 403 && g1.outcome === 'password_change_required', { gateway: { status: g1.status, outcome: g1.outcome } });
  const q = new URLSearchParams({ response_type: 'code', client_id: st.portal.clientId, redirect_uri: `${c.GATEWAY_ORIGIN}/callback`, scope: 'openid', state: 'uc11-state-123', nonce: 'uc11-nonce-123', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256' });
  const brw = new Browser();
  const page = await brw.open(`${BASE}/v1.0/endpoint/default/authorize?${q}`, { username: name('rene'), password: pw('rene') });
  const isChange = /id="change-password-main-form"/.test(page.html);
  check('D', 'the hosted Verify page asks for a new password ("Change the initial password", with a Skip Now button): this is the reset experience, handled by Verify', isChange && /CSIAH0307I/.test(page.html), { page: (page.html.match(/<title[^>]*>([^<]*)/i) || [])[1], stepsBefore: page.steps });
  if (isChange) {
    const action = new URL(decode(page.html.match(/<meta name="action" content="([^"]*)"/)[1]), page.url).href;
    const oldField = attr(page.html.match(/<input[^>]*id="oldpassword"[^>]*>/)[0], 'value');
    const np = c.newPassword();
    // [LIVE] the hosted form takes operation=verify with old + new password (what its Submit button posts); the page then continues to the app.
    const done = await brw.post(action, { operation: 'verify', username: name('rene'), oldpassword: oldField, newpassword: np, confirmpassword: np }).catch(() => null);
    const after = await loginStatus('rene', np);
    const oldNow = await loginStatus('rene');
    check('D', 'the customer chooses a new password on the hosted page: the new one signs in and the legacy one no longer does (the change is done by Verify, not by an administrator)', after.status === 200 && oldNow.status === 400, { replay: done ? { status: done.status, title: (done.html.match(/<title[^>]*>([^<]*)/i) || [])[1] } : 'no response', newPasswordLogin: after.status, legacyPasswordLogin: oldNow.status });
  }
  const admin = await api('PATCH', `/v2.0/Users/${(await c.verifyUser(name('rene'))).id}`, {
    body: { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'replace', path: 'password', value: c.newPassword() }] }, headers: { usershouldnotneedtoresetpassword: 'true' } });
  check('D', 'for contrast: an administrator can set a password by SCIM PATCH (204) and clear the forced-change state in one call (used for support cases)', admin.status === 204, { status: admin.status });
  void rene;

  // ================================================================================================================
  console.log('\nE. Just-in-time migration: the first login verifies against the legacy store and creates the user in Verify');
  const jean = c.seed('jean');
  check('E', `${jean.key} (legacy {PBKDF2}, a format Verify cannot import) is not in Verify before the first login`, !(await migrated('jean')));
  const before = await legacyStats();
  const e1 = await gwLogin({ username: name('jean'), password: pw('jean') });
  const after1 = await legacyStats();
  check('E', 'first login with the legacy password succeeds through the gateway, no reset prompt', e1.status === 200 && e1.outcome === 'signed_in' && e1.source === 'legacy->verify' && e1.migrated === true && e1.tokenIssued, { status: e1.status, outcome: e1.outcome, source: e1.source, ms: e1.ms });
  check('E', 'the legacy store was consulted exactly once for that login (POST /password-verify)', after1.verifyCalls === before.verifyCalls + 1, { before: before.verifyCalls, after: after1.verifyCalls });
  const ju = await c.verifyUser(name('jean'));
  check('E', 'the user now exists in Verify, created with the verified password (Verify hashed it itself: re-hash on first login) and with the policy linkage', !!ju && ju.active && JSON.stringify(c.linkageOf(ju)) === JSON.stringify(c.expectedLinkage(jean)), { id: ju && ju.id, link: c.linkageOf(ju) });
  const jt = await ropc.passwordGrant(name('jean'), pw('jean'));
  check('E', 'a plain Verify sign-in with the same password now works with no gateway (native Verify credential)', jt.status === 200, { status: jt.status, ms: jt.ms });
  const s2 = c.seed('sophie');
  const e2 = await gwLogin({ username: name('sophie'), password: pw('sophie') });
  const su = await c.verifyUser(name('sophie'));
  check('E', 'JIT works for a broker too: brokerage and broker id come across with the first login', e2.status === 200 && e2.migrated === true && su && c.linkageOf(su).department === s2.brokerage && c.linkageOf(su).employeeNumber === s2.brokerId, { link: c.linkageOf(su) });
  const e3 = await gwLogin({ username: name('omar'), password: pw('omar') });
  check('E', 'JIT also covers a format the bulk import refuses ({SMD5})', e3.status === 200 && e3.migrated === true, { status: e3.status, outcome: e3.outcome, ms: e3.ms });
  check('E', 'the legacy store marks the JIT users as migrated (cut-over tracking)', ((await axios.get(`${c.LEGACY_URL}/export`)).data.filter((r) => [name('jean'), name('sophie'), name('omar')].includes(r.login) && r.migratedAt)).length === 3);

  // ================================================================================================================
  console.log('\nF. After JIT: switch the legacy store OFF; migrated users keep working');
  await axios.post(`${c.LEGACY_URL}/_admin/offline`, { offline: true });
  const callsAtOff = (await legacyStats()).verifyCalls;
  const f1 = await gwLogin({ username: name('jean'), password: pw('jean') });
  const f2 = await gwLogin({ username: name('marie'), password: pw('marie') });
  check('F', 'with the legacy store offline, a JIT-migrated user (jean) and a bulk-migrated user (marie) both still sign in', f1.status === 200 && f1.source === 'verify' && f2.status === 200 && f2.source === 'verify', { jean: f1.source, marie: f2.source });
  check('F', 'and the legacy store was not asked at all for them', (await legacyStats()).verifyCalls === callsAtOff, { verifyCalls: callsAtOff });
  const f3 = await gwLogin({ username: name('late'), password: pw('late') });
  check('F', 'a user who has NOT logged in yet cannot be migrated while the legacy store is down: 503 "temporarily unavailable", nothing created, no wrong "invalid password"', f3.status === 503 && f3.outcome === 'legacy_unavailable' && !(await migrated('late')), { status: f3.status, outcome: f3.outcome });
  await axios.post(`${c.LEGACY_URL}/_admin/offline`, { offline: false });
  const f4 = await gwLogin({ username: name('late'), password: pw('late') });
  check('F', 'when the legacy store is back, that user migrates on the next try', f4.status === 200 && f4.migrated === true, { status: f4.status, outcome: f4.outcome });

  // ================================================================================================================
  console.log('\nG. Safety rules of the pattern');
  const g0 = (await legacyStats()).verifyCalls;
  const gu = await gwLogin({ username: `${c.P}nobody`, password: 'Whatever-123!' });
  const gw2 = await gwLogin({ username: name('paul'), password: ['Wr', c.randomSecret(6), '1!'].join('-') });
  check('G', 'unknown user and wrong password for a migrated user give the SAME answer (401 refused): no account enumeration', gu.status === 401 && gw2.status === 401 && gu.outcome === gw2.outcome, { unknown: gu.outcome, wrong: gw2.outcome });
  check('G', 'a wrong password for a user already in Verify never reaches the legacy store (Verify is authoritative once migrated)', (await legacyStats()).verifyCalls === g0 + 1, { verifyCallsDelta: (await legacyStats()).verifyCalls - g0, note: 'only the unknown user asked the legacy store' });
  const before2 = await legacyStats();
  const okMig = await gwLogin({ username: name('jean'), password: pw('jean') });
  check('G', 'a correct password for a migrated user is served by Verify alone (no legacy call)', okMig.source === 'verify' && (await legacyStats()).verifyCalls === before2.verifyCalls);
  const dupGuard = await gwLogin({ username: `${c.P}marie-alias`, password: pw('marie') });
  check('G', 'a legacy password that does not belong to the typed login is refused (the legacy store answers per login)', dupGuard.status === 401, { status: dupGuard.status });
  const tl = await gwLogin({ username: name('baddata'), password: pw('baddata') });
  check('G', 'a legacy record with invalid data (bad e-mail) fails cleanly at JIT: no half-created user, clear error to the caller', tl.status === 502 && tl.outcome === 'verify_error' && !(await migrated('baddata')), { status: tl.status, outcome: tl.outcome });
  const noPw = await gwLogin({ username: name('jean') });
  check('G', 'a request without a password is a 400, not a crash', noPw.status === 400);
  const evs = JSON.stringify(gw.events);
  check('G', 'the gateway event log holds no password and no token', !Object.values(st.users).some((u) => evs.includes(u.password)) && !/eyJ[A-Za-z0-9_-]{20,}\./.test(evs), { events: gw.events.length });

  // ================================================================================================================
  console.log('\nH. A legacy password that is correct but weaker than the new policy');
  const wk = c.seed('weak');
  const h1 = await gwLogin({ username: name('weak'), password: pw('weak') });
  check('H', `${wk.key}'s legacy password (${c.WEAK_PASSWORD.length} characters) is verified but the new platform needs 8+: the gateway asks for a new one (422) and creates NOTHING yet`, h1.status === 422 && h1.outcome === 'new_password_required' && !(await migrated('weak')), { status: h1.status, outcome: h1.outcome, policy: h1.policyMessage });
  const strong = c.newPassword();
  const h2 = await gwLogin({ username: name('weak'), password: pw('weak'), newPassword: strong });
  const h3 = await ropc.passwordGrant(name('weak'), strong);
  check('H', 'with a new password the user is migrated and signs in; the weak legacy password does not work on the new platform', h2.status === 200 && h2.migrated === true && h2.passwordChanged === true && h3.status === 200 && (await ropc.passwordGrant(name('weak'), pw('weak'))).status === 400, { status: h2.status, changed: h2.passwordChanged });
  const h4 = await gwLogin({ username: name('weak'), password: c.WEAK_PASSWORD, newPassword: 'x1' });
  check('H', 'a new password that is itself too weak is refused (already migrated: Verify decides)', h4.status === 401 || h4.status === 422, { status: h4.status, outcome: h4.outcome });

  // ================================================================================================================
  console.log('\nI. Rollback and re-migration');
  const rb = await rollback({ legacyUrl: c.LEGACY_URL, client: mig, logins: c.SEED.map(c.userNameOf) });
  check('I', `rollback removes every migrated user from Verify (${rb.deleted.length} deleted) and clears the markers; nothing in the legacy store changed`, rb.failed.length === 0 && rb.deleted.length >= 10 && (await Promise.all(c.SEED.map((s) => c.verifyUser(c.userNameOf(s))))).every((u) => !u) && (await axios.get(`${c.LEGACY_URL}/export`)).data.every((r) => !r.migratedAt), { deleted: rb.deleted.length, absent: rb.absent.length });
  const rb1 = await gwLogin({ username: name('jean'), password: pw('jean') });
  check('I', 'after the rollback the customer still signs in with the legacy password, and is just migrated again on that login: a rollback loses no customer', rb1.status === 200 && rb1.migrated === true, { status: rb1.status, outcome: rb1.outcome });
  const rb2 = await migrateBulk({ legacyUrl: c.LEGACY_URL, client: mig, resetLogins: [], log: () => {} });
  check('I', 'a bulk run after the rollback migrates the importable records again (re-runnable cut-over)', rb2.batches.every((b) => b.accepted && b.state === 'COMPLETED') && (await loginStatus('marie')).status === 200, { processed: rb2.batches.reduce((n, b) => n + (b.processed || 0), 0) });

  // ================================================================================================================
  console.log('\nJ. Least privilege: the migration tooling is a 2-entitlement API client');
  const probes = {
    readUsers: (await mig.api('GET', '/v2.0/Users', { query: { count: 1 }, quiet: true })).status,
    listApiClients: (await mig.api('GET', '/v1.0/apiclients', { quiet: true })).status,
    listApplications: (await mig.api('GET', '/v1.0/applications', { quiet: true })).status,
    createPolicy: (await mig.api('POST', '/v5.0/policyvault/accesspolicy', { body: {}, quiet: true })).status,
    listIdentitySources: (await mig.api('GET', '/v1.0/identitysources', { quiet: true })).status,
  };
  check('J', 'the migrator client can read and manage users, and is refused (403) on API clients, applications, access policies and identity sources', probes.readUsers === 200 && [probes.listApiClients, probes.listApplications, probes.createPolicy, probes.listIdentitySources].every((s) => s === 403), { probes });
  check('J', `the migrator holds ${st.migrator.entitlements.length} entitlements against the admin client's 165`, st.migrator.entitlements.length === c.MIGRATOR_ENTITLEMENTS.length);

  // ================================================================================================================
  console.log('\nK. What is NOT done natively on this tenant [LIVE]');
  const flow = await api('GET', '/v1.0/config/models', { quiet: true });
  const bridge = await api('GET', '/config/v1.0/onpremagents', { quiet: true });
  const bridgeCreate = await api('POST', '/config/v1.0/onpremagents', { body: { name: `${c.P}probe-agent`, purpose: 'EXTAUTHN' }, quiet: true });
  check('K', 'LIMIT: Flow designer is not enabled (403 CSIBZ0098E), so the "ldap_to_okta_migration"-style flow cannot be imported', flow.status === 403 && /CSIBZ0098E/.test(JSON.stringify(flow.data)), { status: flow.status });
  check('K', 'LIMIT: the Verify Bridge is not configured (404 CSIBS0035E) and creating an external-authentication agent is refused (401 CSIBS0033E): the native JIT option 1 needs IBM', bridge.status === 404 && /CSIBS0035E/.test(JSON.stringify(bridge.data)) && bridgeCreate.status === 401 && /CSIBS0033E/.test(JSON.stringify(bridgeCreate.data)), { onpremagents: bridge.status, create: bridgeCreate.status });

  // ---- clean up the stubs and leave the tenant in the "pre-cutover" state ----
  legacySrv.close(); gwSrv.close();
  await c.purgeUsers();
  const failed = results.filter((r) => !r.pass);
  failed.forEach((r) => console.log(`  FAIL  ${r.scenario}: ${r.title}`));
  console.log(`\n${results.length - failed.length}/${results.length} checks passed.`);
  console.log('evidence:', ev.save({ passed: results.length - failed.length, total: results.length, hashMatrix: ev.doc.steps.find((s) => s.matrix) ? ev.doc.steps.find((s) => s.matrix).matrix : undefined }));
  void createClient; void crypto; void idem; void sleep;
  process.exit(failed.length ? 1 : 0);
})().catch((e) => { console.error(e.stack || e.message || e); process.exit(2); });

'use strict';
// Re-runs the live probes from DEMO-BUILD-GUIDE.md section 0.1 and prints a pass/fail table.
//   node demo/00-probe.js
// "expected blocked" rows PASS when the tenant still refuses (known IBM enablement gaps). If one of them
// starts returning 2xx, IBM enabled the feature: update the guide.
// Every probe object is created with the ifc-demo-probe- name and deleted in the same check.
const { api, PREFIX, evidence } = require('./lib/verify');

const rows = [];
const check = async (id, title, fn, { expectBlocked = false } = {}) => {
  let ok = false, detail = '';
  try { const r = await fn(); ok = r.ok; detail = r.detail; } catch (e) { detail = `error: ${e.message}`; }
  const pass = expectBlocked ? !ok : ok;
  rows.push({ id, title, expectBlocked, pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${String(id).padEnd(3)} ${title.padEnd(62)} ${detail}`);
};
const st = (r) => `HTTP ${r.status}` + (r.data && r.data.messageId ? ` ${r.data.messageId}` : '');
const scimUser = (name, email) => ({
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'], userName: name,
  name: { givenName: 'Probe', familyName: 'User', formatted: 'Probe User' }, emails: [{ type: 'work', value: email }], active: true,
});

(async () => {
  console.log(`Tenant probe (${new Date().toISOString()})\n`);
  await check(1, 'API client_credentials token + SCIM read', async () => {
    const r = await api('GET', '/v2.0/Users', { query: { count: 1, attributes: 'id' }, quiet: true });
    return { ok: r.status === 200, detail: st(r) };
  });
  await check(2, 'Flow designer (expected blocked, CI-49771)', async () => {
    const r = await api('GET', '/v1.0/config/models', { quiet: true });
    return { ok: r.status === 200, detail: st(r) };
  }, { expectBlocked: true });
  await check(3, 'Branding themes list (create is blocked on trial)', async () => {
    const r = await api('GET', '/v1.0/branding/themes', { quiet: true });
    return { ok: r.status === 200, detail: st(r) };
  });
  await check(4, 'Dynamic client registration create + delete', async () => {
    const c = await api('POST', '/oauth2/register', { body: { client_name: `${PREFIX}probe-dcr`, redirect_uris: ['https://localhost/cb'], grant_types: ['authorization_code'] }, quiet: true });
    if (c.status !== 201) return { ok: false, detail: st(c) };
    const a = await api('GET', '/v1.0/applications');
    const app = (((a.data || {})._embedded || {}).applications || []).find((x) => x.name === `${PREFIX}probe-dcr`);
    const d = app ? await api('DELETE', app._links.self.href, { quiet: true }) : { status: 'no-app' };
    return { ok: d.status === 200 || d.status === 204, detail: `create ${c.status}, delete ${d.status}` };
  });
  await check(8, 'SCIM user create (+ usershouldnotneedtoresetpassword) and delete', async () => {
    const c = await api('POST', '/v2.0/Users', { body: scimUser(`${PREFIX}probe-user`, 'probe-user@example.com'), headers: { usershouldnotneedtoresetpassword: 'true' }, quiet: true });
    if (c.status !== 201) return { ok: false, detail: st(c) };
    const d = await api('DELETE', `/v2.0/Users/${c.data.id}`, { quiet: true });
    return { ok: d.status === 204, detail: `create ${c.status}, delete ${d.status}` };
  });
  await check(10, 'SCIM filter userName sw "ifc-demo-"', async () => {
    const r = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${PREFIX}"`, attributes: 'id' }, quiet: true });
    return { ok: r.status === 200, detail: `${st(r)}, ${r.data && r.data.totalResults} match(es)` };
  });
  await check(12, 'Access policy v5.0 list', async () => {
    const r = await api('GET', '/v5.0/policyvault/accesspolicy', { quiet: true });
    return { ok: r.status === 200, detail: `${st(r)}, total ${r.data && r.data.total}` };
  });
  await check(15, 'STS client create + delete', async () => {
    const c = await api('POST', '/v1.0/sts/oauth/clients', {
      body: { clientName: `${PREFIX}probe-sts`, enabled: true, clientAuthentication: { clientAuthMethod: 'client_secret_basic', clientSecret: 'Pr0be-Secret-xyz-123' }, tokenSettings: { signingAlg: 'RS256' },
        tokenExchangeSettings: { subjectTokenTypes: ['urn:ietf:params:oauth:token-type:access_token'], requestedTokenTypes: ['urn:ietf:params:oauth:token-type:access_token'] } }, quiet: true,
    });
    if (c.status !== 201) return { ok: false, detail: st(c) };
    const l = await api('GET', '/v1.0/sts/oauth/clients');
    const mine = ((l.data || {}).clients || []).find((x) => x.clientName === `${PREFIX}probe-sts`);
    const d = mine ? await api('DELETE', `/v1.0/sts/oauth/clients/${mine.clientId}`, { quiet: true }) : { status: 'not-listed' };
    return { ok: d.status === 204, detail: `create ${c.status}, delete ${d.status}` };
  });
  await check(17, 'Authenticator registrations and discovery readable', async () => {
    const a = await api('GET', '/v1.0/authenticators', { quiet: true });
    const d = await api('GET', '/v1.0/authenticators/discovery', { quiet: true });
    return { ok: a.status === 200 && d.status === 200, detail: `${a.data && a.data.total} registration(s) tenant-wide, ${d.data && d.data.total} client(s)` };
  });
  await check(21, 'Email OTP transient create + cancel (to the tenant admin mailbox)', async () => {
    const me = await api('GET', '/v2.0/Users', { query: { count: 50, attributes: 'userName,emails' }, quiet: true });
    const admin = ((me.data || {}).Resources || []).find((u) => !u.userName.startsWith(PREFIX));
    if (!admin) return { ok: false, detail: 'no non-demo user found' };
    const c = await api('POST', '/v2.0/factors/emailotp/transient/verifications', { body: { emailAddress: admin.emails[0].value }, quiet: true });
    if (c.status === 201) await api('DELETE', `/v2.0/factors/emailotp/transient/verifications/${c.data.id}`, { quiet: true });
    return { ok: c.status === 201, detail: st(c) };
  });
  await check(22, 'TOTP enroll + verify endpoint reachable (user created and removed)', async () => {
    const u = await api('POST', '/v2.0/Users', { body: scimUser(`${PREFIX}probe-totp`, 'probe-totp@example.com'), quiet: true });
    if (u.status !== 201) return { ok: false, detail: st(u) };
    const e = await api('POST', '/v2.0/factors/totp', { body: { userId: u.data.id, accountName: `${PREFIX}probe-totp`, enabled: true }, quiet: true });
    const v = e.status === 201 ? await api('POST', `/v2.0/factors/totp/${e.data.id}`, { body: { otp: '000000' }, quiet: true }) : { status: 'n/a' };
    await api('DELETE', `/v2.0/Users/${u.data.id}`, { quiet: true });
    return { ok: e.status === 201 && v.status === 400, detail: `enroll ${e.status}, wrong code ${v.status} (400 expected)` };
  });
  await check(23, 'SMS OTP (expected blocked: not supported for this account)', async () => {
    const r = await api('POST', '/v2.0/factors/smsotp/transient/verifications', { body: { correlation: '1', phoneNumber: '+15145550100' }, quiet: true });
    return { ok: r.status === 201, detail: st(r) };
  }, { expectBlocked: true });

  const fails = rows.filter((r) => !r.pass);
  console.log(`\n${rows.length - fails.length}/${rows.length} as expected.`);
  const ev = evidence('probe');
  rows.forEach((r) => ev.step(`${r.id} ${r.title}`, { pass: r.pass, expectBlocked: r.expectBlocked, detail: r.detail }));
  console.log('evidence:', ev.save({ passed: rows.length - fails.length, total: rows.length }));
  process.exit(fails.length ? 1 : 0);
})();

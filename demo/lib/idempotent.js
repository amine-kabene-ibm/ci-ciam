'use strict';
// "ensure*" helpers: safe to run repeatedly. Only the helpers that a built use case needs live here;
// add ensureApp / ensurePolicy here when a use case needs them (do not duplicate them in ucNN folders).
const { api, PREFIX } = require('./verify');

const q = (s) => String(s).replace(/"/g, '\\"');

// Find a user by userName. Returns the SCIM resource or null.
async function findUser(userName) {
  const r = await api('GET', '/v2.0/Users', {
    query: { filter: `userName eq "${q(userName)}"`, attributes: 'id,userName,emails,active,name' },
  });
  if (r.status !== 200) throw new Error(`findUser ${userName}: HTTP ${r.status} cid=${r.cid}`);
  return (r.data.Resources || [])[0] || null;
}

// Create the user if missing. Sends usershouldnotneedtoresetpassword (otherwise logins fail with CSIAQ0267E).
async function ensureUser({ userName, email, given, family, password }) {
  if (!userName.startsWith(PREFIX)) throw new Error(`user name must start with ${PREFIX}`);
  const existing = await findUser(userName);
  if (existing) return { user: existing, created: false };
  const body = {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    userName,
    name: { givenName: given, familyName: family, formatted: `${given} ${family}` },
    displayName: `${given} ${family}`,
    emails: [{ type: 'work', value: email }],
    active: true,
  };
  if (password) body.password = password;
  const r = await api('POST', '/v2.0/Users', { body, headers: { usershouldnotneedtoresetpassword: 'true' } });
  if (r.status !== 201) throw new Error(`ensureUser ${userName}: HTTP ${r.status} cid=${r.cid}`);
  return { user: r.data, created: true };
}

// Also removes the user's IBM Verify app registrations (otherwise they may be orphaned). TOTP enrolments go with the user.
async function deleteUser(id) {
  const a = await api('GET', '/v1.0/authenticators', { query: { search: `owner="${id}"` }, quiet: true });
  for (const reg of (a.status === 200 && a.data.authenticators) || []) {
    await api('DELETE', `/v1.0/authenticators/${reg.id}`, { quiet: true });
  }
  return api('DELETE', `/v2.0/Users/${id}`, { quiet: true });
}

// Delete every user whose userName starts with the prefix. Returns the list of deleted userNames.
async function deleteUsersByPrefix(prefix) {
  const r = await api('GET', '/v2.0/Users', { query: { filter: `userName sw "${q(prefix)}"`, attributes: 'id,userName', count: 200 } });
  if (r.status !== 200) throw new Error(`list users sw ${prefix}: HTTP ${r.status} cid=${r.cid}`);
  const out = [];
  for (const u of r.data.Resources || []) {
    const d = await deleteUser(u.id);
    out.push({ userName: u.userName, status: d.status });
  }
  return out;
}

async function ensureGroup(displayName) {
  if (!displayName.startsWith(PREFIX)) throw new Error(`group name must start with ${PREFIX}`);
  const r = await api('GET', '/v2.0/Groups', { query: { filter: `displayName eq "${q(displayName)}"` } });
  if (r.status === 200 && (r.data.Resources || []).length) return { group: r.data.Resources[0], created: false };
  const c = await api('POST', '/v2.0/Groups', {
    body: { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'], displayName },
  });
  if (c.status !== 201) throw new Error(`ensureGroup ${displayName}: HTTP ${c.status} cid=${c.cid}`);
  return { group: c.data, created: true };
}

async function deleteGroupsByPrefix(prefix) {
  const r = await api('GET', '/v2.0/Groups', { query: { filter: `displayName sw "${q(prefix)}"` } });
  if (r.status !== 200) return [];
  const out = [];
  for (const g of r.data.Resources || []) {
    const d = await api('DELETE', `/v2.0/Groups/${g.id}`, { quiet: true });
    out.push({ displayName: g.displayName, status: d.status });
  }
  return out;
}

// API clients (/v1.0/apiclients). Create returns 201 with an EMPTY body, so we list to find it, then GET it
// (the GET response carries clientId + clientSecret). If the entitlements drifted, recreate it.
async function findApiClient(clientName) {
  const r = await api('GET', '/v1.0/apiclients');
  if (r.status !== 200) throw new Error(`list apiclients: HTTP ${r.status} cid=${r.cid}`);
  return (r.data.apiClients || []).find((c) => c.clientName === clientName) || null;
}

async function ensureApiClient(clientName, entitlements) {
  if (!clientName.startsWith(PREFIX)) throw new Error(`api client name must start with ${PREFIX}`);
  let existing = await findApiClient(clientName);
  let created = false;
  const same = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  if (existing && !same(existing.entitlements || [], entitlements)) {
    await api('DELETE', `/v1.0/apiclients/${existing.id}`);
    existing = null;
  }
  if (!existing) {
    const c = await api('POST', '/v1.0/apiclients', { body: { clientName, entitlements, enabled: true } });
    if (c.status !== 201) throw new Error(`create apiclient ${clientName}: HTTP ${c.status} cid=${c.cid}`);
    existing = await findApiClient(clientName);
    created = true;
  }
  const g = await api('GET', `/v1.0/apiclients/${existing.id}`);
  if (g.status !== 200) throw new Error(`get apiclient ${clientName}: HTTP ${g.status} cid=${g.cid}`);
  return { id: existing.id, clientId: g.data.clientId, clientSecret: g.data.clientSecret, entitlements: g.data.entitlements, created };
}

async function deleteApiClientsByPrefix(prefix) {
  const r = await api('GET', '/v1.0/apiclients');
  const out = [];
  for (const c of (r.data && r.data.apiClients) || []) {
    if (!c.clientName.startsWith(prefix)) continue;
    const d = await api('DELETE', `/v1.0/apiclients/${c.id}`, { quiet: true });
    out.push({ clientName: c.clientName, status: d.status });
  }
  return out;
}

// TOTP enrolment: one per user. Keep it if the caller still holds its secret (prev = {id, secret}), otherwise recreate.
async function ensureTotp(userId, accountName, prev) {
  const l = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${userId}"` } });
  const existing = (l.data && l.data.totp) || [];
  if (prev && prev.id && prev.secret && existing.some((t) => t.id === prev.id)) return { id: prev.id, secret: prev.secret, created: false };
  for (const t of existing) await api('DELETE', `/v2.0/factors/totp/${t.id}`);
  const e = await api('POST', '/v2.0/factors/totp', { body: { userId, accountName, enabled: true } });
  if (e.status !== 201) throw new Error(`TOTP enrol failed: HTTP ${e.status} cid=${e.cid}`);
  return { id: e.data.id, secret: e.data.attributes.secret, created: true };
}

// STS (token exchange) clients. Create returns 201 with an EMPTY body and the list uses clientId, not id [LIVE].
// We choose the secret, so a client whose secret or lifetime drifted is recreated.
async function findStsClient(clientName) {
  const r = await api('GET', '/v1.0/sts/oauth/clients');
  if (r.status !== 200) throw new Error(`list sts clients: HTTP ${r.status} cid=${r.cid}`);
  return (r.data.clients || []).find((c) => c.clientName === clientName) || null;
}

async function ensureStsClient(clientName, { secret, accessTokenLifetime }) {
  if (!clientName.startsWith(PREFIX)) throw new Error(`sts client name must start with ${PREFIX}`);
  const tokenType = 'urn:ietf:params:oauth:token-type:access_token';
  let existing = await findStsClient(clientName);
  let created = false;
  if (existing) {
    const g = await api('GET', `/v1.0/sts/oauth/clients/${existing.clientId}`);
    const ok = g.status === 200 && g.data.enabled && g.data.clientAuthentication.clientSecret === secret
      && g.data.tokenSettings.accessTokenLifetime === accessTokenLifetime;
    if (!ok) { await api('DELETE', `/v1.0/sts/oauth/clients/${existing.clientId}`); existing = null; }
  }
  if (!existing) {
    const c = await api('POST', '/v1.0/sts/oauth/clients', {
      body: {
        clientName, enabled: true,
        clientAuthentication: { clientAuthMethod: 'client_secret_basic', clientSecret: secret },
        tokenSettings: { signingAlg: 'RS256', accessTokenLifetime },
        tokenExchangeSettings: { subjectTokenTypes: [tokenType], requestedTokenTypes: [tokenType] },
      },
    });
    if (c.status !== 201) throw new Error(`create sts client ${clientName}: HTTP ${c.status} cid=${c.cid}`);
    existing = await findStsClient(clientName);
    created = true;
  }
  return { clientId: existing.clientId, created };
}

async function deleteStsClientsByPrefix(prefix) {
  const r = await api('GET', '/v1.0/sts/oauth/clients');
  const out = [];
  for (const c of (r.data && r.data.clients) || []) {
    if (!c.clientName.startsWith(prefix)) continue;
    out.push({ clientName: c.clientName, status: (await api('DELETE', `/v1.0/sts/oauth/clients/${c.clientId}`, { quiet: true })).status });
  }
  return out;
}

// Dynamic-client-registration apps (/oauth2/register). The secret is only returned at creation, so the caller keeps
// {clientId, clientSecret, registrationUri, registrationToken} (prev) in its state file. If prev still resolves, reuse it.
async function listApplications() {
  const a = await api('GET', '/v1.0/applications');
  return ((a.data && a.data._embedded) || {}).applications || [];
}

async function deleteApplicationsByPrefix(prefix) {
  const out = [];
  for (const x of await listApplications()) {
    if (!x.name.startsWith(prefix)) continue;
    out.push({ name: x.name, status: (await api('DELETE', x._links.self.href, { quiet: true })).status });
  }
  return out;
}

async function ensureDcrClient(name, body, prev) {
  if (!name.startsWith(PREFIX)) throw new Error(`application name must start with ${PREFIX}`);
  if (prev && prev.registrationUri) {
    const g = await api('GET', new URL(prev.registrationUri).pathname, { noAuth: true, headers: { Authorization: `Bearer ${prev.registrationToken}` }, quiet: true });
    if (g.status === 200) return { ...prev, created: false };
  }
  await deleteApplicationsByPrefix(name); // same-named leftovers whose secret we no longer hold
  const r = await api('POST', '/oauth2/register', { body: { client_name: name, ...body } });
  if (r.status !== 201) throw new Error(`register ${name}: HTTP ${r.status} cid=${r.cid}`);
  return {
    clientId: r.data.client_id, clientSecret: r.data.client_secret,
    registrationUri: r.data.registration_client_uri, registrationToken: r.data.registration_access_token, created: true,
  };
}

module.exports = {
  findUser, ensureUser, deleteUser, deleteUsersByPrefix, ensureGroup, deleteGroupsByPrefix,
  findApiClient, ensureApiClient, deleteApiClientsByPrefix,
  ensureTotp, findStsClient, ensureStsClient, deleteStsClientsByPrefix, listApplications, deleteApplicationsByPrefix, ensureDcrClient,
};

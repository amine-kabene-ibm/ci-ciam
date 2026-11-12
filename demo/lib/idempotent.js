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

async function ensureStsClient(clientName, { secret, accessTokenLifetime, actorRequired = false }) {
  if (!clientName.startsWith(PREFIX)) throw new Error(`sts client name must start with ${PREFIX}`);
  const tokenType = 'urn:ietf:params:oauth:token-type:access_token';
  let existing = await findStsClient(clientName);
  let created = false;
  if (existing) {
    const g = await api('GET', `/v1.0/sts/oauth/clients/${existing.clientId}`);
    const ok = g.status === 200 && g.data.enabled && g.data.clientAuthentication.clientSecret === secret
      && g.data.tokenSettings.accessTokenLifetime === accessTokenLifetime
      && !!(g.data.tokenExchangeSettings || {}).actorTokenRequired === actorRequired;
    if (!ok) { await api('DELETE', `/v1.0/sts/oauth/clients/${existing.clientId}`); existing = null; }
  }
  if (!existing) {
    // actorRequired (UC-09 on-behalf-of): the exchange must carry an actor_token. [LIVE] CSIAQ5242E without one.
    const c = await api('POST', '/v1.0/sts/oauth/clients', {
      body: {
        clientName, enabled: true,
        clientAuthentication: { clientAuthMethod: 'client_secret_basic', clientSecret: secret },
        tokenSettings: { signingAlg: 'RS256', accessTokenLifetime },
        tokenExchangeSettings: {
          subjectTokenTypes: [tokenType], requestedTokenTypes: [tokenType],
          ...(actorRequired ? { actorTokenTypes: [tokenType], actorTokenRequired: true } : {}),
        },
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

// Change a registered application's OIDC settings in place (GET, mutate, PUT). `mutate(app)` edits the full application document
// (e.g. app.providers.oidc.properties.accessTokenExpiry, .additionalConfig.logoutOption). Returns the PUT status. [LIVE] PUT returns 200, empty body.
async function updateApplication(name, mutate) {
  const x = (await listApplications()).find((a) => a.name === name);
  if (!x) throw new Error(`updateApplication: ${name} not found`);
  const g = await api('GET', x._links.self.href);
  if (g.status !== 200) throw new Error(`get application ${name}: HTTP ${g.status} cid=${g.cid}`);
  mutate(g.data);
  const p = await api('PUT', x._links.self.href, { body: g.data });
  if (p.status !== 200) throw new Error(`update application ${name}: HTTP ${p.status} cid=${p.cid}`);
  return p.status;
}

// Group membership by SCIM PATCH (204). Safe to repeat: checks the current members first.
async function ensureGroupMember(groupId, userId) {
  const g = await api('GET', `/v2.0/Groups/${groupId}`);
  if (g.status === 200 && (g.data.members || []).some((m) => m.value === userId)) return { added: false };
  const r = await api('PATCH', `/v2.0/Groups/${groupId}`, {
    body: { schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'], Operations: [{ op: 'add', path: 'members', value: [{ value: userId, type: 'user' }] }] },
  });
  if (r.status !== 204) throw new Error(`add ${userId} to group ${groupId}: HTTP ${r.status} cid=${r.cid}`);
  return { added: true };
}

// Access policies, v5.0 [LIVE]. rules = [{name, conditions, action, authnMethods}] where action is one of ACTION_ALLOW, ACTION_MFA_ALWAYS,
// ACTION_MFA_PER_SESSION, ACTION_DENY (ACTION_MFA_PERSIST does not exist: CSIBI0006E). authnMethods values: 'totp', 'emailotp', 'fido2', 'smsotp',
// 'anyFactor', ... or 'urn:ibm:security:authentication:asf:macotp' (the bare asf:totp URN is rejected, CSIBI0071E).
// Group conditions compare against the token's `groupIds`, which holds group NAMES (not SCIM ids): use the displayName.
// Creates the policy, or replaces its rules when they drifted. Returns {id, created, updated}.
async function ensurePolicy(name, description, rules) {
  if (!name.startsWith(PREFIX)) throw new Error(`policy name must start with ${PREFIX}`);
  const wanted = rules.map((r) => ({
    alwaysRun: false, firstFactor: false, name: r.name, conditions: r.conditions || [],
    result: { action: r.action, authnMethods: r.authnMethods || ['totp'], serverSideActions: [] },
  }));
  const body = { containsFirstFactor: false, description, name, meta: { state: 'ACTIVE', schema: 'urn:access:policy:5.0:schema', enforcementType: 'fedSSO' }, rules: wanted };
  const l = await api('GET', '/v5.0/policyvault/accesspolicy', { query: { search: `name="${q(name)}"` } });
  if (l.status !== 200) throw new Error(`find policy ${name}: HTTP ${l.status} cid=${l.cid}`);
  const found = (l.data.policies || []).find((p) => p.name === name);
  if (!found) {
    const c = await api('POST', '/v5.0/policyvault/accesspolicy', { body });
    if (c.status !== 201) throw new Error(`create policy ${name}: HTTP ${c.status} cid=${c.cid}`);
    return { id: String(c.data.id), created: true, updated: false };
  }
  const g = await api('GET', `/v5.0/policyvault/accesspolicy/${found.id}`);
  const shape = (rs) => JSON.stringify(rs.map((r) => [r.name, r.conditions, r.result.action, r.result.authnMethods]));
  if (g.status === 200 && shape(g.data.rules || []) === shape(wanted)) return { id: String(found.id), created: false, updated: false };
  const u = await api('PUT', `/v5.0/policyvault/accesspolicy/${found.id}`, { body: { ...g.data, description, rules: wanted } });
  if (u.status !== 200 && u.status !== 201) throw new Error(`update policy ${name}: HTTP ${u.status} cid=${u.cid}`);
  return { id: String(found.id), created: false, updated: true };
}

async function deletePoliciesByPrefix(prefix) {
  const r = await api('GET', '/v5.0/policyvault/accesspolicy', { query: { search: `name contains "${q(prefix)}"` } });
  const out = [];
  for (const p of ((r.data && r.data.policies) || []).filter((x) => x.name.startsWith(prefix))) {
    out.push({ name: p.name, status: (await api('DELETE', `/v5.0/policyvault/accesspolicy/${p.id}`, { quiet: true })).status });
  }
  return out;
}

// Who may sign in to an application registered with all_users_entitled:false (UC-10 "one account per brand") [LIVE]:
// users or groups get an entitlement; everyone else is refused with CSIAQ0279E. Body shape: {additions:[{assignee:{subjectId,subjectType},grantType:'DISC'}]}.
// Only direct USER entitlements gated a login in testing: a group entitlement was accepted (200) but did not let its members in.
const appIdOf = async (name) => {
  const x = (await listApplications()).find((a) => a.name === name);
  if (!x) throw new Error(`application ${name} not found`);
  return x._links.self.href.split('/').pop();
};

async function listAppEntitlements(appId) {
  const r = await api('GET', `/v1.0/owner/applications/${appId}/entitlements`);
  if (r.status !== 200) throw new Error(`list entitlements of ${appId}: HTTP ${r.status} cid=${r.cid}`);
  return r.data.entitlements || [];
}

async function ensureAppEntitlement(appId, userId) {
  if ((await listAppEntitlements(appId)).some((e) => e.assignee.subjectId === userId)) return { added: false };
  const r = await api('POST', `/v1.0/owner/applications/${appId}/entitlements`, {
    body: { additions: [{ assignee: { subjectId: userId, subjectType: 'user' }, grantType: 'DISC' }] },
  });
  if (r.status !== 200) throw new Error(`entitle ${userId} to ${appId}: HTTP ${r.status} cid=${r.cid}`);
  return { added: true };
}

async function removeAppEntitlement(appId, userId) {
  const e = (await listAppEntitlements(appId)).find((x) => x.assignee.subjectId === userId);
  if (!e) return { removed: false };
  const r = await api('POST', `/v1.0/owner/applications/${appId}/entitlements`, { body: { deletions: [e.id] } });
  if (r.status !== 200) throw new Error(`remove entitlement of ${userId} on ${appId}: HTTP ${r.status} cid=${r.cid}`);
  return { removed: true };
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

// CIBA application (UC-14) [LIVE 2026-11-12]: POST /v1.0/applications (templateId "1", applicationState true) with grantTypes.ciba "true" and
// additionalConfig.backchannelSettings. Channels accepted: "push", "email" only (400 CSIAQ0509 otherwise). The secret stays readable by GET, so no
// state file is needed. The app admits entitled users only (CSIAQ0279E): entitle customers with ensureAppEntitlement. A drifted app is recreated.
async function ensureCibaApp(name, { channels = ['email'], sendAllKnownUserAttributes = true } = {}) {
  if (!name.startsWith(PREFIX)) throw new Error(`application name must start with ${PREFIX}`);
  const read = async () => {
    const x = (await listApplications()).find((a) => a.name === name);
    if (!x) return null;
    const g = await api('GET', x._links.self.href);
    if (g.status !== 200) throw new Error(`get application ${name}: HTTP ${g.status} cid=${g.cid}`);
    return { appId: x._links.self.href.split('/').pop(), doc: g.data };
  };
  let cur = await read();
  let created = false;
  const bs = cur && cur.doc.providers.oidc.properties.additionalConfig.backchannelSettings;
  const same = cur && cur.doc.applicationState === true && cur.doc.providers.oidc.properties.grantTypes.ciba === 'true' && bs
    && JSON.stringify(bs.userAuthChannels) === JSON.stringify(channels)
    && String(cur.doc.providers.oidc.properties.sendAllKnownUserAttributes) === String(sendAllKnownUserAttributes);
  if (cur && !same) { await api('DELETE', `/v1.0/applications/${cur.appId}`); cur = null; }
  if (!cur) {
    const c = await api('POST', '/v1.0/applications', { body: {
      name, templateId: '1', applicationState: true,
      providers: { oidc: { properties: {
        sendAllKnownUserAttributes: String(sendAllKnownUserAttributes),
        grantTypes: { ciba: 'true' },
        additionalConfig: { backchannelSettings: { deliveryMode: 'poll', supportUserCode: false, proximityCheck: 'disabled', userAuthChannels: channels } },
      } } },
    } });
    if (c.status !== 201) throw new Error(`create CIBA application ${name}: HTTP ${c.status} cid=${c.cid}`);
    cur = await read();
    created = true;
  }
  const p = cur.doc.providers.oidc.properties;
  return { appId: cur.appId, clientId: p.clientId, clientSecret: p.clientSecret, channels, created };
}

// Webhook management (/config/v1.0/webhooks/)
async function listWebhooks() {
  const r = await api('GET', '/config/v1.0/webhooks/', { quiet: true });
  return ((r.data && r.data.webhooks) || []);
}

async function findWebhook(name) {
  const list = await listWebhooks();
  return list.find((w) => w.name === name) || null;
}

async function ensureWebhook(name, { type = 'notification', purpose = ['notifications'], urls = ['https://example.com/webhook'], notification } = {}) {
  if (!name.startsWith(PREFIX)) throw new Error(`webhook name must start with ${PREFIX}`);
  let existing = await findWebhook(name);
  if (existing) {
    return { id: existing.id, webhook: existing, created: false };
  }
  const body = {
    name,
    type,
    purpose,
    urls,
    ...(type === 'notification' ? {
      notification: notification || {
        enabled: true,
        interests: [{ name: 'user', clauses: [{ operation: 'include', key: 'action', value: '*' }] }],
      },
    } : {}),
  };
  const c = await api('POST', '/config/v1.0/webhooks/', { body, quiet: true });
  if (c.status !== 200 && c.status !== 201) throw new Error(`ensureWebhook ${name}: HTTP ${c.status} cid=${c.cid}`);
  return { id: c.data.id, webhook: c.data, created: true };
}

async function deleteWebhooksByPrefix(prefix) {
  const list = await listWebhooks();
  const out = [];
  for (const w of list) {
    if (!w.name.startsWith(prefix)) continue;
    const d = await api('DELETE', `/config/v1.0/webhooks/${w.id}`, { quiet: true });
    out.push({ name: w.name, status: d.status });
  }
  return out;
}

module.exports = {
  findUser, ensureUser, deleteUser, deleteUsersByPrefix, ensureGroup, deleteGroupsByPrefix, ensureGroupMember,
  findApiClient, ensureApiClient, deleteApiClientsByPrefix,
  ensureTotp, findStsClient, ensureStsClient, deleteStsClientsByPrefix, listApplications, deleteApplicationsByPrefix, ensureDcrClient,
  updateApplication, ensurePolicy, deletePoliciesByPrefix, appIdOf, listAppEntitlements, ensureAppEntitlement, removeAppEntitlement,
  listWebhooks, findWebhook, ensureWebhook, deleteWebhooksByPrefix, ensureCibaApp,
};

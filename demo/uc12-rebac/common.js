'use strict';
// Names, ports and helpers shared by all UC-12 scripts. Everything on the tenant starts with "ifc-demo-uc12-".
// UC-12 = Verify authenticates the broker (OIDC token, introspected by the gateway); an EXTERNAL relationship engine (OpenFGA) decides
// what that broker may see. Three tenant-side actors: the users, a password-grant app (how the demo signs a broker in), and two
// least-privilege clients (the gateway's introspection client, and the sync job that mirrors source-system changes into Verify).
const crypto = require('crypto');
const { PREFIX, BASE, stateFile, oauthClient, createClient } = require('../lib/verify');
const E = require('../../stubs/rules-engine/openfga');
const { TYPE_DEFINITIONS } = require('../../stubs/rules-engine/model');
const { createSource, syncGraph } = require('../../stubs/policy-api/source');

const UC = 'uc12';
const P = `${PREFIX}${UC}-`;
const state = stateFile(UC);

const GATEWAY_PORT = 4170; // the policy API gateway stub (also serves the console UI)
const FGA_PORT = 4171; // OpenFGA HTTP
const FGA_GRPC_PORT = 4172; // OpenFGA gRPC (not used, but must not clash)
const GATEWAY_URL = `http://127.0.0.1:${GATEWAY_PORT}`;

const LOGIN_APP = `${P}login`; // password-grant client: signs a broker in for the demo
const GATEWAY_STS = `${P}gateway`; // STS client: the gateway introspects tokens with this (not with the admin client) [LIVE UC-09]
const SYNC_CLIENT = `${P}sync`; // API client: the job that mirrors broker moves into the Verify directory
const SYNC_ENTITLEMENTS = ['readUsers', 'manageUsers'];

const userNameOf = (key) => `${P}${key}`;
const emailOf = (key) => `uc12.${key}@ifc-demo.invalid`;
const randomSecret = (n) => crypto.randomBytes(n).toString('base64url');
const newPassword = () => ['Ifc', randomSecret(9), '8b'].join('-') + '!';

const SCIM_PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const ENT = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

const syncClient = (st) => createClient(st.sync.clientId, st.sync.clientSecret);
const ropc = (st) => oauthClient(st.login.clientId, st.login.clientSecret);

// Verify user id (the `sub` of the broker's token) by short name.
const subOf = (st) => (key) => {
  if (!st.users[key]) throw new Error(`unknown broker ${key}`);
  return st.users[key].id;
};
// Reverse map for display: sub -> "Anna Leclerc (BRK-0101)"
function labelsOf(st, source) {
  const m = {};
  for (const [k, u] of Object.entries(st.users)) { const b = source.seed.brokers[k]; m[u.id] = `${b.given} ${b.family} (${b.brokerId})`; }
  return m;
}

// Put the broker's directory record in line with the source system: department = brokerage, employee number = broker id, title = role.
// Uses the least-privilege sync client. SCIM "add" replaces a single-valued attribute [LIVE].
async function syncDirectory(st, source, key) {
  const b = source.brokers[key];
  const ops = [
    { op: 'add', path: `${ENT}:department`, value: b.brokerage || '' },
    { op: 'add', path: `${ENT}:employeeNumber`, value: b.brokerId },
    { op: 'add', path: 'title', value: b.role },
  ];
  return syncClient(st).api('PATCH', `/v2.0/Users/${st.users[key].id}`, { body: { schemas: [SCIM_PATCH], Operations: ops } });
}

// Start OpenFGA, create a store, load the model, and fill the graph from the source system. Returns what the gateway needs.
async function bootEngine(st, source, ports = { port: FGA_PORT, grpcPort: FGA_GRPC_PORT }) {
  const bin = await E.ensureBinary();
  const engine = await E.startEngine(ports);
  const fga = new E.FgaClient(engine.url);
  const storeId = await fga.createStore(`ifc-demo-uc12-${Date.now()}`);
  fga.use(storeId, null);
  const modelId = await fga.writeModel(TYPE_DEFINITIONS);
  const sync = await syncGraph(fga, source.desiredTuples(subOf(st)));
  return { bin, engine, fga, storeId, modelId, sync };
}

// A change in the source system (a broker joins/leaves a brokerage, a client changes hands): apply it, mirror it into the relationship graph
// (this is what takes access away or gives it) and into the Verify directory (department, so that the NEXT token carries the new brokerage).
// Returns timings. `mutate(source)` is the change itself.
async function applyChange(st, source, fga, mutate) {
  const t0 = Date.now();
  const before = Object.fromEntries(Object.entries(source.brokers).map(([k, b]) => [k, b.brokerage]));
  mutate(source);
  const sync = await syncGraph(fga, source.desiredTuples(subOf(st)));
  const graphMs = Date.now() - t0;
  const directory = [];
  for (const [k, b] of Object.entries(source.brokers)) {
    if (before[k] !== b.brokerage) directory.push({ broker: k, status: (await syncDirectory(st, source, k)).status });
  }
  return { sync, graphMs, directory, totalMs: Date.now() - t0 };
}

module.exports = {
  UC, BASE, PREFIX, P, state, GATEWAY_PORT, FGA_PORT, FGA_GRPC_PORT, GATEWAY_URL, LOGIN_APP, GATEWAY_STS, SYNC_CLIENT, SYNC_ENTITLEMENTS,
  userNameOf, emailOf, randomSecret, newPassword, SCIM_PATCH, ENT, syncClient, ropc, subOf, labelsOf, syncDirectory,
  bootEngine, applyChange, createSource, syncGraph, E,
};

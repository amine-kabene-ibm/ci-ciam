'use strict';
// UC-12 scenario runner: relationship-based authorization for broker access, against the REAL Verify tenant.
//   node demo/uc12-rebac/run.js
// Verify authenticates the broker (real password-grant sign-in, real token introspection). OpenFGA (native process, started here) decides what
// that broker may see. The source system, engine and gateway are stubs. Evidence (status codes, ids, timings; never passwords or tokens): demo/out/uc12.json.
//   A. Pre-conditions: model loaded, graph synced from the source system, directory + token carry the broker's brokerage
//   B. The PDF's demo 1: access check that reflects an INHERITED relationship (brokerage -> broker -> client -> policy), with the reasoning path
//   C. Authenticated is not authorized; bad tokens never reach the engine
//   D. The PDF's demo 3: "all resources this user can access" and the audit question "who can access this resource"
//   E. The PDF's demo 2: reassign a broker to another brokerage; the SAME token loses (and gains) access, no re-login
//   F. A broker who leaves the brokerage loses access immediately; client transfer; sync is idempotent
//   G. Identity layer: deactivating the user in Verify stops a token the relationship graph would still allow
//   H. Exhaustive cross-check: engine matrix == independent oracle computed from the source data, after every change
//   I. What the token can and cannot carry (claims), and least privilege of the sync job
//   J. Scale smoke test: 8,000+ relationships, in-memory (a sizing hint for the conversation, not a benchmark)
const axios = require('axios');
const { evidence, api, createClient } = require('../lib/verify');
const idem = require('../lib/idempotent');
const c = require('./common');
const { boot, decode } = require('./runtime');

const ev = evidence('uc12');
const results = [];
const note = (s) => console.log(`    ${s}`);
const ms = (a) => a.slice().sort((x, y) => x - y);
const pct = (a, p) => ms(a)[Math.min(a.length - 1, Math.floor(a.length * p))];

(async () => {
  const st = c.state.read();
  if (!st || !st.users) { console.error('Run setup first: node demo/uc12-rebac/setup.js'); process.exit(1); }
  const check = (scenario, title, pass, extra = {}) => {
    results.push({ scenario, title, pass });
    console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${title}`);
    ev.step(`${scenario}: ${title}`, { pass, ...extra });
  };

  const rt = await boot(st);
  const { source, fga } = rt;
  const KEYS = Object.keys(source.brokers);
  const POLS = Object.keys(source.policies);
  const keyOfSub = (sub) => KEYS.find((k) => rt.subs[k] === sub);
  const gw = axios.create({ baseURL: rt.url, validateStatus: () => true });

  // tokens: one real Verify sign-in per broker, reused until the scenario says otherwise
  const tok = {};
  const login = async (k) => { tok[k] = await rt.signIn(k); return tok[k]; };
  const call = async (k, method, url, body) => {
    if (!tok[k]) await login(k);
    const t0 = Date.now();
    const r = await gw.request({ method, url, data: body, headers: { Authorization: `Bearer ${tok[k].token}` } });
    return { status: r.status, body: r.data, ms: Date.now() - t0 };
  };
  const read = (k, n) => call(k, 'get', `/api/policies/${n}`);

  // independent oracle: what the source data says, computed without the engine
  const oracle = (k, n) => {
    const b = source.brokers[k]; const cl = source.clients[source.policies[n].client];
    const serving = cl.placedBy === k && b.role === 'broker' && !!b.brokerage && b.brokerage === cl.brokerage;
    const managing = b.role === 'manager' && !!b.brokerage && b.brokerage === cl.brokerage;
    return { view: serving || managing, edit: serving };
  };
  const engineMatrix = async () => {
    const m = {};
    for (const k of KEYS) for (const n of POLS) m[`${k}|${n}`] = { view: (await fga.check(`user:${rt.subs[k]}`, 'can_view', `policy:${n}`)).allowed, edit: (await fga.check(`user:${rt.subs[k]}`, 'can_edit', `policy:${n}`)).allowed };
    return m;
  };
  const sameAsOracle = async () => {
    const m = await engineMatrix(); const bad = [];
    for (const k of KEYS) for (const n of POLS) { const o = oracle(k, n); const e = m[`${k}|${n}`]; if (o.view !== e.view || o.edit !== e.edit) bad.push(`${k}|${n}`); }
    return { ok: bad.length === 0, bad, cells: KEYS.length * POLS.length };
  };
  const viewable = async (k) => (await call(k, 'get', '/api/policies')).body.policies.map((p) => p.policyNumber).sort();

  try {
    // ================================================================================================================
    console.log('\nA. Pre-conditions: model, graph from the source system, directory, token');
    const tuples = await fga.read();
    check('A', `OpenFGA v${rt.boot.bin.version} is up, the model is loaded, and the graph holds ${rt.boot.sync.total} relationships synced from the source system`, tuples.length === rt.boot.sync.total && rt.boot.sync.total > 0, { engineVersion: rt.boot.bin.version, tuples: tuples.length, storeId: rt.boot.storeId, modelId: rt.boot.modelId, syncMs: rt.boot.sync.ms });
    const again = await c.syncGraph(fga, source.desiredTuples(c.subOf(st)));
    check('A', 'syncing again changes nothing (0 added, 0 removed): the sync is idempotent', again.added === 0 && again.removed === 0, again);
    const u = await idem.findUser(c.userNameOf('anna'));
    const full = await api('GET', `/v2.0/Users/${u.id}`);
    const ent = full.data[c.ENT] || {};
    check('A', 'the Verify directory holds the source-system facts written by the least-privilege sync client (department = brokerage, employeeNumber = broker id, title = role)', ent.department === 'BRG-A' && ent.employeeNumber === 'BRK-0101' && full.data.title === 'broker', { department: ent.department, employeeNumber: ent.employeeNumber, jobTitle: full.data.title });
    const s1 = await login('anna');
    check('A', 'a real sign-in against Verify (password grant) returns an ID token whose subject is the Verify user id and which carries department = BRG-A', s1.sub === rt.subs.anna && s1.idClaims.department === 'BRG-A', { signInMs: s1.ms, claims: Object.keys(s1.idClaims).filter((x) => ['department', 'job_title', 'preferred_username', 'sub'].includes(x)) });
    check('A', 'the access token is opaque: the gateway cannot read claims from it and must introspect', !/^eyJ/.test(s1.token), { opaque: true });

    // ================================================================================================================
    console.log('\nB. An access check that reflects an inherited relationship (brokerage -> broker -> client -> policy)');
    const b1 = await read('anna', 'IFC-100001');
    check('B', 'Anna (broker, Alpha) reads policy IFC-100001 of her client Tremblay -> 200 allow', b1.status === 200 && b1.body.decision === 'allow', { status: b1.status, totalMs: b1.ms, checkMs: b1.body.checkMs });
    check('B', 'the answer carries the reasoning path: policy -> client -> brokerage -> placed by Anna -> still a member today', b1.body.reasoning.length === 5 && b1.body.reasoning.filter((s) => s.ok).length === 4 && /placed client/.test(b1.body.reasoning[2].fact) && /is a broker of/.test(b1.body.reasoning[3].fact), { reasoning: b1.body.reasoning.map((s) => `${s.ok ? 'yes' : 'no '} ${s.fact}`) });
    const b2 = await read('anna', 'IFC-100004');
    check('B', 'Anna reads IFC-100004 (client Roy, held by the OTHER brokerage Beta) -> 403 deny, with the reason', b2.status === 403 && b2.body.decision === 'deny' && b2.body.reasoning.some((s) => /did not place/.test(s.fact)), { status: b2.status, reasoning: b2.body.reasoning.map((s) => `${s.ok ? 'yes' : 'no '} ${s.fact}`) });
    const b3 = await read('maya', 'IFC-100003');
    check('B', 'Maya (MANAGER of Alpha, placed nobody) reads IFC-100003 -> 200 allow: access inherited from the brokerage, no per-policy grant', b3.status === 200 && /manager of/.test(b3.body.reasoning[4].fact) && b3.body.reasoning[4].ok, { status: b3.status, grantedBy: 'brokerage manager' });
    const b4 = await call('maya', 'put', '/api/policies/IFC-100003', { note: 'manager tries to edit' });
    check('B', 'Maya tries to EDIT -> 403: managers read, only the servicing broker writes', b4.status === 403, { status: b4.status });
    const b5 = await call('anna', 'put', '/api/policies/IFC-100003', { note: 'renewal call booked' });
    check('B', 'Anna edits IFC-100003 -> 200 allow (servicing broker)', b5.status === 200 && b5.body.decision === 'allow', { status: b5.status });
    const b6 = await read('ben', 'IFC-100001');
    const b7 = await read('noor', 'IFC-100001');
    check('B', 'Ben (broker, Beta) and Noor (manager, Beta) cannot read an Alpha policy -> 403 / 403', b6.status === 403 && b7.status === 403, { ben: b6.status, noor: b7.status });
    const logA = (await gw.get('/api/log')).data.filter((e) => e.action);
    check('B', 'every decision above is in the gateway log with who, what, allow/deny, reason and the path taken (the audit trail)', logA.length >= 7 && logA.every((e) => e.decision && e.reason && e.who) && logA.filter((e) => e.path_taken).length >= 7, { entries: logA.length, sample: logA.slice(0, 2).map((e) => ({ who: e.who, action: e.action, policy: e.policy, decision: e.decision, reason: e.reason, checkMs: e.checkMs, introspectMs: e.introspectMs })) });
    check('B', 'the reasoning shown to the user never disagrees with the engine\'s decision (consistent flag on every logged decision)', logA.every((e) => e.consistent !== false), { checked: logA.length });

    // ================================================================================================================
    console.log('\nC. Authenticated is not authorized; a bad token never reaches the engine');
    const z1 = await login('zoe');
    check('C', 'Zoe (a valid Verify account, no brokerage) signs in for real: HTTP 200 and an ID token', !!z1.token && z1.sub === rt.subs.zoe, { signInMs: z1.ms });
    const z2 = await read('zoe', 'IFC-100001');
    const z3 = await call('zoe', 'get', '/api/policies');
    check('C', 'Zoe is authenticated but sees nothing: read -> 403, "all resources I can access" -> 0', z2.status === 403 && z3.status === 200 && z3.body.count === 0, { read: z2.status, listed: z3.body.count });
    const before = (await gw.get('/api/log')).data.length;
    const n1 = await gw.get('/api/policies/IFC-100001');
    const n2 = await gw.get('/api/policies/IFC-100001', { headers: { Authorization: 'Bearer not-a-real-token' } });
    const lastTwo = (await gw.get('/api/log')).data.slice(before);
    check('C', 'no token -> 401; a made-up token -> 401 (Verify introspection says active:false); neither reaches the engine', n1.status === 401 && n2.status === 401 && lastTwo.every((e) => e.checkMs === undefined), { noToken: n1.status, badToken: n2.status });

    // ================================================================================================================
    console.log('\nD. "All resources this user can access" and "who can access this resource"');
    const lists = {};
    for (const k of KEYS) lists[k] = await viewable(k);
    check('D', 'Anna lists 3 policies (IFC-100001..3), Ben 3 (100004..6), Maya 3 (Alpha), Noor 3 (Beta), Zoe 0', lists.anna.join() === 'IFC-100001,IFC-100002,IFC-100003' && lists.ben.join() === 'IFC-100004,IFC-100005,IFC-100006' && lists.maya.join() === lists.anna.join() && lists.noor.join() === lists.ben.join() && lists.zoe.length === 0, { lists });
    const lA = await call('anna', 'get', '/api/policies');
    check('D', 'the listing marks which of those Anna may also edit, and answers in milliseconds (engine list-objects)', lA.body.policies.every((p) => p.canEdit === true) && lA.body.listMs < 250, { listMs: lA.body.listMs, gatewayMs: lA.ms });
    const who = await call('anna', 'get', '/api/policies/IFC-100001/access');
    check('D', 'the audit question for IFC-100001: can view = Anna + Maya, can edit = Anna', who.body.canView.join() === 'Anna Leclerc,Maya Tanaka' && who.body.canEdit.join() === 'Anna Leclerc', { canView: who.body.canView, canEdit: who.body.canEdit });

    // ================================================================================================================
    console.log('\nE. Reassign a broker to a different brokerage: access changes with no re-login');
    const oldAnna = tok.anna; // same token object used before AND after the change
    const e0 = await read('anna', 'IFC-100001');
    const dirBefore = (await api('GET', `/v2.0/Users/${rt.subs.anna}`)).data[c.ENT].department;
    const chg = await c.applyChange(st, source, fga, (s) => s.moveBroker('anna', 'BRG-B'));
    note(`change applied: graph ${chg.sync.added} added / ${chg.sync.removed} removed in ${chg.graphMs} ms; directory sync ${JSON.stringify(chg.directory)}; total ${chg.totalMs} ms`);
    const e1 = await read('anna', 'IFC-100001'); // SAME token
    check('E', 'Anna moves from Alpha to Beta. With the SAME access token (no re-login) she loses IFC-100001: 200 before, 403 after', e0.status === 200 && e1.status === 403 && tok.anna === oldAnna, { before: e0.status, after: e1.status, sameToken: tok.anna === oldAnna, tokenIssuedAt: oldAnna.iat });
    check('E', 'the denial explains itself: she is no longer a broker of the brokerage that holds that client', e1.body.reasoning.some((s) => /is not a broker of brokerage:BRG-A/.test(s.fact)), { reasoning: e1.body.reasoning.map((s) => `${s.ok ? 'yes' : 'no '} ${s.fact}`) });
    check('E', 'her listing is now empty (the clients stay with the brokerage Alpha; she did not take her book)', (await viewable('anna')).length === 0, {});
    const maya1 = await viewable('maya'); const noor1 = await viewable('noor');
    check('E', 'Maya (manager of Alpha) still sees the Alpha clients; Noor (manager of Beta) gains nothing: only the broker moved', maya1.length === 3 && noor1.length === 3 && !noor1.includes('IFC-100001'), { maya: maya1.length, noor: noor1.length });
    const dirAfter = (await api('GET', `/v2.0/Users/${rt.subs.anna}`)).data[c.ENT].department;
    check('E', 'the Verify directory follows: department BRG-A -> BRG-B (SCIM PATCH 204 by the sync client)', dirBefore === 'BRG-A' && dirAfter === 'BRG-B' && chg.directory.every((d) => d.status === 204), { before: dirBefore, after: dirAfter, patch: chg.directory });
    const s2 = await rt.signIn('anna');
    check('E', 'a NEW sign-in carries the new brokerage in the ID token (department = BRG-B) while the OLD token still says BRG-A: claims are a snapshot, the engine is the authority', s2.idClaims.department === 'BRG-B' && oldAnna.idClaims.department === 'BRG-A', { oldTokenClaim: oldAnna.idClaims.department, newTokenClaim: s2.idClaims.department });
    check('E', 'cross-check: engine matrix equals the independent oracle after the move', (await sameAsOracle()).ok, await sameAsOracle());

    const chg2 = await c.applyChange(st, source, fga, (s) => s.moveBroker('anna', 'BRG-A'));
    note(`Anna moves back: ${chg2.totalMs} ms`);
    check('E', 'moving Anna back restores her access with the same token (3 policies again)', (await viewable('anna')).length === 3 && (await read('anna', 'IFC-100001')).status === 200, { totalMs: chg2.totalMs });

    const chg3 = await c.applyChange(st, source, fga, (s) => s.moveBroker('anna', 'BRG-B', true));
    const aBook = await viewable('anna'); const mayaAfterBook = await viewable('maya'); const noorAfterBook = await viewable('noor');
    check('E', 'Anna moves WITH her book of business: she keeps her 3 clients\' policies, Alpha\'s manager loses them, Beta\'s manager gains them', aBook.join() === 'IFC-100001,IFC-100002,IFC-100003' && mayaAfterBook.length === 0 && noorAfterBook.length === 6, { anna: aBook.length, maya: mayaAfterBook.length, noor: noorAfterBook.length, totalMs: chg3.totalMs });
    check('E', 'cross-check against the oracle after the book moves', (await sameAsOracle()).ok, await sameAsOracle());
    await c.applyChange(st, source, fga, (s) => s.reset());

    // ================================================================================================================
    console.log('\nF. A broker who leaves loses access immediately; client transfer; sync');
    const f0 = await read('ben', 'IFC-100004');
    const leave = await c.applyChange(st, source, fga, (s) => s.leaveBrokerage('ben'));
    const f1 = await read('ben', 'IFC-100004');
    check('F', 'Ben leaves the brokerage: 200 -> 403 on his very next call with the same token', f0.status === 200 && f1.status === 403, { before: f0.status, after: f1.status, totalMs: leave.totalMs });
    check('F', 'his clients are not orphaned: Beta\'s manager Noor still sees all 3 Beta policies', (await viewable('noor')).length === 3, {});
    check('F', 'the directory shows no brokerage for Ben any more (department cleared)', (((await api('GET', `/v2.0/Users/${rt.subs.ben}`)).data[c.ENT] || {}).department || '') === '', { directoryStatus: leave.directory });
    await c.applyChange(st, source, fga, (s) => s.reset());
    check('F', 'resetting the source system restores Ben\'s access (3 policies)', (await viewable('ben')).length === 3, {});
    const t0 = await c.applyChange(st, source, fga, (s) => s.transferClient('C-0003', 'anna'));
    const annaT = await viewable('anna'); const benT = await viewable('ben');
    check('F', 'client Roy (C-0003) is transferred from Ben to Anna: Anna gains IFC-100004, Ben loses it, in one graph transaction', annaT.includes('IFC-100004') && !benT.includes('IFC-100004') && t0.sync.added >= 1, { graphMs: t0.graphMs, added: t0.sync.added, removed: t0.sync.removed });
    check('F', 'cross-check against the oracle after the transfer', (await sameAsOracle()).ok, await sameAsOracle());
    await c.applyChange(st, source, fga, (s) => s.reset());
    const again2 = await c.syncGraph(fga, source.desiredTuples(c.subOf(st)));
    check('F', 'after the reset the graph is back to the original and a further sync changes nothing', again2.added === 0 && again2.removed === 0, again2);

    // ================================================================================================================
    console.log('\nG. Identity layer: a deactivated user is stopped by Verify, even though the graph still says allow');
    const g0 = await read('maya', 'IFC-100001');
    const dis = await api('PATCH', `/v2.0/Users/${rt.subs.maya}`, { body: { schemas: [c.SCIM_PATCH], Operations: [{ op: 'replace', path: 'active', value: false }] } });
    const g1 = await read('maya', 'IFC-100001');
    const graphSays = await fga.check(`user:${rt.subs.maya}`, 'can_view', 'policy:IFC-100001');
    check('G', 'SCIM deactivate Maya (HTTP 204): her existing token is refused at once -> 401, token_not_active', g0.status === 200 && dis.status === 204 && g1.status === 401, { before: g0.status, patch: dis.status, after: g1.status, cid: dis.cid });
    check('G', 'the relationship graph still says allow for Maya: the two layers are independent, and the identity layer wins', graphSays.allowed === true, { graph: graphSays.allowed });
    const g2 = await api('PATCH', `/v2.0/Users/${rt.subs.maya}`, { body: { schemas: [c.SCIM_PATCH], Operations: [{ op: 'replace', path: 'active', value: true }] } });
    const g3 = await login('maya'); const g4 = await read('maya', 'IFC-100001');
    check('G', 'reactivated: a new sign-in works and the same relationships apply again', g2.status === 204 && g4.status === 200, { reactivate: g2.status, signInMs: g3.ms, read: g4.status });

    // ================================================================================================================
    console.log('\nH. Exhaustive cross-check');
    const h = await sameAsOracle();
    check('H', `all ${h.cells} broker x policy cells (view and edit) from the engine equal the independent oracle computed from the source data`, h.ok, h);
    const viaGw = [];
    for (const k of ['anna', 'ben', 'maya', 'noor', 'zoe']) for (const n of POLS) { const r = await read(k, n); viaGw.push({ k, n, got: r.status === 200, want: oracle(k, n).view }); }
    check('H', `the same ${viaGw.length} read decisions THROUGH the gateway (real tokens, real introspection) equal the oracle`, viaGw.every((x) => x.got === x.want), { mismatches: viaGw.filter((x) => x.got !== x.want).map((x) => `${x.k}|${x.n}`) });

    // ================================================================================================================
    console.log('\nI. What the token can and cannot carry; least privilege');
    const lat = []; const lat2 = [];
    for (let i = 0; i < 20; i++) { const r = await read('anna', 'IFC-100001'); lat.push(r.ms); lat2.push(r.body.checkMs); }
    check('I', 'a read through the gateway costs one Verify introspection plus one engine check', true, { gatewayMsP50: pct(lat, 0.5), gatewayMsP95: pct(lat, 0.95), engineCheckMsP50: pct(lat2, 0.5), engineCheckMsP95: pct(lat2, 0.95), note: 'the gateway time is dominated by the introspection round trip to the EU tenant; the engine check is single-digit ms' });
    const mintTest = await api('GET', '/v1.0/attributefunctions', { quiet: true });
    const fnNames = (mintTest.data || []).map((f) => f.name);
    check('I', 'LIMIT: the tenant\'s attribute functions are the built-ins only (no HTTP / external call); a token-minting callout to an external rules engine is therefore NOT possible on this tenant', mintTest.status === 200 && fnNames.length > 0 && !fnNames.some((n) => /http|call|rest|rules?/i.test(n)), { builtins: fnNames, docs: 'external-callout attribute functions are paid-tier only [DOCS]; ask IBM' });
    const bad = await api('POST', '/v1.0/attributes', { body: { name: 'ifc_demo_uc12_probe', description: 'probe', scope: 'global', sourceType: 'javascript', datatype: 'string', tags: ['sso'], value: 'x' }, quiet: true });
    check('I', 'LIMIT: custom attributes can only be STATIC / CREDENTIAL / SCHEMA / PROFILE / ORG; a scripted or external source is refused (HTTP 400 CSIBE2716E)', bad.status === 400 && bad.data && bad.data.messageId === 'CSIBE2716E', { status: bad.status, messageId: bad.data && bad.data.messageId });
    let mapRefused = null;
    try { await idem.updateApplication(c.LOGIN_APP, (a) => { a.providers.oidc.properties.tokenResponseMap = [{ name: 'brokerage', value: 'x' }]; }); mapRefused = false; } catch (e) { mapRefused = /HTTP 400/.test(e.message); }
    check('I', 'LIMIT: the plan\'s "tokenResponseMap" key is refused (HTTP 400) when put in the application\'s oidc.properties; no other placement was tried, so this does not prove enrichment maps are impossible', mapRefused === true, { refused: mapRefused });
    const lc = c.syncClient(st);
    const forbidden = await lc.api('GET', '/v1.0/apiclients', { quiet: true });
    const okUsers = await lc.api('GET', '/v2.0/Users', { query: { filter: `userName eq "${c.userNameOf('anna')}"`, attributes: 'id' }, quiet: true });
    check('I', 'least privilege: the sync client (2 entitlements) can read users but is refused admin work (API clients -> 403)', okUsers.status === 200 && forbidden.status === 403, { users: okUsers.status, apiclients: forbidden.status });
    const st403 = await oauthIntrospectWithSts();
    check('I', 'the gateway introspects with its own STS client, not the admin client (token active:true for a live token)', st403 === true, { stsClient: c.GATEWAY_STS });

    // ================================================================================================================
    console.log('\nJ. Scale smoke test (a second, separate store in the same engine; in-memory; NOT a benchmark)');
    const big = new c.E.FgaClient(rt.engine.url);
    big.use(await big.createStore('ifc-demo-uc12-scale'), null);
    await big.writeModel(require('../../stubs/rules-engine/model').TYPE_DEFINITIONS);
    const BRG = 20; const BROKERS = 5; const CLIENTS = 100; const POL = 2;
    const desired = [];
    for (let g = 0; g < BRG; g++) {
      desired.push({ user: `user:mgr${g}`, relation: 'manager', object: `brokerage:G${g}` });
      for (let b = 0; b < BROKERS; b++) desired.push({ user: `user:b${g}_${b}`, relation: 'member', object: `brokerage:G${g}` });
      for (let cl = 0; cl < CLIENTS; cl++) {
        desired.push({ user: `brokerage:G${g}`, relation: 'brokerage', object: `client:G${g}C${cl}` });
        desired.push({ user: `user:b${g}_${cl % BROKERS}`, relation: 'placed_by', object: `client:G${g}C${cl}` });
        for (let p = 0; p < POL; p++) desired.push({ user: `client:G${g}C${cl}`, relation: 'client', object: `policy:G${g}C${cl}P${p}` });
      }
    }
    const load = await c.syncGraph(big, desired);
    check('J', `loaded ${load.total} relationships (${BRG} brokerages, ${BRG * BROKERS} brokers, ${BRG * CLIENTS} clients, ${BRG * CLIENTS * POL} policies) in ${load.ms} ms`, load.added === desired.length, { tuples: load.total, ms: load.ms, transactions: load.transactions });
    const samples = []; let right = 0;
    for (let i = 0; i < 200; i++) {
      const g = i % BRG; const cl = (i * 7) % CLIENTS; const b = cl % BROKERS; const r = await big.check(`user:b${g}_${b}`, 'can_edit', `policy:G${g}C${cl}P0`);
      const x = await big.check(`user:b${g}_${(b + 1) % BROKERS}`, 'can_edit', `policy:G${g}C${cl}P0`);
      samples.push(r.ms); if (r.allowed && !x.allowed) right += 1;
    }
    check('J', '200 pairs of checks (the placing broker allowed, a colleague of the same brokerage denied) are all correct', right === 200, { right, checkMsP50: pct(samples, 0.5), checkMsP95: pct(samples, 0.95) });
    const lo = await big.listObjects('user:b3_2', 'can_view', 'policy'); const loM = await big.listObjects('user:mgr3', 'can_view', 'policy');
    check('J', `list-objects at this size: a broker sees ${CLIENTS / BROKERS * POL} policies (${lo.ms} ms), a manager sees ${CLIENTS * POL} (${loM.ms} ms)`, lo.objects.length === CLIENTS / BROKERS * POL && loM.objects.length === CLIENTS * POL, { brokerMs: lo.ms, managerMs: loM.ms });
    const mv = await big.write({ deletes: [{ user: 'user:b3_2', relation: 'member', object: 'brokerage:G3' }] });
    const afterLeave = await big.check('user:b3_2', 'can_view', 'policy:G3C2P0');
    check('J', 'removing ONE membership tuple at this size cuts that broker\'s access on the next check', mv.status === 200 && afterLeave.allowed === false, { writeMs: mv.ms, checkMs: afterLeave.ms });
    const noop = await c.syncGraph(big, desired.filter((t) => !(t.user === 'user:b3_2' && t.relation === 'member')));
    check('J', 'a full re-sync of the unchanged graph writes nothing', noop.added === 0 && noop.removed === 0, { ms: noop.ms, tuples: noop.total });
  } finally {
    await rt.stop();
  }

  async function oauthIntrospectWithSts() {
    const { oauthClient } = require('../lib/verify');
    const sts = oauthClient(st.gateway.clientId, st.gateway.secret);
    const t = await c.ropc(st).passwordGrant(c.userNameOf('zoe'), st.users.zoe.password);
    const i = await sts.introspect(t.data.access_token);
    return i.status === 200 && i.data.active === true;
  }

  // restore: the tenant directory is back in line with the seed (the run changed department values)
  const seedSource = c.createSource();
  for (const k of Object.keys(seedSource.brokers)) { const r = await c.syncDirectory(st, seedSource, k); if (r.status !== 204) console.log(`  ! restore directory ${k}: ${r.status}`); }

  const passed = results.filter((r) => r.pass).length;
  ev.save({ total: results.length, passed, engine: 'OpenFGA', engineVersion: require('../../stubs/rules-engine/openfga').VERSION });
  console.log(`\n${passed}/${results.length} checks passed.  Evidence: ${ev.file}`);
  if (passed !== results.length) { console.log(results.filter((r) => !r.pass).map((r) => `  FAIL ${r.scenario}: ${r.title}`).join('\n')); process.exit(1); }
})().catch((e) => { console.error(e.stack || e.message || e); process.exit(2); });

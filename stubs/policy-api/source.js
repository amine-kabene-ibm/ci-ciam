'use strict';
// STUB of IFC's relationship SOURCE SYSTEM (UC-12 precondition: "relationship graph populated and kept in sync with the source system").
// It owns who works for which brokerage, which broker placed which client, and which policies a client holds. Fictional data.
// desiredTuples() turns that into the relationship graph; syncGraph() makes the rules engine (OpenFGA) match it, writing only the difference.
//   brokerage -> broker (member / manager) ; brokerage + placing broker -> client ; client -> policy

const SEED = {
  brokerages: { 'BRG-A': 'Alpha Courtage', 'BRG-B': 'Beta Assurance' },
  // key = short name used in user names (ifc-demo-uc12-<key>); role "broker" works clients, role "manager" oversees a brokerage.
  // zoe has a valid Verify account and NO relationship: authenticated is not authorized.
  brokers: {
    anna: { given: 'Anna', family: 'Leclerc', role: 'broker', brokerage: 'BRG-A', brokerId: 'BRK-0101' },
    ben: { given: 'Ben', family: 'Okafor', role: 'broker', brokerage: 'BRG-B', brokerId: 'BRK-0102' },
    maya: { given: 'Maya', family: 'Tanaka', role: 'manager', brokerage: 'BRG-A', brokerId: 'MGR-0201' },
    noor: { given: 'Noor', family: 'Haddad', role: 'manager', brokerage: 'BRG-B', brokerId: 'MGR-0202' },
    zoe: { given: 'Zoe', family: 'Martin', role: 'broker', brokerage: null, brokerId: 'BRK-0103' },
  },
  clients: {
    'C-0001': { name: 'Tremblay', brokerage: 'BRG-A', placedBy: 'anna' },
    'C-0002': { name: 'Gagnon', brokerage: 'BRG-A', placedBy: 'anna' },
    'C-0003': { name: 'Roy', brokerage: 'BRG-B', placedBy: 'ben' },
    'C-0004': { name: 'Lavoie', brokerage: 'BRG-B', placedBy: 'ben' },
  },
  policies: {
    'IFC-100001': { client: 'C-0001', product: 'Auto', premiumMonthly: 142.5 },
    'IFC-100002': { client: 'C-0001', product: 'Home', premiumMonthly: 88.0 },
    'IFC-100003': { client: 'C-0002', product: 'Auto', premiumMonthly: 131.25 },
    'IFC-100004': { client: 'C-0003', product: 'Tenant', premiumMonthly: 31.0 },
    'IFC-100005': { client: 'C-0004', product: 'Home', premiumMonthly: 97.4 },
    'IFC-100006': { client: 'C-0004', product: 'Auto', premiumMonthly: 160.0 },
  },
};

const clone = (x) => JSON.parse(JSON.stringify(x));

function createSource() {
  let data = clone(SEED);
  const src = {
    get brokerages() { return data.brokerages; },
    get brokers() { return data.brokers; },
    get clients() { return data.clients; },
    get policies() { return data.policies; },
    seed: SEED,
    reset() { data = clone(SEED); },
    snapshot() { return clone(data); },
    policyInfo(number) {
      const p = data.policies[number];
      if (!p) return null;
      const c = data.clients[p.client];
      return { policyNumber: number, product: p.product, premiumMonthly: p.premiumMonthly, client: p.client, clientName: c.name };
    },
    // A broker joins another brokerage (and so leaves the old one). By default the clients stay where they were: they belong to the
    // brokerage. With withBook the broker's book of business moves too (the clients this broker placed now belong to the new brokerage).
    moveBroker(key, brokerage, withBook = false) {
      if (!data.brokers[key]) throw new Error(`unknown broker ${key}`);
      if (!data.brokerages[brokerage]) throw new Error(`unknown brokerage ${brokerage}`);
      data.brokers[key].brokerage = brokerage;
      if (withBook) for (const c of Object.values(data.clients)) if (c.placedBy === key) c.brokerage = brokerage;
    },
    // A broker leaves the brokerage and joins none (offboarding from the brokerage, the account may still exist).
    leaveBrokerage(key) {
      if (!data.brokers[key]) throw new Error(`unknown broker ${key}`);
      data.brokers[key].brokerage = null;
    },
    // Book transfer: the client moves to another broker, and so to that broker's brokerage.
    transferClient(clientId, brokerKey) {
      if (!data.clients[clientId]) throw new Error(`unknown client ${clientId}`);
      if (!data.brokers[brokerKey]) throw new Error(`unknown broker ${brokerKey}`);
      if (!data.brokers[brokerKey].brokerage) throw new Error(`broker ${brokerKey} has no brokerage`);
      data.clients[clientId].placedBy = brokerKey;
      data.clients[clientId].brokerage = data.brokers[brokerKey].brokerage;
    },
    // The relationship graph this data implies. subOf(key) = the broker's Verify user id (the `sub` of their token).
    desiredTuples(subOf) {
      const t = [];
      for (const [key, b] of Object.entries(data.brokers)) {
        if (b.brokerage) t.push({ user: `user:${subOf(key)}`, relation: b.role === 'manager' ? 'manager' : 'member', object: `brokerage:${b.brokerage}` });
      }
      for (const [id, c] of Object.entries(data.clients)) {
        t.push({ user: `brokerage:${c.brokerage}`, relation: 'brokerage', object: `client:${id}` });
        t.push({ user: `user:${subOf(c.placedBy)}`, relation: 'placed_by', object: `client:${id}` });
      }
      for (const [n, p] of Object.entries(data.policies)) t.push({ user: `client:${p.client}`, relation: 'client', object: `policy:${n}` });
      return t;
    },
  };
  return src;
}

const keyOf = (t) => `${t.user}|${t.relation}|${t.object}`;
const strip = (t) => ({ user: t.user, relation: t.relation, object: t.object });

// Make the engine's graph equal to `desired`. Writes only the difference, in transactions of at most 100 tuples. Safe to repeat (0 changes).
async function syncGraph(fga, desired) {
  const t0 = Date.now();
  const current = await fga.read();
  const have = new Map(current.map((t) => [keyOf(t), t]));
  const want = new Map(desired.map((t) => [keyOf(t), t]));
  const writes = desired.filter((t) => !have.has(keyOf(t))).map(strip);
  const deletes = current.filter((t) => !want.has(keyOf(t))).map(strip);
  const added = writes.length; const removed = deletes.length;
  let ops = 0;
  while (writes.length || deletes.length) {
    const r = await fga.write({ writes: writes.splice(0, 50), deletes: deletes.splice(0, 50) });
    if (r.status !== 200) throw new Error(`graph write failed: HTTP ${r.status} ${JSON.stringify(r.data).slice(0, 200)}`);
    ops += 1;
  }
  return { added, removed, unchanged: desired.length - added, total: desired.length, transactions: ops, ms: Date.now() - t0 };
}

module.exports = { SEED, createSource, syncGraph };

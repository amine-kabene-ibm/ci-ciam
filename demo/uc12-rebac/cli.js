'use strict';
// Terminal client for the UC-12 demo (needs serve.js running). The presenter's alternative to the browser console.
//   node demo/uc12-rebac/cli.js matrix                          who can see what, every broker x policy (engine answer)
//   node demo/uc12-rebac/cli.js signin  <broker>                real Verify sign-in (anna ben maya noor zoe)
//   node demo/uc12-rebac/cli.js read    <broker> <policy>       GET  /api/policies/<n>      with that broker's token
//   node demo/uc12-rebac/cli.js edit    <broker> <policy>       PUT  /api/policies/<n>
//   node demo/uc12-rebac/cli.js list    <broker>                every policy this broker can access (list-objects)
//   node demo/uc12-rebac/cli.js who     <broker> <policy>       who can view / edit the policy (list-users)
//   node demo/uc12-rebac/cli.js move    <broker> <BRG-x> [--book]   broker changes brokerage (--book: takes their clients)
//   node demo/uc12-rebac/cli.js leave   <broker>                broker leaves the brokerage
//   node demo/uc12-rebac/cli.js transfer <client> <broker>      client changes hands
//   node demo/uc12-rebac/cli.js reset                           restore the demo data
//   node demo/uc12-rebac/cli.js log                             last gateway decisions with the reasoning path
const axios = require('axios');
const { GATEWAY_URL } = require('./common');

const [, , cmd, a, b, flag] = process.argv;
const post = (p, body) => axios.post(GATEWAY_URL + p, body, { validateStatus: () => true }).then((r) => r.data);

async function matrix() {
  const s = (await axios.get(`${GATEWAY_URL}/console/state`)).data;
  const m = (await axios.get(`${GATEWAY_URL}/console/matrix`)).data;
  const keys = s.brokers.map((x) => x.key);
  console.log(['policy'.padEnd(12), 'client'.padEnd(14), 'held by'.padEnd(8), ...keys.map((k) => `${k}(${s.brokers.find((x) => x.key === k).brokerage || '-'})`.padEnd(12))].join(' '));
  for (const [n, p] of Object.entries(s.policies)) {
    const cl = s.clients[p.client];
    console.log([n.padEnd(12), `${p.client} ${cl.name}`.padEnd(14), cl.brokerage.padEnd(8), ...keys.map((k) => { const x = m.matrix[k][n]; return (x.edit ? 'view+edit' : x.view ? 'view' : '-').padEnd(12); })].join(' '));
  }
  console.log(`\n${m.tuples} relationships; ${keys.length * Object.keys(s.policies).length * 2} checks in ${m.ms} ms`);
}

(async () => {
  try {
    if (cmd === 'matrix') return await matrix();
    if (cmd === 'signin') return console.log(JSON.stringify(await post('/console/signin', { broker: a }), null, 2));
    if (['read', 'edit'].includes(cmd)) { const r = await post('/console/call', { broker: a, action: cmd === 'read' ? 'view' : 'edit', policy: b }); return console.log(`${r.request}\n-> HTTP ${r.status} in ${r.ms} ms\n${JSON.stringify(r.body, null, 2)}`); }
    if (cmd === 'list') { const r = await post('/console/call', { broker: a, action: 'list' }); return console.log(`${r.request}\n-> HTTP ${r.status} in ${r.ms} ms\n${JSON.stringify(r.body, null, 2)}`); }
    if (cmd === 'who') { const r = await post('/console/call', { broker: a, action: 'who', policy: b }); return console.log(`-> HTTP ${r.status}\n${JSON.stringify(r.body, null, 2)}`); }
    if (cmd === 'move') return console.log(JSON.stringify(await post('/console/change', { type: 'move', broker: a, brokerage: b, withBook: flag === '--book' }), null, 2));
    if (cmd === 'leave') return console.log(JSON.stringify(await post('/console/change', { type: 'leave', broker: a }), null, 2));
    if (cmd === 'transfer') return console.log(JSON.stringify(await post('/console/change', { type: 'transfer', client: a, broker: b }), null, 2));
    if (cmd === 'reset') return console.log(JSON.stringify(await post('/console/change', { type: 'reset' }), null, 2));
    if (cmd === 'log') { const l = (await axios.get(`${GATEWAY_URL}/api/log`)).data.slice(-8); return l.forEach((e) => console.log(`${e.at.slice(11, 23)} ${String(e.decision).toUpperCase().padEnd(5)} ${(e.who || e.sub || '').padEnd(14)} ${(e.method || '')} ${e.path}  ${e.reason}  check ${e.checkMs == null ? '-' : e.checkMs + ' ms'}`)); }
    console.log('usage: see the header of demo/uc12-rebac/cli.js');
  } catch (e) { console.error(e.code === 'ECONNREFUSED' ? 'Gateway is not running: node demo/uc12-rebac/serve.js' : e.message); process.exit(1); }
})();

'use strict';
// Live demo runtime: relationship engine (OpenFGA :4171) + policy gateway and console (http://127.0.0.1:4170). Leave it running.
//   node demo/uc12-rebac/serve.js
// Then the browser console at http://127.0.0.1:4170, or the terminal client: node demo/uc12-rebac/cli.js help
const c = require('./common');
const { boot } = require('./runtime');

const st = c.state.read();
if (!st || !st.users) { console.error('Run setup first: node demo/uc12-rebac/setup.js'); process.exit(1); }

boot(st).then((rt) => {
  console.log(`Relationship engine  OpenFGA v${rt.boot.bin.version}  http://127.0.0.1:${c.FGA_PORT}  store ${rt.boot.storeId}  model ${rt.boot.modelId}`);
  console.log(`Graph loaded         ${rt.boot.sync.total} relationships from the source system in ${rt.boot.sync.ms} ms`);
  console.log(`Policy gateway       ${rt.url}   (console UI at /, API at /api)`);
  console.log('Tokens are introspected with the gateway STS client, not the admin client. Ctrl-C to stop (the graph is in memory and is rebuilt on start).');
  const bye = async () => { await rt.stop(); process.exit(0); };
  process.on('SIGINT', bye); process.on('SIGTERM', bye);
}).catch((e) => { console.error(e.message); process.exit(1); });

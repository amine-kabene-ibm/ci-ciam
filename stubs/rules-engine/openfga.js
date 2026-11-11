'use strict';
// STUB of IFC's "fine-grained authorization service / rules engine" (UC-12): OpenFGA (open source, CNCF), run as a native process.
//   ensureBinary()  downloads the pinned release into demo/out/bin (gitignored) and checks its SHA-256 against the published checksums
//   startEngine()   starts it with the in-memory datastore on 127.0.0.1 (data is lost when it stops: the graph is rebuilt by sync)
//   FgaClient       the few OpenFGA HTTP calls the demo needs: store, model, write, read, check, list-objects, list-users
// Why native and not Podman: the Podman VM on this laptop did not come up (socket refused after `podman machine start`), and OpenFGA is a single
// static Go binary. IFC would run it as a container or use its own rules engine; the gateway code does not change.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, spawnSync, execFileSync } = require('child_process');
const axios = require('axios');

const VERSION = '1.22.1';
const BIN_DIR = path.join(__dirname, '..', '..', 'demo', 'out', 'bin');
const BIN = path.join(BIN_DIR, 'openfga');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// `openfga version` prints to stderr.
function binaryVersion() {
  const r = spawnSync(BIN, ['version'], { encoding: 'utf8' });
  const m = /version `v?(\d+\.\d+\.\d+)`/.exec(`${r.stdout || ''}${r.stderr || ''}`);
  return m ? m[1] : null;
}

// Node can run under Rosetta on Apple Silicon (process.arch === 'x64'), so ask the hardware instead.
function hostArch() {
  if (process.platform === 'darwin') {
    const r = spawnSync('sysctl', ['-n', 'hw.optional.arm64'], { encoding: 'utf8' });
    return String(r.stdout).trim() === '1' ? 'arm64' : 'amd64';
  }
  return { arm64: 'arm64', x64: 'amd64' }[process.arch];
}

async function ensureBinary() {
  if (fs.existsSync(BIN)) { const v = binaryVersion(); if (v === VERSION) return { path: BIN, version: v, downloaded: false }; }
  const platform = { darwin: 'darwin', linux: 'linux' }[process.platform];
  const arch = hostArch();
  if (!platform || !arch) throw new Error(`no OpenFGA release for ${process.platform}/${process.arch}`);
  const file = `openfga_${VERSION}_${platform}_${arch}.tar.gz`;
  const base = `https://github.com/openfga/openfga/releases/download/v${VERSION}`;
  const get = (u) => axios.get(u, { responseType: 'arraybuffer', maxRedirects: 5, timeout: 120000 }).then((r) => Buffer.from(r.data));
  const [tgz, sums] = await Promise.all([get(`${base}/${file}`), get(`${base}/checksums.txt`)]);
  const line = sums.toString().split('\n').find((l) => l.trim().endsWith(` ${file}`));
  const want = line && line.trim().split(/\s+/)[0];
  const got = crypto.createHash('sha256').update(tgz).digest('hex');
  if (!want || want !== got) throw new Error(`OpenFGA download checksum mismatch for ${file}`);
  fs.mkdirSync(BIN_DIR, { recursive: true });
  const tmp = path.join(os.tmpdir(), `openfga-${process.pid}.tgz`);
  fs.writeFileSync(tmp, tgz);
  execFileSync('tar', ['xzf', tmp, '-C', BIN_DIR, 'openfga']);
  fs.unlinkSync(tmp);
  return { path: BIN, version: binaryVersion(), downloaded: true, sha256: got };
}

async function isUp(url) {
  try { const r = await axios.get(`${url}/healthz`, { timeout: 1000, validateStatus: () => true }); return r.status === 200; } catch (e) { return false; }
}

// Starts the engine and waits for /healthz. Rejects if the process exits first (e.g. port already in use).
async function startEngine({ port, grpcPort }) {
  const url = `http://127.0.0.1:${port}`;
  if (await isUp(url)) throw new Error(`something already answers on ${url}`);
  const child = spawn(BIN, ['run', '--datastore-engine', 'memory', '--http-addr', `127.0.0.1:${port}`, '--grpc-addr', `127.0.0.1:${grpcPort}`,
    '--metrics-enabled=false', '--playground-enabled=false', '--log-level', 'error'], { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = ''; let exited = null;
  child.stderr.on('data', (d) => { stderr += d; });
  child.on('exit', (code) => { exited = code; });
  for (let i = 0; i < 60; i++) {
    if (exited !== null) throw new Error(`openfga exited (${exited}): ${stderr.slice(0, 300)}`);
    if (await isUp(url)) return { url, pid: child.pid, child, stop: () => { try { child.kill('SIGTERM'); } catch (e) { /* gone */ } } };
    await sleep(250);
  }
  child.kill('SIGTERM');
  throw new Error('openfga did not become healthy in 15 s');
}

class FgaClient {
  constructor(url) { this.url = url; this.storeId = null; this.modelId = null; }
  async call(method, p, body) {
    const t0 = Date.now();
    const r = await axios({ method, url: `${this.url}${p}`, data: body, validateStatus: () => true, timeout: 15000 });
    return { status: r.status, data: r.data, ms: Date.now() - t0 };
  }
  async must(method, p, body) {
    const r = await this.call(method, p, body);
    if (r.status >= 300) throw new Error(`openfga ${method} ${p.replace(/\/stores\/[^/]+/, '/stores/_')} -> ${r.status} ${JSON.stringify(r.data).slice(0, 200)}`);
    return r;
  }
  use(storeId, modelId) { this.storeId = storeId; this.modelId = modelId; return this; }
  async createStore(name) { return (await this.must('POST', '/stores', { name })).data.id; }
  async writeModel(typeDefinitions) {
    const r = await this.must('POST', `/stores/${this.storeId}/authorization-models`, { schema_version: '1.1', type_definitions: typeDefinitions });
    this.modelId = r.data.authorization_model_id;
    return this.modelId;
  }
  // writes/deletes: [{user, relation, object}]. One request = one transaction (OpenFGA allows 100 tuples per write by default).
  async write({ writes = [], deletes = [] }) {
    if (writes.length > 100 || deletes.length > 100) throw new Error('more than 100 tuples in one write: chunk it');
    const body = { authorization_model_id: this.modelId };
    if (writes.length) body.writes = { tuple_keys: writes };
    if (deletes.length) body.deletes = { tuple_keys: deletes };
    return this.call('POST', `/stores/${this.storeId}/write`, body);
  }
  async check(user, relation, object) {
    const r = await this.must('POST', `/stores/${this.storeId}/check`, { tuple_key: { user, relation, object }, authorization_model_id: this.modelId });
    return { allowed: r.data.allowed === true, ms: r.ms };
  }
  async listObjects(user, relation, type) {
    const r = await this.must('POST', `/stores/${this.storeId}/list-objects`, { user, relation, type, authorization_model_id: this.modelId });
    return { objects: r.data.objects || [], ms: r.ms };
  }
  async listUsers(object, relation, userType) {
    const [type, id] = object.split(/:(.*)/);
    const r = await this.must('POST', `/stores/${this.storeId}/list-users`, {
      object: { type, id }, relation, user_filters: [{ type: userType }], authorization_model_id: this.modelId });
    return { users: (r.data.users || []).map((u) => `${u.object.type}:${u.object.id}`), ms: r.ms };
  }
  // All tuples, or those of one object + relation (tuple_key {object, relation}).
  async read(tupleKey) {
    const out = []; let token;
    do {
      const r = await this.must('POST', `/stores/${this.storeId}/read`, { ...(tupleKey ? { tuple_key: tupleKey } : {}), page_size: 100, ...(token ? { continuation_token: token } : {}) });
      out.push(...(r.data.tuples || []).map((t) => t.key));
      token = r.data.continuation_token;
    } while (token);
    return out;
  }
}

module.exports = { VERSION, BIN, ensureBinary, startEngine, isUp, FgaClient };

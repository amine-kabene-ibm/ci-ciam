'use strict';
// STUB: IFC customer self-service portal, "My trusted devices" (UC-04). Port 4041 by default.
// The signed-in customer (password-grant token, no admin rights) can: register a device (QR for the real IBM Verify app, or "simulate a phone scan"),
// see the registered devices, send a test push to one, and revoke one. All logic lives in devices.js; this file is HTTP + one HTML page.
// The customer is fixed from the UC-04 state file (no login screen: the portal's own sign-in is out of scope here, see UC-08 / UC-01).
const express = require('express');
const http = require('http');
const { createDeviceService } = require('./devices');

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Intact - My trusted devices</title>
<style>
body{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;margin:0;background:#f4f4f4;color:#161616}
header{background:#c60c30;color:#fff;padding:14px 24px;font-size:18px}header small{opacity:.85;margin-left:12px}
main{max-width:980px;margin:20px auto;padding:0 16px;display:grid;grid-template-columns:1fr 1fr;gap:16px}
section{background:#fff;border:1px solid #e0e0e0;padding:16px}h2{margin:0 0 10px;font-size:15px}.wide{grid-column:1 / span 2}
button,select,input{padding:7px 12px;font-size:14px}button{background:#0f62fe;color:#fff;border:0;cursor:pointer}button.alt{background:#393939}button.del{background:#da1e28}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid #e0e0e0;padding:6px;text-align:left}
.badge{display:inline-block;padding:2px 9px;border-radius:12px;font-size:12px;color:#fff;background:#8d8d8d}.ACTIVE,.VERIFY_SUCCESS{background:#198038}.PENDING{background:#f1c21b;color:#161616}.USER_DENIED,.VERIFY_FAILED,.TIMEOUT{background:#da1e28}
pre{background:#f4f4f4;padding:8px;overflow:auto;font-size:12px}.muted{color:#6f6f6f;font-size:12px}img{max-width:220px;border:1px solid #e0e0e0}
</style></head><body>
<header>Intact Financial <small>My account - trusted devices (IBM Verify)</small></header>
<main>
<section class="wide"><h2>1. My trusted devices <span class="muted" id="who"></span></h2><button class="alt" onclick="load()">Refresh</button>
<div id="devs"></div></section>
<section><h2>2. Register device</h2>
<p class="muted">Real phone: install IBM Verify, press Show QR, scan it (Add account). Simulated phone: no QR needed.</p>
<button onclick="qr()">Show QR code</button> <button class="alt" onclick="sim()">Simulate a phone scan</button><br><br>
Device name <input id="dn" value="Marie's second phone" size="22"> <select id="pf"><option>IOS</option><option>Android</option></select>
<div id="qrbox"></div></section>
<section><h2>3. Send a test push</h2>
<p class="muted">Pick a device in the table. A simulated phone answers by itself; a real phone shows the push and you tap Approve.</p>
<select id="ans"><option value="approve">simulated phone approves</option><option value="deny">simulated phone denies</option><option value="none">real phone: I will answer</option></select>
<input id="loc" value="Montreal, QC, Canada" size="22"><br><br><pre id="out">Nothing sent yet.</pre></section>
</main><script>
const $=i=>document.getElementById(i);let sel=null;
async function j(p,o){const r=await fetch(p,Object.assign({headers:{'Content-Type':'application/json'}},o||{}));return {s:r.status,d:await r.json().catch(()=>({}))}}
async function load(){const r=await j('/api/devices');if(r.s!==200){$('devs').textContent=r.d.error;return}$('who').textContent='('+r.d.userName+')';
 const d=r.d.devices;$('devs').innerHTML=d.length?'<table><tr><th></th><th>Device</th><th>Platform</th><th>State</th><th>Registered</th><th></th></tr>'+d.map(x=>'<tr><td><input type="radio" name="d" onclick="sel=\\''+x.id+'\\'" '+(sel===x.id?'checked':'')+'></td><td>'+x.deviceName+(x.simulated?' <span class="muted">(simulated)</span>':'')+'</td><td>'+x.platformType+' '+(x.deviceType||'')+'</td><td><span class="badge '+x.state+'">'+x.state+'</span></td><td>'+x.created.slice(0,19).replace('T',' ')+'</td><td><button class="del" onclick="rev(\\''+x.id+'\\')">Revoke</button> <button onclick="push(\\''+x.id+'\\')">Push</button></td></tr>').join('')+'</table>':'<p>No trusted device registered.</p>'}
async function qr(){$('qrbox').innerHTML='<p class="muted">loading...</p>';const r=await fetch('/api/qr');if(r.status!==200){$('qrbox').textContent='QR failed: HTTP '+r.status;return}$('qrbox').innerHTML='<p><img src="'+URL.createObjectURL(await r.blob())+'"></p><p class="muted">Scan with IBM Verify. Then Refresh.</p>'}
async function sim(){const r=await j('/api/simulate',{method:'POST',body:JSON.stringify({deviceName:$('dn').value,platformType:$('pf').value})});$('out').textContent=JSON.stringify(r.d,null,2);load()}
async function push(id){$('out').textContent='sending...';const r=await j('/api/push/'+id,{method:'POST',body:JSON.stringify({answer:$('ans').value,location:$('loc').value})});$('out').textContent=JSON.stringify(r.d,null,2);load()}
async function rev(id){const r=await j('/api/devices/'+id,{method:'DELETE'});$('out').textContent=JSON.stringify(r.d,null,2);load()}
load();
</script></body></html>`;

function buildApp(svc, who) {
  const app = express();
  app.use(express.json());
  const fail = (res, r) => res.status(r.httpStatus || 500).json({ error: r.error, cid: r.cid || null });
  app.get('/', (req, res) => res.type('html').send(PAGE));
  app.get('/health', (req, res) => res.json({ ok: true }));
  app.get('/api/devices', async (req, res) => { const r = await svc.list(); return r.error ? fail(res, r) : res.json({ userName: who, devices: r.devices }); });
  app.get('/api/qr', async (req, res) => { const r = await svc.initiate(`Intact (${who})`, { format: 'png' }); return r.error ? fail(res, r) : res.type('png').send(r.png); });
  app.post('/api/simulate', async (req, res) => {
    const b = req.body || {};
    const r = await svc.simulateScan({ deviceName: String(b.deviceName || 'Simulated phone').slice(0, 40), platformType: b.platformType === 'Android' ? 'Android' : 'IOS', deviceType: b.platformType === 'Android' ? 'Pixel 8' : 'iPhone' });
    return r.error ? fail(res, r) : res.json({ registered: r.id, registerMs: r.registerMs, steps: r.steps });
  });
  app.post('/api/push/:id', async (req, res) => {
    const b = req.body || {};
    const p = await svc.push(req.params.id, { message: 'Is this you? Confirm this action in your Intact account.', location: String(b.location || ''), type: 'Test push' });
    if (p.error) return fail(res, p);
    const dev = svc.sims.get(req.params.id);
    let answered = null;
    if (dev && b.answer !== 'none') answered = await dev.handleNext(b.answer === 'deny' ? 'deny' : 'approve', { timeoutMs: 10000, intervalMs: 300 });
    const done = await svc.waitFor(req.params.id, p.txn.id, { timeoutMs: dev && b.answer !== 'none' ? 8000 : 60000 });
    return res.json({ pushHttpMs: p.ms, deviceSawItAfterMs: answered && answered.seenMs, finalState: done.txn && done.txn.state, waitedMs: done.waitedMs, note: dev ? 'simulated phone' : 'real phone: tap Approve/Deny in IBM Verify' });
  });
  app.delete('/api/devices/:id', async (req, res) => { const r = await svc.revoke(req.params.id); return r.error ? fail(res, r) : res.json({ revoked: req.params.id, ms: r.ms }); });
  return app;
}

function startServer(port, svc, who) {
  const app = buildApp(svc, who);
  return new Promise((resolve, reject) => {
    const server = http.createServer(app).listen(port, '127.0.0.1', () => resolve({ server, url: `http://localhost:${port}` }));
    server.on('error', reject);
  });
}

module.exports = { startServer, buildApp };

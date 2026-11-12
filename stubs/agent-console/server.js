'use strict';
// STUB: IFC Contact Center agent console (UC-14). Port 4140 by default.
// A small web page for the agent: type the caller's user name, click Verify, watch the CIBA request go pending then verified,
// then use the actions that are only possible after the caller approved (read profile, unlock account), and read the audit trail.
// All logic lives in agent.js; this file is HTTP + one HTML page. No credentials of the caller ever pass through this console.
const express = require('express');
const http = require('http');
const { createAgentConsole } = require('./agent');

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>IFC Contact Center - Agent console</title>
<style>
body{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;margin:0;background:#f4f4f4;color:#161616}
header{background:#c60c30;color:#fff;padding:14px 24px;font-size:18px}header small{opacity:.85;margin-left:12px}
main{max-width:980px;margin:20px auto;padding:0 16px;display:grid;grid-template-columns:1fr 1fr;gap:16px}
section{background:#fff;border:1px solid #e0e0e0;padding:16px}h2{margin:0 0 10px;font-size:15px}
input{padding:8px;border:1px solid #8d8d8d;width:62%;font-size:14px}button{padding:8px 14px;background:#0f62fe;color:#fff;border:0;font-size:14px;cursor:pointer}
button:disabled{background:#c6c6c6;cursor:not-allowed}button.alt{background:#393939}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:13px;color:#fff}
.pending{background:#f1c21b;color:#161616}.verified{background:#198038}.expired,.denied,.error,.none{background:#8d8d8d}.denied,.error{background:#da1e28}
pre{background:#f4f4f4;padding:8px;overflow:auto;font-size:12px;margin:8px 0 0}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border-bottom:1px solid #e0e0e0;padding:4px;text-align:left}
.wide{grid-column:1 / span 2}.muted{color:#6f6f6f;font-size:12px}
</style></head><body>
<header>IFC Contact Center <small>Agent console - caller verification (CIBA)</small></header>
<main>
<section><h2>1. Verify the caller</h2>
<input id="u" value="" placeholder="caller user name"> <button id="go" onclick="start()">Verify customer</button>
<p class="muted">Sends a back-channel request to the caller's registered channel. The agent never sees or types a credential.</p>
<p>Status: <span id="st" class="badge none">not started</span> <span id="left" class="muted"></span></p>
<p id="bm" class="muted"></p><pre id="msg">Waiting for an agent action.</pre></section>
<section><h2>2. Agent actions (need a verified caller)</h2>
<button id="pf" onclick="act('profile')" disabled>Read caller profile</button>
<button id="ul" onclick="act('unlock')" disabled class="alt">Unlock account</button>
<pre id="out">Locked until the caller approves.</pre></section>
<section class="wide"><h2>3. Audit trail (Verify events API)</h2><button class="alt" onclick="aud()">Refresh audit</button>
<span class="muted" id="ac"></span><div id="at"></div></section>
</main>
<script>
let sid=null,timer=null,since=Date.now()-60000,who='';
const $=i=>document.getElementById(i);
async function j(p,o){const r=await fetch(p,o);return {s:r.status,d:await r.json()}}
function show(s){const e=$('st');e.textContent=s.status;e.className='badge '+s.status;$('bm').textContent='Message shown to the caller: "'+s.bindingMessage+'"';
 $('left').textContent=s.status==='verified'?('verified window: '+s.verifiedLeftSec+' s left'):('polls: '+s.polls);
 const ok=s.status==='verified';$('pf').disabled=!ok;$('ul').disabled=!ok;
 $('msg').textContent=s.status==='pending'?'Request sent. Waiting for '+s.userName+' to approve (polling every '+s.intervalSec+' s)...':(s.reason||s.status);
 if(s.status!=='pending'&&timer){clearInterval(timer);timer=null;aud()}}
async function start(){who=$('u').value.trim();if(!who)return;since=Date.now()-5000;
 const r=await j('/api/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({userName:who})});
 if(r.s!==200){$('st').textContent='error';$('st').className='badge error';$('msg').textContent=r.d.error;return}
 sid=r.d.session.id;show(r.d.session);if(timer)clearInterval(timer);timer=setInterval(async()=>{const p=await j('/api/session/'+sid);if(p.s===200)show(p.d.session)},2000)}
async function act(a){const r=await j('/api/'+a+'/'+sid,{method:'POST'});$('out').textContent=JSON.stringify(r.d,null,2);aud()}
async function aud(){const r=await j('/api/audit?since='+since+'&user='+encodeURIComponent(who));if(r.s!==200){$('at').textContent=r.d.error;return}
 const a=r.d.audit;$('ac').textContent=' '+a.pendingPolls+' "still pending" poll event(s) hidden';
 $('at').innerHTML='<table><tr><th>time (UTC)</th><th>kind</th><th>result</th><th>detail</th></tr>'+a.rows.map(x=>'<tr><td>'+x.time.slice(11,19)+'</td><td>'+x.kind+'</td><td>'+x.result+'</td><td>'+(x.bindingMessage?('"'+x.bindingMessage+'" '):'')+(x.cause||'')+'</td></tr>').join('')+'</table>'}
</script></body></html>`;

function buildApp(consoleLogic) {
  const app = express();
  app.use(express.json());
  const send = (res, r, key) => (r.error ? res.status(r.httpStatus || 500).json({ error: r.error, oauthError: r.oauthError || null, cid: r.cid || null }) : res.json({ [key]: r[key] }));
  app.get('/', (req, res) => res.type('html').send(PAGE));
  app.get('/health', (req, res) => res.json({ ok: true }));
  app.post('/api/verify', async (req, res) => send(res, await consoleLogic.startVerification(String((req.body || {}).userName || '').trim()), 'session'));
  app.get('/api/session/:id', async (req, res) => send(res, await consoleLogic.poll(req.params.id), 'session'));
  app.post('/api/profile/:id', async (req, res) => send(res, await consoleLogic.profile(req.params.id), 'profile'));
  app.post('/api/unlock/:id', async (req, res) => send(res, await consoleLogic.unlock(req.params.id), 'unlock'));
  app.get('/api/audit', async (req, res) => send(res, await consoleLogic.audit({ sinceMs: Number(req.query.since) || undefined, userName: req.query.user || undefined }), 'audit'));
  return app;
}

function startServer(port, cfg) {
  const app = buildApp(createAgentConsole(cfg));
  return new Promise((resolve, reject) => {
    const server = http.createServer(app).listen(port, '127.0.0.1', () => resolve({ server, url: `http://localhost:${port}` }));
    server.on('error', reject);
  });
}

module.exports = { startServer, buildApp };

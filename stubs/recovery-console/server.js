'use strict';
// STUB: IFC recovery console (UC-03). Port 4030 by default.
// Two roles on one page, so the demo fits one screen:
//   1. "Customer portal": the policyholder starts recovery. The customer only learns the ROUTE (self-service link or call the agent), never the reasons.
//   2. "Agent console": risk signals read from Verify, caller verification (Verify e-mails a one-time code to the address ON FILE),
//      "Reset password and end sessions", and the audit trail.
// All logic lives in recovery.js; this file is HTTP + one HTML page.
const express = require('express');
const http = require('http');
const { createRecoveryConsole } = require('./recovery');

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>IFC - Account recovery</title>
<style>
body{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;margin:0;background:#f4f4f4;color:#161616}
header{background:#c60c30;color:#fff;padding:14px 24px;font-size:18px}header small{opacity:.85;margin-left:12px}
main{max-width:1060px;margin:20px auto;padding:0 16px;display:grid;grid-template-columns:1fr 1fr;gap:16px}
section{background:#fff;border:1px solid #e0e0e0;padding:16px}h2{margin:0 0 10px;font-size:15px}
input{padding:8px;border:1px solid #8d8d8d;width:58%;font-size:14px}button{padding:8px 14px;background:#0f62fe;color:#fff;border:0;font-size:14px;cursor:pointer;margin:2px 0}
button:disabled{background:#c6c6c6;cursor:not-allowed}button.alt{background:#393939}button.danger{background:#da1e28}
.badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:13px;color:#fff}.low{background:#198038}.high{background:#da1e28}.none{background:#8d8d8d}
pre{background:#f4f4f4;padding:8px;overflow:auto;font-size:12px;margin:8px 0 0;white-space:pre-wrap}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border-bottom:1px solid #e0e0e0;padding:4px;text-align:left}
.wide{grid-column:1 / span 2}.muted{color:#6f6f6f;font-size:12px}ul{margin:6px 0;padding-left:18px;font-size:13px}
</style></head><body>
<header>IFC <small>Account recovery - customer portal and contact-center console (UC-03 demo stub)</small></header>
<main>
<section><h2>1. Customer portal: "I cannot sign in"</h2>
<input id="u" placeholder="user name"> <button onclick="recover()">Start recovery</button>
<p class="muted">The customer is told the route, never the reasons: an attacker must not learn what trips the rules.</p>
<pre id="pub">Waiting.</pre></section>
<section><h2>2. Agent console: risk signals (read from Verify)</h2>
<p>Case: <span id="cid" class="muted">none</span> &nbsp; Risk: <span id="risk" class="badge none">-</span> &nbsp; Route: <span id="route" class="muted">-</span></p>
<ul id="why"><li class="muted">Start a recovery first.</li></ul><div id="sig"></div></section>
<section><h2>3. Agent: verify the caller, then recover</h2>
<button id="b1" onclick="vstart()" disabled>Send a code to the address on file</button><br>
<input id="code" placeholder="code the caller reads out"> <button id="b2" onclick="vconfirm()" disabled class="alt">Confirm</button>
<p class="muted" id="vst">The agent never sees or types the caller's credential. The code goes only to the e-mail on file; the agent cannot change that address.</p>
<button id="b3" onclick="reset()" disabled class="danger">Reset password and end all sessions</button>
<pre id="out">Locked until the caller is verified.</pre></section>
<section><h2>4. Case log</h2><pre id="log">-</pre></section>
<section class="wide"><h2>5. Audit trail (Verify events API + case log)</h2><button class="alt" onclick="aud()">Refresh audit</button>
<span class="muted"> Verify events appear 15 to 90 s after the action.</span><div id="at"></div></section>
</main>
<script>
let cid=null,who='',since=Date.now()-60000;
const $=i=>document.getElementById(i);
async function j(p,o){const r=await fetch(p,o);return {s:r.status,d:await r.json()}}
const post=(p,b)=>j(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
async function recover(){who=$('u').value.trim();if(!who)return;since=Date.now()-5000;const r=await post('/api/recover',{userName:who});
 $('pub').textContent=r.s===200?JSON.stringify(r.d.public,null,2):JSON.stringify(r.d,null,2);cid=r.d.caseId||null;if(cid)show();else{$('cid').textContent='none (no account, same answer as for any customer)';}}
async function show(){const r=await j('/api/case/'+cid);if(r.s!==200)return;const c=r.d.case;$('cid').textContent=c.id+'  ('+c.userName+')';
 const b=$('risk');b.textContent=c.risk.level+' ('+c.risk.score+')';b.className='badge '+c.risk.level;$('route').textContent=c.route;
 $('why').innerHTML=c.risk.reasons.map(x=>'<li><b>'+x.code+'</b>: '+x.label+' <span class="muted">('+x.evidence+')</span></li>').join('')+c.risk.info.map(x=>'<li class="muted">'+x.code+': '+x.label+'</li>').join('')||'<li>no risk signal</li>';
 $('sig').innerHTML='<table><tr><th>time (UTC)</th><th>result</th><th>device</th><th>origin</th><th>country</th></tr>'+c.recentAttempts.map(a=>'<tr><td>'+a.time.slice(11,19)+'</td><td>'+a.result+'</td><td>'+(a.device||'').slice(0,28)+'</td><td>'+a.origin+'</td><td>'+(a.country||'')+'</td></tr>').join('')+'</table><p class="muted">Locked: '+c.locked+' | authenticators: '+c.factors+' | last sign-in: '+(c.lastLogin||'-')+' | e-mail on file: '+c.email+'</p>';
 $('b1').disabled=false;$('b2').disabled=!c.verification;$('b3').disabled=!c.verified;
 $('log').textContent=c.steps.map(s=>s.at.slice(11,19)+' '+(s.ok?'ok  ':'FAIL')+' '+s.step+(s.detail?' - '+s.detail:'')).join('\\n');}
async function vstart(){const r=await post('/api/verify/'+cid+'/start');$('vst').textContent=r.s===200?'Code sent to '+r.d.verification.sentTo+'. Correlation shown to the caller: '+r.d.verification.correlation:r.d.error;show()}
async function vconfirm(){const r=await post('/api/verify/'+cid+'/confirm',{code:$('code').value});$('vst').textContent=r.s===200?'Caller VERIFIED (window '+r.d.verified.ttlSec+' s).':(r.d.error+' ('+(r.d.verifyMessageId||'')+')');show()}
async function reset(){const r=await post('/api/reset/'+cid);$('out').textContent=JSON.stringify(r.d,null,2);show();setTimeout(aud,1500)}
async function aud(){const r=await j('/api/audit?since='+since+'&user='+encodeURIComponent(who));if(r.s!==200){$('at').textContent=r.d.error;return}
 $('at').innerHTML='<table><tr><th>time (UTC)</th><th>event</th><th>result</th><th>by</th><th>origin</th><th>country</th><th>detail</th></tr>'+r.d.audit.rows.map(x=>'<tr><td>'+x.time.slice(11,19)+'</td><td>'+x.kind+'</td><td>'+x.result+'</td><td>'+(x.by||'')+'</td><td>'+(x.origin||'')+'</td><td>'+(x.country||'')+'</td><td>'+(x.cause||'')+'</td></tr>').join('')+'</table>'}
</script></body></html>`;

function buildApp(rc) {
  const app = express();
  app.use(express.json());
  const send = (res, r, key) => (r.error ? res.status(r.httpStatus || 500).json({ error: r.error, verifyMessageId: r.verifyMessageId || null, cid: r.cid || null }) : res.json({ [key]: r[key] }));
  app.get('/', (req, res) => res.type('html').send(PAGE));
  app.get('/callback', (req, res) => res.type('html').send('<p>Signed in. (UC-03 portal stand-in callback)</p>'));
  app.get('/health', (req, res) => res.json({ ok: true }));
  app.post('/api/recover', async (req, res) => {
    const r = await rc.startRecovery(String((req.body || {}).userName || '').trim());
    return r.error ? send(res, r, '') : res.json({ public: r.public, caseId: r.caseId || null });
  });
  app.get('/api/case/:id', (req, res) => { const c = rc.caseView(req.params.id); return c ? res.json({ case: c }) : res.status(404).json({ error: 'unknown case' }); });
  app.get('/api/options/:id', (req, res) => send(res, rc.verificationOptions(req.params.id), 'options'));
  app.post('/api/verify/:id/start', async (req, res) => send(res, await rc.startVerification(req.params.id), 'verification'));
  app.post('/api/verify/:id/confirm', async (req, res) => send(res, await rc.confirmVerification(req.params.id, (req.body || {}).code), 'verified'));
  app.post('/api/reset/:id', async (req, res) => send(res, await rc.resetAndEndSessions(req.params.id), 'reset'));
  app.get('/api/audit', async (req, res) => send(res, await rc.audit({ userName: String(req.query.user || ''), sinceMs: Number(req.query.since) || undefined }), 'audit'));
  return app;
}

function startServer(port, cfg) {
  const app = buildApp(createRecoveryConsole(cfg));
  return new Promise((resolve, reject) => {
    const server = http.createServer(app).listen(port, '127.0.0.1', () => resolve({ server, url: `http://localhost:${port}` }));
    server.on('error', reject);
  });
}

module.exports = { startServer, buildApp };

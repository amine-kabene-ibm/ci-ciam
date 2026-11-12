'use strict';
// IFC registration portal (UC-01): the web page and the HTTP API in front of the registration service.
//   Page          GET /                       register wizard (signed out) or "my account" with progressive profiling (signed in)
//   Registration  POST /api/register/start    {email, policyNumber?, postalCode?}   -> duplicate check + verification e-mail
//                 POST /api/register/complete {txn, code, password}                  -> identity created with minimal data
//   Sign-in       GET /login -> IBM Verify hosted login (code + PKCE) -> GET /callback; GET /logout (local)
//   Profile       GET /api/me   POST /api/profile/:stage                             -> what is still missing / save it
//   Trace         GET /api/trace                                                     -> the last Verify API calls (method, path, status, ms)
//   Demo inbox    POST /api/demo/inbox, GET /api/demo/inbox/code?txn=                -> only when cfg.demoInbox is given (a disposable test inbox)
const express = require('express');
const crypto = require('crypto');
const { BASE, send } = require('../../demo/lib/verify');
const { verifyJwt, tenantJwks, ISSUER } = require('../rp-sso/server');
const { createRegistrationService } = require('./service');

const ENDPOINT = `${BASE}/v1.0/endpoint/default`;
const rand = (n) => crypto.randomBytes(n).toString('base64url');
const cookiesOf = (req) => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map((c) => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));

// cfg: {port, api, client360Url, groupId, clientId, clientSecret, rules?, demoInbox?: {create(), waitForOtp(inbox,{correlation})}}
function createPortal(cfg) {
  const origin = `http://localhost:${cfg.port}`;
  const trace = [];
  const tapped = async (method, p, opts) => {
    const r = await cfg.api(method, p, opts);
    trace.push({ at: new Date().toISOString(), method, path: p.replace(/\/[0-9A-Za-z]{8,}(?=\/|$)/g, '/{id}'), status: r.status, ms: r.ms });
    if (trace.length > 60) trace.shift();
    return r;
  };
  const service = createRegistrationService({ api: tapped, client360Url: cfg.client360Url, groupId: cfg.groupId, rules: cfg.rules });
  const sessions = new Map(); // sid -> {userId, claims}
  const txns = new Map();     // oauth state -> {nonce, verifier}
  const inboxes = new Map();  // registration txn -> inbox
  const getJwks = tenantJwks();
  const cookie = 'ifc_uc01_sid';

  const sess = (req) => { const id = cookiesOf(req)[cookie]; return id && sessions.has(id) ? { id, s: sessions.get(id) } : null; };
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());
  const reply = (res, r) => { const { status, ...rest } = r; res.status(status).set('Cache-Control', 'no-store').json(rest); };

  app.get('/', (req, res) => res.type('html').set('Cache-Control', 'no-store').send(PAGE.replace('__DEMO_INBOX__', cfg.demoInbox ? 'true' : 'false')));
  app.get('/health', (req, res) => res.json({ ok: true }));

  app.post('/api/register/start', async (req, res) => {
    try { reply(res, await service.start(req.body || {})); } catch (e) { reply(res, { status: 502, error: 'directory_unavailable', detail: e.message.slice(0, 120) }); }
  });
  app.post('/api/register/complete', async (req, res) => {
    try { reply(res, await service.complete(req.body || {})); } catch (e) { reply(res, { status: 502, error: 'directory_unavailable', detail: e.message.slice(0, 120) }); }
  });

  app.get('/login', (req, res) => {
    const state = rand(16); const nonce = rand(16); const verifier = rand(32);
    txns.set(state, { nonce, verifier });
    const q = new URLSearchParams({
      response_type: 'code', client_id: cfg.clientId, redirect_uri: `${origin}/callback`, scope: 'openid profile email', state, nonce,
      code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
    });
    if (req.query.login_hint) q.set('login_hint', String(req.query.login_hint));
    res.redirect(`${ENDPOINT}/authorize?${q}`);
  });

  app.get('/callback', async (req, res) => {
    const { code, state, error } = req.query;
    const txn = txns.get(state); txns.delete(state);
    if (error || !txn || !code) return res.status(400).type('html').send(`<h2>Sign-in did not complete</h2><p>${String(error || 'unknown request').replace(/[<>&"]/g, '')}</p><p><a href="/">Back</a></p>`);
    const t = await send({
      method: 'post', url: `${ENDPOINT}/token`, validateStatus: () => true, auth: { username: cfg.clientId, password: cfg.clientSecret },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      data: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: `${origin}/callback`, code_verifier: txn.verifier }).toString(),
    });
    if (t.status !== 200) return res.status(502).type('html').send(`<h2>Token exchange failed (HTTP ${t.status})</h2><p><a href="/">Back</a></p>`);
    let claims;
    try { claims = await verifyJwt(t.data.id_token, getJwks, { iss: ISSUER, aud: cfg.clientId }); if (claims.nonce !== txn.nonce) throw new Error('nonce mismatch'); } catch (e) {
      return res.status(400).type('html').send(`<h2>ID token rejected</h2><p>${String(e.message).replace(/[<>&"]/g, '')}</p>`);
    }
    const id = rand(24);
    sessions.set(id, { userId: claims.sub, claims });
    res.append('Set-Cookie', `${cookie}=${id}; Path=/; HttpOnly; SameSite=Lax`);
    res.redirect('/');
  });

  app.get('/logout', (req, res) => {
    const c = sess(req); if (c) sessions.delete(c.id);
    res.append('Set-Cookie', `${cookie}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
    res.redirect('/');
  });

  app.get('/api/me', async (req, res) => {
    const c = sess(req);
    if (!c) return res.status(401).json({ error: 'not_signed_in' });
    const p = await service.getProfile(c.s.userId);
    if (p.status !== 200) return reply(res, p);
    const k = c.s.claims;
    reply(res, { ...p, profile: { ...p.profile, mobile: p.profile.mobile ? `${p.profile.mobile.slice(0, 5)}***${p.profile.mobile.slice(-4)}` : null },
      idToken: { preferred_username: k.preferred_username, amr: k.amr, employee_id: k.employee_id || null, claims: Object.keys(k).sort() } });
  });
  app.post('/api/profile/:stage', async (req, res) => {
    const c = sess(req);
    if (!c) return res.status(401).json({ error: 'not_signed_in' });
    const r = await service.saveStage(c.s.userId, req.params.stage, req.body || {});
    if (r.profile) r.profile.mobile = r.profile.mobile ? `${r.profile.mobile.slice(0, 5)}***${r.profile.mobile.slice(-4)}` : null;
    reply(res, r);
  });
  app.get('/api/trace', (req, res) => res.json({ calls: trace.slice(-15) }));

  if (cfg.demoInbox) {
    app.post('/api/demo/inbox', async (req, res) => {
      try { const inbox = await cfg.demoInbox.create(); inboxes.set('pending', inbox); res.json({ address: inbox.address }); } catch (e) { res.status(502).json({ error: 'inbox_unavailable', detail: e.message.slice(0, 100) }); }
    });
    app.get('/api/demo/inbox/code', async (req, res) => {
      const t = service._txns.get(String(req.query.txn)); const inbox = inboxes.get('pending');
      if (!t || !inbox) return res.status(404).json({ error: 'no_inbox' });
      try { res.json({ code: await cfg.demoInbox.waitForOtp(inbox, { correlation: t.correlation, timeoutMs: 170000 }) }); } catch (e) { res.status(504).json({ error: 'no_mail_yet' }); }
    });
  }
  return { app, service, trace };
}

function listen(portal, port) {
  return new Promise((resolve, reject) => {
    const server = portal.app.listen(port, '127.0.0.1', () => resolve({ url: `http://localhost:${port}`, close: () => new Promise((r) => server.close(r)) }));
    server.on('error', reject);
  });
}

const PAGE = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>IFC: create your account</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box}body{font:15px/1.45 system-ui,sans-serif;margin:0;background:#f4f5f7;color:#161616}
header{background:#c60c30;color:#fff;padding:14px 24px;font-size:20px}header small{opacity:.85;font-size:12px;margin-left:10px}
main{display:grid;grid-template-columns:minmax(320px,520px) 1fr;gap:20px;padding:20px 24px;max-width:1100px}
.card{background:#fff;border-radius:6px;padding:18px 20px;box-shadow:0 1px 3px #0002}h2{margin:0 0 10px;font-size:18px}h3{margin:0 0 6px;font-size:14px;color:#525252}
label{display:block;margin:10px 0 3px;font-size:13px;color:#393939}input,select{width:100%;padding:8px;border:1px solid #8d8d8d;border-radius:3px;font:inherit}
button{margin-top:14px;padding:9px 16px;border:0;border-radius:3px;background:#c60c30;color:#fff;font:inherit;cursor:pointer}button.sec{background:#fff;color:#c60c30;border:1px solid #c60c30}
.msg{margin-top:12px;padding:8px 10px;border-radius:3px;background:#edf5ff;border-left:3px solid #0f62fe}.err{background:#fff1f1;border-color:#da1e28}.ok{background:#defbe6;border-color:#198038}
.bar{height:8px;background:#e0e0e0;border-radius:4px}.bar i{display:block;height:8px;background:#198038;border-radius:4px}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:4px 6px;border-bottom:1px solid #e0e0e0;text-align:left;vertical-align:top}.mono{font-family:ui-monospace,monospace;font-size:12px}
.hide{display:none}.row{display:flex;gap:10px}.row>*{flex:1}.muted{color:#6f6f6f;font-size:12px}a{color:#0f62fe}
</style></head><body>
<header>IFC <small>UC-01 self-service registration and progressive profiling (demo)</small></header>
<main><div>
<div id="wizard" class="card"><h2>Create your account</h2>
 <div id="s1"><label>E-mail address<input id="email" autocomplete="off" placeholder="you@example.com"></label>
  <label style="display:flex;gap:8px;align-items:center;margin-top:12px"><input type="checkbox" id="haspol" style="width:auto"> I am already an IFC customer (link my policy)</label>
  <div id="polbox" class="hide row"><label>Policy number<input id="policy" placeholder="AUTO-31877"></label><label>Postal code<input id="postal" placeholder="H2X 1Y4"></label></div>
  <div id="inboxbox" class="hide muted" style="margin-top:10px">No mailbox handy? <a href="#" id="mkinbox">use a disposable test inbox</a> (a real e-mail from IBM Verify is still sent and read for you).</div>
  <button id="go1">Continue</button></div>
 <div id="s2" class="hide"><p>We sent a code to <b id="sentto"></b>. It starts with <b id="corr" class="mono"></b>: type only the digits after the dash.</p>
  <label>Code<input id="code" autocomplete="off" inputmode="numeric"></label><label>Choose a password<input id="pw" type="password" autocomplete="new-password"></label>
  <button id="go2">Create my account</button> <button class="sec" id="back">Start over</button></div>
 <div id="s3" class="hide"><div class="msg ok" id="done"></div><p><a href="/login" id="signin"><button>Sign in</button></a></p><p class="muted">Next time you sign in, we ask only for what we still need.</p></div>
 <div id="msg" class="msg hide"></div>
 <p class="muted" style="margin-top:14px">Already registered? <a href="/login">Sign in</a></p></div>
<div id="account" class="card hide"><h2>My account</h2><div id="who"></div><div class="bar" style="margin:8px 0"><i id="barfill" style="width:0"></i></div><div class="muted" id="pct"></div>
 <div id="stage" class="hide"><h3 id="stagetitle"></h3><div id="stagefields"></div><button id="savestage">Save</button></div><div id="amsg" class="msg hide"></div>
 <p><a href="/logout">Sign out</a></p></div></div>
<div><div class="card" id="idcard"><h3>What the tenant knows (signed-in view)</h3><div class="muted" id="idempty">Sign in to see the ID-token claims.</div><table id="idtab" class="hide"></table></div>
<div class="card" style="margin-top:20px"><h3>Last IBM Verify API calls</h3><table id="trace"><tbody></tbody></table></div></div></main>
<script>
var DEMO_INBOX=__DEMO_INBOX__;var txn=null;
function $(i){return document.getElementById(i)}function show(i,v){$(i).classList.toggle('hide',!v)}
function say(id,t,k){var m=$(id);m.textContent=t;m.className='msg '+(k||'');m.classList.remove('hide')}
function post(u,b){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})}).then(function(r){return r.json().then(function(j){j._s=r.status;return j})})}
$('haspol').onchange=function(){show('polbox',this.checked)};if(DEMO_INBOX)show('inboxbox',true);
var WHY={duplicate:function(j){return 'You already have an account (matched on: '+(j.matchedOn||[]).join(', ')+'). Sign in, or recover your password.'},invalid_email:function(){return 'That e-mail address does not look right.'},invalid_policy_number:function(){return 'Policy numbers look like AUTO-31877.'},email_not_deliverable:function(){return 'We cannot deliver e-mail to that address.'},wrong_code:function(j){return 'That code is not correct. Attempts left: '+j.attemptsLeft},code_expired:function(){return 'That code expired. Start over.'},too_many_attempts:function(){return 'Too many wrong codes. Start over.'},weak_password:function(){return 'Choose a stronger password (8+ characters, mixed).'}};
function why(j){return (WHY[j.error]||function(){return 'Something went wrong ('+j.error+')'})(j)}
$('mkinbox').onclick=function(e){e.preventDefault();post('/api/demo/inbox').then(function(j){if(j.address)$('email').value=j.address;else say('msg','Test inbox unavailable','err')})};
$('go1').onclick=function(){show('msg',false);post('/api/register/start',{email:$('email').value,policyNumber:$('haspol').checked?$('policy').value:'',postalCode:$('postal').value}).then(function(j){
 if(j._s!==200){say('msg',why(j),'err');return}txn=j.txn;$('sentto').textContent=$('email').value;$('corr').textContent=j.correlation+'-';show('s1',false);show('s2',true);
 if(j.policyLinked)say('msg','Your policy is linked to this account.','ok');
 if(DEMO_INBOX&&$('inboxbox')&&!$('inboxbox').classList.contains('hide')){say('msg','Reading the code from the test inbox (can take a minute)...');fetch('/api/demo/inbox/code?txn='+txn).then(function(r){return r.json()}).then(function(c){if(c.code){$('code').value=c.code;say('msg','Code read from the test inbox.','ok')}})}
 tick()})};
$('go2').onclick=function(){post('/api/register/complete',{txn:txn,code:$('code').value,password:$('pw').value}).then(function(j){
 if(j._s!==201){say('msg',why(j),'err');return}show('s2',false);show('s3',true);show('msg',false);$('signin').href='/login?login_hint='+encodeURIComponent($('email').value);
 $('done').textContent='Account created in '+j.ms+' ms with just your e-mail and password.'+(j.client360Id?' Linked to customer record '+j.client360Id+'.':' (Client 360 was unavailable: link pending.)');tick()})};
$('back').onclick=function(){location.reload()};
function field(k,l,t,opts){var h='<label>'+l;if(t==='select'){h+='<select id="f_'+k+'">'+opts.map(function(o){return '<option value="'+o[0]+'">'+o[1]+'</option>'}).join('')+'</select>'}else h+='<input id="f_'+k+'">';return h+'</label>'}
var FIELDS={postalCode:function(){return field('postalCode','Postal code')},preferredLanguage:function(){return field('preferredLanguage','Preferred language','select',[['fr-CA','Français'],['en-CA','English']])},hasVehicle:function(){return field('hasVehicle','Do you own a vehicle?','select',[['yes','Yes'],['no','No']])},mobile:function(){return field('mobile','Mobile number (optional)')}};
var stageId=null;
function me(){fetch('/api/me').then(function(r){if(r.status===401)return null;return r.json()}).then(function(j){
 if(!j||!j.profile){show('wizard',true);show('account',false);return}show('wizard',false);show('account',true);var p=j.profile;
 $('who').innerHTML='<b></b><div class="muted"></div>';$('who').firstChild.textContent=p.email;$('who').lastChild.textContent='Customer record: '+(p.client360Id||'not linked yet')+(p.policyNumber?'  |  Policy: '+p.policyNumber:'');
 $('barfill').style.width=j.completeness+'%';$('pct').textContent='Profile '+j.completeness+'% complete';
 var st=j.nextStage;show('stage',!!st);if(st){stageId=st.id;$('stagetitle').textContent=st.title+' (one question, not a long form)';$('stagefields').innerHTML=st.required.concat(st.optional).map(function(k){return FIELDS[k]()}).join('')}
 else say('amsg','Nothing more to ask. Thank you.','ok');
 var t=$('idtab');t.innerHTML='<tr><th>Claim</th><th>Value</th></tr><tr><td>preferred_username</td><td>'+esc(j.idToken.preferred_username)+'</td></tr><tr><td>employee_id (= Client 360 id)</td><td class="mono">'+esc(j.idToken.employee_id||'(absent)')+'</td></tr><tr><td>amr</td><td>'+esc((j.idToken.amr||[]).join(', '))+'</td></tr><tr><td>all claims</td><td class="mono">'+esc(j.idToken.claims.join(', '))+'</td></tr>';show('idtab',true);show('idempty',false)})}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
$('savestage').onclick=function(){var v={};document.querySelectorAll('#stagefields input,#stagefields select').forEach(function(e){v[e.id.slice(2)]=e.value});
 post('/api/profile/'+stageId,v).then(function(j){if(j._s!==200){say('amsg',j.error==='validation'?'Please check: '+Object.keys(j.fields).join(', '):why(j),'err');return}say('amsg','Saved in '+j.patchMs+' ms.','ok');me();tick()})};
function tick(){fetch('/api/trace').then(function(r){return r.json()}).then(function(j){$('trace').querySelector('tbody').innerHTML=j.calls.slice().reverse().map(function(c){return '<tr><td class="mono">'+esc(c.method)+'</td><td class="mono">'+esc(c.path)+'</td><td>'+c.status+'</td><td>'+c.ms+' ms</td></tr>'}).join('')})}
me();tick();
</script></body></html>`;

module.exports = { createPortal, listen };

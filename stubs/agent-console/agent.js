'use strict';
// UC-14 agent-console logic (the "client application / consumption device" of IFC's main flow).
// Used by the web console (server.js) and by demo/uc14-ciba/run.js, so both behave the same.
//
// Verify does the hard parts: it sends the approval request to the caller, authenticates the caller, and issues the tokens.
// This module only: starts the request (POST /oauth2/ciba), polls for the result (POST /oauth2/token, CIBA grant), confirms WHO approved
// (userinfo of the issued access token, compared with the directory id of the caller), and gates agent actions on that.
// The "verified agent session" (and its time limit) is kept HERE, in memory: it is console logic, not a Verify feature [INFER].
const { BASE, send, createClient, oauthClient } = require('../../demo/lib/verify');

const IBM_EXT = 'urn:ietf:params:scim:schemas:extension:ibm:2.0:User';
const PATCH_OP = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const PENDING_RE = /CSIAQ0249E/;

// cfg: { cibaClientId, cibaClientSecret, agentClientId, agentClientSecret, cibaApp, agentLabel, bindingTail?, verifiedTtlSec?, tempPassword() , client360(userName) }
function createAgentConsole(cfg) {
  const ciba = oauthClient(cfg.cibaClientId, cfg.cibaClientSecret);
  const agent = createClient(cfg.agentClientId, cfg.agentClientSecret).api;
  const ttl = (cfg.verifiedTtlSec || 300) * 1000;
  const sessions = new Map(); // id -> session (access tokens are used once for userinfo, then dropped)
  let seq = 0;

  async function findCaller(userName) {
    const r = await agent('GET', '/v2.0/Users', {
      query: { filter: `userName eq "${String(userName).replace(/"/g, '')}"`, attributes: `id,userName,name,active,emails,${IBM_EXT}:pwdAccountLockedTime` }, quiet: true,
    });
    if (r.status !== 200) return { error: `directory lookup failed: HTTP ${r.status}`, status: r.status, cid: r.cid };
    const u = (r.data.Resources || [])[0];
    return u ? { user: u } : { user: null };
  }

  // Agent action 1: ask the caller to approve. Returns {session} or {error, httpStatus, oauthError}.
  // opts.ref: short code appended to the message so the caller (and the audit) can tell requests apart. opts.expirySec: request lifetime.
  async function startVerification(userName, agentLabel, opts = {}) {
    const label = agentLabel || cfg.agentLabel;
    const binding = `${label} is verifying your identity${opts.ref ? ` (ref ${opts.ref})` : ''}`;
    const t0 = Date.now();
    const r = await ciba.ciba({ scope: 'openid', login_hint: userName, binding_message: binding, requested_expiry: String(opts.expirySec || cfg.requestedExpirySec || 900) });
    if (r.status !== 200) {
      return { error: (r.data && (r.data.error_description || r.data.error)) || `HTTP ${r.status}`, httpStatus: r.status, oauthError: r.data && r.data.error, cid: r.cid };
    }
    const id = `S${++seq}`;
    const s = {
      id, userName, bindingMessage: binding, authReqId: r.data.auth_req_id, intervalSec: r.data.interval || 5, expiresInSec: r.data.expires_in,
      startedAt: Date.now(), status: 'pending', lastPollAt: 0, polls: 0, startMs: Date.now() - t0, verifiedAt: null, sub: null, verifiedUserId: null,
    };
    sessions.set(id, s);
    return { session: view(s) };
  }

  // Poll Verify (respecting the interval). 200 -> verify who approved -> 'verified'. authorization_pending -> 'pending'.
  async function poll(id) {
    const s = sessions.get(id);
    if (!s) return { error: 'unknown session', httpStatus: 404 };
    if (s.status !== 'pending') return { session: view(s) };
    if (Date.now() - s.lastPollAt < s.intervalSec * 1000) return { session: view(s) }; // never poll faster than the interval (slow_down)
    s.lastPollAt = Date.now();
    s.polls++;
    const r = await ciba.cibaToken(s.authReqId);
    s.lastOauthError = r.data && r.data.error;
    if (r.status === 200 && r.data.access_token) {
      // Who approved? Trust Verify's userinfo for the issued token, not the caller's say-so.
      const ui = await send({
        method: 'get', url: `${BASE}/oidc/endpoint/default/userinfo`, headers: { Authorization: `Bearer ${r.data.access_token}`, Accept: 'application/json' },
        validateStatus: () => true,
      });
      const found = await findCaller(s.userName);
      const sub = ui.status === 200 ? ui.data.sub : null;
      if (sub && found.user && sub === found.user.id) {
        s.status = 'verified'; s.verifiedAt = Date.now(); s.sub = sub; s.verifiedUserId = found.user.id;
        s.amr = ui.data.amr; s.acr = r.data.acr;
      } else {
        s.status = 'denied'; s.reason = 'token subject does not match the caller on the call';
      }
    } else if (r.status === 400 && r.data && r.data.error === 'authorization_pending') {
      // still waiting
    } else if (r.status === 400 && r.data && r.data.error === 'slow_down') {
      s.intervalSec += 5;
    } else if (r.status === 400 && r.data && r.data.error === 'expired_token') {
      s.status = 'expired';
    } else if (r.data && r.data.error === 'access_denied') {
      s.status = 'denied'; s.reason = r.data.error_description;
    } else {
      s.status = 'error'; s.reason = `${r.status} ${r.data && r.data.error}`;
    }
    return { session: view(s) };
  }

  function view(s) {
    return {
      id: s.id, userName: s.userName, status: s.status, bindingMessage: s.bindingMessage, intervalSec: s.intervalSec, expiresInSec: s.expiresInSec,
      polls: s.polls, startedAt: s.startedAt, verifiedAt: s.verifiedAt, reason: s.reason || null, startMs: s.startMs,
      verifiedLeftSec: s.status === 'verified' ? Math.max(0, Math.round((s.verifiedAt + ttl - Date.now()) / 1000)) : null,
    };
  }

  // Every agent action that touches the caller must pass through here.
  function requireVerified(id) {
    const s = sessions.get(id);
    if (!s) return { error: 'unknown session', httpStatus: 404 };
    if (s.status !== 'verified') return { error: `caller is not verified (session is ${s.status})`, httpStatus: 403 };
    if (Date.now() > s.verifiedAt + ttl) { s.status = 'expired'; return { error: 'verification window has ended: verify the caller again', httpStatus: 403 }; }
    return { s };
  }

  // Agent action 2: read the caller's personal information (profile from the directory + the Client 360 stub).
  async function profile(id) {
    const g = requireVerified(id); if (g.error) return g;
    const f = await findCaller(g.s.userName);
    if (!f.user) return { error: 'caller not found', httpStatus: 404 };
    const u = f.user;
    return { profile: {
      userName: u.userName, name: u.name && u.name.formatted, email: u.emails && u.emails[0] && u.emails[0].value, active: u.active,
      locked: !!(u[IBM_EXT] && u[IBM_EXT].pwdAccountLockedTime), client360: cfg.client360 ? cfg.client360(u.userName) : null,
    } };
  }

  // Agent action 3: unlock the caller's account = set a temporary password; the caller must choose a new one at next sign-in.
  // [LIVE 2026-11-12] a SCIM password replace is the ONLY thing that cleared the lock; no unlock endpoint exists (404), PATCH of the lock attribute does not clear it.
  async function unlock(id) {
    const g = requireVerified(id); if (g.error) return g;
    const before = await findCaller(g.s.userName);
    const wasLocked = !!(before.user && before.user[IBM_EXT] && before.user[IBM_EXT].pwdAccountLockedTime);
    const r = await agent('PATCH', `/v2.0/Users/${g.s.verifiedUserId}`, {
      body: { schemas: [PATCH_OP], Operations: [{ op: 'replace', path: 'password', value: cfg.tempPassword() }] }, quiet: true,
    });
    if (r.status !== 204) return { error: `unlock failed: HTTP ${r.status}`, httpStatus: 502, cid: r.cid };
    const after = await findCaller(g.s.userName);
    const nowLocked = !!(after.user && after.user[IBM_EXT] && after.user[IBM_EXT].pwdAccountLockedTime);
    return { unlock: { wasLocked, nowLocked, httpStatus: r.status, cid: r.cid, mustChangePassword: true } };
  }

  // Audit trail from Verify's events API (needs readReports). Collapses the "still pending" poll noise into a count.
  async function audit({ sinceMs, userName } = {}) {
    const from = sinceMs || Date.now() - 30 * 60 * 1000;
    const r = await agent('GET', '/v1.0/events', { query: { range_type: 'time', from, to: Date.now(), size: 200, sort_order: 'desc' }, quiet: true });
    if (r.status !== 200) return { error: `events API: HTTP ${r.status}`, httpStatus: r.status, cid: r.cid };
    const evs = (((r.data || {}).response || {}).events || {}).events || [];
    const rows = []; let pending = 0;
    for (const e of evs) {
      const d = e.data || {};
      const isCiba = (d.grant_type || '').includes('ciba') && (d.applicationname === cfg.cibaApp || d.client_name === cfg.cibaApp);
      const isCaller = userName && d.username && d.username.toLowerCase() === userName.toLowerCase() && e.event_type === 'authentication';
      if (!isCiba && !isCaller) continue;
      if (isCiba && d.result === 'failure' && PENDING_RE.test(d.cause || '')) { pending++; continue; }
      rows.push({
        time: new Date(Number(e.time)).toISOString(), type: e.event_type, result: d.result, kind: isCiba ? 'CIBA token' : 'caller sign-in',
        cause: d.cause || null, bindingMessage: d.binding_message || null, user: d.username || d.userid || null,
        client: d.client_name || null, grant: d.grant_type || d.subtype || null, scope: d.scope || null,
      });
    }
    return { audit: { rows, pendingPolls: pending, total: evs.length } };
  }

  return { findCaller, startVerification, poll, profile, unlock, audit, session: (id) => (sessions.get(id) ? view(sessions.get(id)) : null) };
}

module.exports = { createAgentConsole, IBM_EXT };

'use strict';
// UC-06 setup. Idempotent: safe to run any number of times, and it never removes a phone the human already enrolled.
//   node demo/uc06-voice/setup.js
// Creates on the tenant:
//   - API client  ifc-demo-uc06-ccaas   (5 entitlements, used by the voicebot stub instead of the admin client)
//   - user        ifc-demo-uc06-marie   (the policyholder; e-mail = presenter mailbox so the e-mail OTP is readable)
//   - TOTP enrolment for Marie           (plays "the authenticator app"; secret kept in demo/out/uc06.state.json, gitignored)
const { api } = require('../lib/verify');
const idem = require('../lib/idempotent');
const { CCAAS_CLIENT, CCAAS_ENTITLEMENTS, state, customer, resolveMailbox } = require('./common');

const mask = (e) => e.replace(/^(.).*(@.*)$/, '$1***$2');

async function main() {
  const out = {};

  const c = await idem.ensureApiClient(CCAAS_CLIENT, CCAAS_ENTITLEMENTS);
  console.log(`API client   ${CCAAS_CLIENT}  ${c.created ? 'created' : 'exists'}  (${c.entitlements.length} entitlements)`);
  out.ccaas = { clientId: c.clientId, clientSecret: c.clientSecret, entitlements: c.entitlements };

  const mailbox = await resolveMailbox();
  const { user, created } = await idem.ensureUser({
    userName: customer.userName, email: mailbox, given: customer.given, family: customer.family,
  });
  console.log(`User         ${customer.userName}  ${created ? 'created' : 'exists'}  id=${user.id}  mailbox=${mask(mailbox)}`);
  out.user = { id: user.id, userName: customer.userName };

  // TOTP: a user can have ONE enrolment. Keep it if we still hold its secret, otherwise recreate it.
  const prev = state.read();
  const l = await api('GET', '/v2.0/factors/totp', { query: { search: `userId="${user.id}"` } });
  const existing = (l.data && l.data.totp) || [];
  let secret = prev && prev.totp && prev.user && prev.user.id === user.id && existing.some((t) => t.id === prev.totp.id) ? prev.totp.secret : null;
  let totpId = secret ? prev.totp.id : null;
  if (!secret) {
    for (const t of existing) await api('DELETE', `/v2.0/factors/totp/${t.id}`);
    const e = await api('POST', '/v2.0/factors/totp', { body: { userId: user.id, accountName: `Intact (${customer.policyNumber})`, enabled: true } });
    if (e.status !== 201) throw new Error(`TOTP enrol failed: HTTP ${e.status} cid=${e.cid}`);
    secret = e.data.attributes.secret; totpId = e.data.id;
    console.log(`TOTP         enrolled  id=${totpId}`);
  } else {
    console.log(`TOTP         exists    id=${totpId}`);
  }
  out.totp = { id: totpId, secret };
  out.customer = { userName: customer.userName, policyNumber: customer.policyNumber };

  // Registered phone (push) is a human step; report what exists.
  const a = await api('GET', '/v1.0/authenticators', { query: { search: `owner="${user.id}"` } });
  const regs = (a.data && a.data.authenticators) || [];
  console.log(`IBM Verify app registrations for Marie: ${regs.length}${regs.length ? '' : '   -> run: node demo/uc06-voice/enroll-phone.js  [HUMAN]'}`);

  state.write(out);
  console.log(`\nState saved (secrets stay local): ${state.file}`);
}

main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });

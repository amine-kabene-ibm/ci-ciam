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
  const t = await idem.ensureTotp(user.id, `Intact (${customer.policyNumber})`, prev && prev.user && prev.user.id === user.id ? prev.totp : null);
  console.log(`TOTP         ${t.created ? 'enrolled' : 'exists  '}  id=${t.id}`);
  out.totp = { id: t.id, secret: t.secret };
  out.customer = { userName: customer.userName, policyNumber: customer.policyNumber };

  // Registered phone (push) is a human step; report what exists.
  const a = await api('GET', '/v1.0/authenticators', { query: { search: `owner="${user.id}"` } });
  const regs = (a.data && a.data.authenticators) || [];
  console.log(`IBM Verify app registrations for Marie: ${regs.length}${regs.length ? '' : '   -> run: node demo/uc06-voice/enroll-phone.js  [HUMAN]'}`);

  state.write(out);
  console.log(`\nState saved (secrets stay local): ${state.file}`);
}

main().catch((e) => { console.error('SETUP FAILED:', e.message); process.exit(1); });

'use strict';
// STUBS of IFC back-end systems that the CCaaS calls AFTER the caller is authenticated:
//   Billing API, Client 360 API (system of record for the profile), Policy-change API.
// Verify is not involved here: this is the "CCaaS acknowledges authentication, invokes APIs" part of UC-06.
// Single source of truth for the demo customers: demo/uc06-voice/setup.js creates matching users in Verify.

const customers = [
  {
    userName: 'ifc-demo-uc06-marie',
    given: 'Marie',
    family: 'Tremblay',
    policyNumber: 'AUTO-48213',
    vehicle: '2021 Honda Civic',
    billing: { outstanding: 184.37, currency: 'CAD', dueDate: '2026-11-28' },
    renewalDate: '2027-03-14',
  },
  { // UC-07: the customer who signs in to the app and is handed over to the voicebot
    userName: 'ifc-demo-uc07-marie',
    given: 'Marie',
    family: 'Tremblay',
    policyNumber: 'AUTO-77120',
    vehicle: '2023 Toyota RAV4',
    billing: { outstanding: 92.15, currency: 'CAD', dueDate: '2026-12-05' },
    renewalDate: '2027-05-02',
  },
];

// Action catalogue = the risk tiers. tier 1: one verified factor. tier 2: tier 1 + a step-up factor.
const ACTIONS = {
  outstanding_bill: { kind: 'information query', tier: 1 },
  renewal_date: { kind: 'information query', tier: 1 },
  proof_of_insurance: { kind: 'document request', tier: 1 },
  storage: { kind: 'simple transaction', tier: 1 },
  change_email: { kind: 'sensitive transaction', tier: 2 },
  change_bank_account: { kind: 'sensitive transaction', tier: 2 },
};

const normalise = (s) => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const clone = (o) => JSON.parse(JSON.stringify(o));
const mask = (email) => {
  const [l, d] = String(email).split('@');
  return `${l[0]}${'*'.repeat(Math.max(l.length - 1, 2))}@${d}`;
};

let live = clone(customers); // mutable copy so reset() restores the demo data

const reset = () => { live = clone(customers); };
const findByPolicy = (raw) => live.find((c) => normalise(c.policyNumber) === normalise(raw)) || null;
const findByUserName = (u) => live.find((c) => c.userName === u) || null;

// "Billing API"
const billing = (c) => ({ api: 'Billing API', ...c.billing });
// "Client 360 API": proof of insurance is e-mailed to the address on file (never to an address the caller states)
const proofOfInsurance = (c, emailOnFile) => ({
  api: 'Client 360 API', documentId: `POI-${normalise(c.policyNumber)}-2026`, deliveredTo: mask(emailOnFile),
});
const changeEmail = (c, newEmail) => {
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(newEmail || '')) return { error: 'invalid_email' };
  c.profileEmail = newEmail;
  return { api: 'Client 360 API', updated: 'email', newEmail: mask(newEmail) };
};
const changeBankAccount = (c) => ({ api: 'Client 360 API', updated: 'bank_account', note: 'pre-authorized debit mandate re-issued (mock)' });
// "Policy-change API"
const storage = (c) => ({ api: 'Policy-change API', policyNumber: c.policyNumber, vehicle: c.vehicle, status: 'storage-coverage-requested', effective: 'next business day' });

module.exports = {
  customers, ACTIONS, mask, reset, findByPolicy, findByUserName, billing, proofOfInsurance, changeEmail, changeBankAccount, storage,
  renewal: (c) => ({ api: 'Policy-change API', renewalDate: c.renewalDate }),
};

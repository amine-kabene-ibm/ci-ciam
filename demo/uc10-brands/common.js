'use strict';
// Names and constants shared by all UC-10 scripts. Everything on the tenant starts with "ifc-demo-uc10-".
// The two brands are FICTIONAL stand-ins for IFC brands: Aurora Insurance (English first) and Boréal Assurance (French first).
const crypto = require('crypto');
const { PREFIX, BASE, stateFile } = require('../lib/verify');

const UC = 'uc10';
const state = stateFile(UC);
const randomSecret = (n) => crypto.randomBytes(n).toString('base64url');
// Meets the tenant password policy (upper, lower, digit, symbol) without a fixed literal.
const newUserCredential = () => ['Ifc', randomSecret(9), '8b'].join('-') + '!';

// Brand portals run on their own host names (*.localhost resolves to loopback; DCR accepts such redirect URIs [LIVE]).
// Each brand = its own application (one client id), its own access policy, its own default language, its own admin.
const BRANDS = {
  aurora: {
    key: 'aurora', name: 'Aurora Insurance', appName: `${PREFIX}uc10-aurora`, themeName: `${PREFIX}uc10-aurora`,
    host: 'aurora.localhost', port: 4101, colour: '#007d79', dark: '#005d5d', defaultLocale: 'en', policy: 'aurora', adminUser: 'auroraAdmin',
    text: {
      en: { tagline: 'Home and auto insurance, made simple.', signIn: 'Sign in', signOut: 'Sign out', legal: 'Aurora Insurance is a trade name of the IFC group of companies. Quotes are not binding.', support: 'Customer support', consent: 'I agree to Aurora Insurance receiving my quote data.' },
      fr: { tagline: "L'assurance habitation et auto, tout simplement.", signIn: 'Se connecter', signOut: 'Se déconnecter', legal: "Aurora Assurance est une marque de commerce du groupe IFC. Les soumissions ne sont pas contractuelles.", support: 'Soutien à la clientèle', consent: "J'accepte qu'Aurora Assurance reçoive mes données de soumission." },
    },
    supportUrl: 'https://aurora.example/support',
  },
  boreal: {
    key: 'boreal', name: 'Boréal Assurance', appName: `${PREFIX}uc10-boreal`, themeName: `${PREFIX}uc10-boreal`,
    host: 'boreal.localhost', port: 4102, colour: '#9f1853', dark: '#740937', defaultLocale: 'fr', policy: 'boreal', adminUser: 'borealAdmin',
    text: {
      fr: { tagline: "Votre assureur d'ici, proche de vous.", signIn: 'Se connecter', signOut: 'Se déconnecter', legal: "Boréal Assurance est une marque de commerce du groupe IFC. Les soumissions ne sont pas contractuelles.", support: 'Nous joindre', consent: "J'accepte que Boréal Assurance reçoive mes données de soumission." },
      en: { tagline: 'Your local insurer, close to you.', signIn: 'Sign in', signOut: 'Sign out', legal: 'Boréal Assurance is a trade name of the IFC group of companies. Quotes are not binding.', support: 'Contact us', consent: 'I agree to Boréal Assurance receiving my quote data.' },
    },
    supportUrl: 'https://boreal.example/contact',
  },
};
const BRAND_LIST = Object.values(BRANDS);
const origin = (b) => `http://${b.host}:${b.port}`;

// One customer account that is entitled to both brands; a customer of Aurora only (shows per-brand customer scoping);
// one brand administrator per brand (application owner of that brand's application only).
const USERS = {
  customer: { userName: `${PREFIX}uc10-customer`, given: 'Camille', family: 'Tremblay', email: 'uc10.customer@ifc-demo.invalid', totp: true },
  auroraOnly: { userName: `${PREFIX}uc10-aurora-only`, given: 'Victor', family: 'Gagnon', email: 'uc10.aurora.only@ifc-demo.invalid', totp: false },
  auroraAdmin: { userName: `${PREFIX}uc10-aurora-admin`, given: 'Alice', family: 'Aurora-Admin', email: 'uc10.aurora.admin@ifc-demo.invalid', totp: false },
  borealAdmin: { userName: `${PREFIX}uc10-boreal-admin`, given: 'Benoit', family: 'Boreal-Admin', email: 'uc10.boreal.admin@ifc-demo.invalid', totp: false },
};

// Brand policies [LIVE]: Aurora = password only. Boréal = passkey first with an authenticator-app fallback. A user with no passkey
// gets the TOTP page (with the "use another method" link); the passkey itself needs a browser authenticator [HUMAN].
const POLICIES = {
  aurora: { name: `${PREFIX}uc10-policy-aurora`, action: 'ACTION_ALLOW', authnMethods: ['totp'], description: 'UC-10 Aurora: password only' },
  boreal: { name: `${PREFIX}uc10-policy-boreal`, action: 'ACTION_MFA_ALWAYS', authnMethods: ['fido2', 'totp'], description: 'UC-10 Boreal: passkey first, authenticator-app (TOTP) fallback, at every sign-in' },
};
const policyRules = (p) => [{ name: 'all customers', action: p.action, authnMethods: p.authnMethods, conditions: [] }];

// Password-grant client: used ONLY to obtain the brand administrators' own tokens (their delegated-admin calls).
const CONSOLE_APP = `${PREFIX}uc10-admin-console`;

module.exports = {
  UC, BASE, PREFIX, state, randomSecret, newUserCredential, BRANDS, BRAND_LIST, origin, USERS, POLICIES, policyRules, CONSOLE_APP,
};

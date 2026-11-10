'use strict';
// Names and constants shared by all UC-09 scripts. Everything on the tenant starts with "ifc-demo-uc09-".
const crypto = require('crypto');
const { PREFIX, BASE, stateFile } = require('../lib/verify');

const UC = 'uc09';
const state = stateFile(UC);

// The protected IFC API (stubs/ifc-api) and the scope it enforces.
const API_PORT = 4040;
const API_BASE = `http://127.0.0.1:${API_PORT}`;
const SCOPE_READ = 'ifc.policy.read';
const SCOPE_WRITE = 'ifc.policy.write'; // registered on NO client: a request for it must be refused

// Machine clients. Names are the tenant objects (DCR applications, clientName = name).
const CLIENTS = {
  pkjwt: { name: `${PREFIX}uc09-m2m-pkjwt`, label: 'partner machine client, private_key_jwt', dpop: false },
  dpop: { name: `${PREFIX}uc09-m2m-dpop`, label: 'partner machine client, private_key_jwt + DPoP-bound tokens', dpop: true },
  // Registered with the authorization server but NOT a partner of IFC's API: the API allow-list must refuse its token.
  rogue: { name: `${PREFIX}uc09-m2m-rogue`, label: 'unlisted machine client (not an IFC API partner): must be refused by the API', dpop: false },
};
const PARTNER_STS = `${PREFIX}uc09-partner`; // STS client for the on-behalf-of exchange (secret based: the tenant rejects private_key_jwt here)
const POLICYHOLDER = { userName: `${PREFIX}uc09-policyholder`, given: 'Paula', family: 'Policyholder', email: 'uc09.policyholder@ifc-demo.invalid' };
const POLICYHOLDER_APP = `${PREFIX}uc09-policyholder-app`; // password-grant DCR client, used only to obtain the subject token for the exchange

const randomSecret = (n) => crypto.randomBytes(n).toString('base64url');
// Meets the tenant password policy (upper, lower, digit, symbol) without a fixed literal.
const newUserCredential = () => ['Ifc', randomSecret(9), '8b'].join('-') + '!';

// Key id: first 16 chars of SHA-256 over the DER public key. Stable for a given key.
const kidOf = (publicKey) => crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url').slice(0, 16);
const publicJwk = (publicKey, kid) => ({ ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' });

module.exports = {
  UC, BASE, PREFIX, state, API_PORT, API_BASE, SCOPE_READ, SCOPE_WRITE, CLIENTS, PARTNER_STS, POLICYHOLDER, POLICYHOLDER_APP,
  randomSecret, newUserCredential, kidOf, publicJwk,
};

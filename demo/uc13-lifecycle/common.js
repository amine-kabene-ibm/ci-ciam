'use strict';
// UC-13 shared constants and helpers (Broker Identity Lifecycle & Immediate Revocation).
const crypto = require('crypto');
const path = require('path');
const { stateFile } = require('../lib/verify');

const PREFIX = 'ifc-demo-uc13-';
const BROKER_APP = `${PREFIX}broker-portal`;
const STS_CLIENT = `${PREFIX}resource-sts`;
const WEBHOOK_NAME = `${PREFIX}ops-webhook`;
const OPS_QUEUE_PORT = 4040;

const SCIM_CORE = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const SCIM_PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

const BROKERS = {
  elena: {
    userName: `${PREFIX}broker-elena`,
    email: 'elena.vance@brokerage.example.com',
    given: 'Elena',
    family: 'Vance',
    title: 'Commercial Lines Broker',
    department: 'Commercial Lines',
    externalId: 'IFC-BRK-9821',
    employeeNumber: 'BRK-9821',
  },
  marcus: {
    userName: `${PREFIX}broker-marcus`,
    email: 'marcus.brody@agency.example.com',
    given: 'Marcus',
    family: 'Brody',
    title: 'Personal Lines Broker',
    department: 'Personal Lines',
    externalId: 'IFC-BRK-5104',
    employeeNumber: 'BRK-5104',
  },
};

const state = stateFile('uc13');

function newUserCredential() {
  return `IfcDemo!${crypto.randomBytes(6).toString('hex')}A1#`;
}

function randomSecret(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

module.exports = {
  PREFIX,
  BROKER_APP,
  STS_CLIENT,
  WEBHOOK_NAME,
  OPS_QUEUE_PORT,
  SCIM_CORE,
  SCIM_ENTERPRISE,
  SCIM_PATCH,
  BROKERS,
  state,
  newUserCredential,
  randomSecret,
};

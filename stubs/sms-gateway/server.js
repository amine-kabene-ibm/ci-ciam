'use strict';
// STUB "IFC SMS gateway" for UC-02. IBM Verify, with an SMS provider whose webhook purpose is external_sms, POSTs every SMS OTP here instead of sending it
// through IBM's SMS service [LIVE]. A real IFC gateway would hand the message to its carrier; this stub only keeps it in memory so a script can read the code.
//   POST /sms        body {destinationPhoneNumber, content, category:"OTP", language, otp, correlation, expiry}; answers 200
//   GET  /messages   what arrived, with the one-time code and phone number MASKED (the stub never prints codes)
// Verify needs a PUBLIC https URL for the webhook: tunnel to this port (ssh -R 80:localhost:<port> nokey@localhost.run, or cloudflared).
const express = require('express');

function createSmsGateway({ port = 4031, log = () => {} } = {}) {
  const inbox = [];
  const app = express();
  app.disable('x-powered-by');
  app.post('/sms', express.json(), (req, res) => {
    const b = req.body || {};
    inbox.push({ at: Date.now(), to: String(b.destinationPhoneNumber || ''), category: b.category, correlation: b.correlation, expiry: b.expiry, otp: String(b.otp || ''), content: String(b.content || '') });
    log(`[sms-gateway] message for ${String(b.destinationPhoneNumber || '').replace(/\d(?=\d{4})/g, '*')} category=${b.category}`);
    res.status(200).json({ status: 'accepted' });
  });
  app.get('/messages', (req, res) => res.json({ messages: inbox.map((m) => ({ at: m.at, to: m.to.replace(/\d(?=\d{4})/g, '*'), category: m.category, expiry: m.expiry, hasOtp: !!m.otp })) }));
  const listen = () => new Promise((resolve, reject) => { const srv = app.listen(port, () => resolve(srv)); srv.on('error', reject); });
  return { app, inbox, port, listen };
}

module.exports = { createSmsGateway };

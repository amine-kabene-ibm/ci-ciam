'use strict';
// UC-07 (IFC RFP): "Speak with a Voicebot" under the Help menu of the signed-in customer app.
// The web demo app plays the mobile app. When the customer taps the button, the app hands the access token it received from
// Verify at login to the contact-centre (CCaaS) voicebot. The voicebot validates it with Verify, so the caller is not asked to re-authenticate.
// The voicebot is the stub in stubs/voicebot-ccaas (start it with: node demo/uc07-handoff/serve.js).
const express = require('express');
const axios = require('axios');

const router = express.Router();
const voicebotUrl = () => (process.env.UC07_VOICEBOT_URL || 'http://127.0.0.1:4030').replace(/\/+$/, '');

router.get('/', (req, res) => {
  res.render('insurance/call-us', { loggedIn: true, voicebotUrl: voicebotUrl() });
});

router.post('/handoff', async (req, res) => {
  const out = { loggedIn: true, voicebotUrl: voicebotUrl(), attempted: true };
  try {
    // The token never leaves server-side session storage and is not rendered, logged or returned.
    const h = await axios.post(`${voicebotUrl()}/handoff`, { accessToken: req.session.accessToken }, { validateStatus: () => true, timeout: 20000 });
    out.result = { httpStatus: h.status, ...h.data };
    if (h.data && h.data.callId) {
      const a = await axios.get(`${voicebotUrl()}/agent/${h.data.callId}`, { validateStatus: () => true, timeout: 20000 });
      out.agent = a.data;
    }
  } catch (e) {
    out.unreachable = true;
  }
  if (req.accepts(['html', 'json']) === 'json') return res.status(out.unreachable ? 503 : 200).json(out);
  res.render('insurance/call-us', out);
});

module.exports = router;

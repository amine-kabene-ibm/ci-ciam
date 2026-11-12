# UC-02: Passkeys, OTP and authenticator-app fallback

IFC's requirement (`IAM Modernization Use Cases.pdf`, UC-02): the user enters an identifier and the service decides which authenticators exist; a passkey is offered
first where one is registered; OTP / authenticator app is the fallback when no passkey is available; a session token is issued; the user can add passkeys or a new
device from account settings. Capabilities asked: UX nudging to enroll passkeys, OTP delivery (vendor SMS/e-mail **or IFC's own gateways**), governance autonomy.
Demo asked: (1) register and authenticate with a platform passkey, (2) required AAL mapped to application or transaction type, (3) fallback for customers without a passkey-capable device.

Evidence tags: `[LIVE]` executed on the tenant, `[DOCS]` from documentation, `[INFER]` reasoning, `[HUMAN]` a person or IBM must do it.

## What is here

| File | What it does |
|---|---|
| `common.js` | Names, the three assurance levels, users, helpers that drive the Verify-hosted second-factor pages |
| `setup.js` | Idempotent. 2 customers (alice: passkey customer; bob: no passkey, real mail.tm mailbox), both with a validated authenticator app. 3 policies, 3 apps, a password-grant console client. `--sms-url <https url>/sms` also registers IFC's SMS gateway |
| `run.js` | 46 checks, scenarios A-I, against the real tenant. Writes `demo/out/uc02.json` |
| `serve.js` | Runs the 3 AAL portals for a browser: `:4021` AAL1, `:4022` AAL2, `:4023` AAL3 |
| `verify.js` | PASS / FAIL / HUMAN report (runs `run.js`) |
| `teardown.js` | Removes everything UC-02 created. Never touches the tenant's default FIDO2 relying party |
| `../lib/webauthn.js` | Software WebAuthn authenticator (ES256, "none" attestation, resident keys) so a script can play the customer's device |
| `../../stubs/passkey-portal/` | OIDC relying party per AAL + `/settings` (passkey list + nudge), `/api/nudge`, `/api/methods?username=` (identifier-first) |
| `../../stubs/sms-gateway/` | IFC's "own SMS gateway": receives Verify's SMS webhook. `tunnel.js` opens a free public tunnel with plain `ssh` |

Helpers added to `demo/lib/idempotent.js`: `defaultFidoRp`, `listFidoRegistrations`, `deleteFidoRegistrations`, `listSmsProviders`, `ensureSmsGateway`, `deleteSmsGatewaysByPrefix`.
`demo/teardown-all.js` now also sweeps SMS providers (before their webhooks).

Tenant objects (all `ifc-demo-uc02-*`): users `-alice`, `-bob`; policies `-policy-aal1-password`, `-policy-aal2-otp`, `-policy-aal3-passkey`; applications `-app-aal1`, `-app-aal2`, `-app-aal3`, `-app-console`;
(only during the SMS scenario) webhook + SMS provider `-sms-gateway`. Passkey registrations live under the users and go with them.

## Commands

```bash
node demo/uc02-passkeys/setup.js      # idempotent
node demo/uc02-passkeys/run.js        # scenarios A-I, 46 checks, evidence in demo/out/uc02.json (60-90 s, no human)
node demo/uc02-passkeys/verify.js     # PASS / FAIL / HUMAN
node demo/uc02-passkeys/serve.js      # 3 portals for the browser demo
node demo/uc02-passkeys/teardown.js   # remove everything
```

## What is proven [LIVE]

- **Passkey registration and sign-in against the real tenant.** Verify's FIDO2 APIs issue options, accept the device's attestation (`validated:true`), list it (`GET /v2.0/factors/fido2/registrations`),
  and accept the assertion on the hosted login page. The ID token's `amr` is `password, fido2, 2fa`. The signature counter moves.
- **Attacks are refused.** Forged signature, replayed (already used) challenge, never-issued challenge, wrong web origin (a look-alike site) at sign-in; wrong origin and a replayed result at registration.
- **Required AAL is a policy.** AAL1 `ACTION_ALLOW`; AAL2 `ACTION_MFA_ALWAYS` with `fido2 + totp + emailotp`; AAL3 `ACTION_MFA_ALWAYS` with `fido2` only. Same customer, three journeys.
  A customer without a passkey is refused at AAL3 (`CSIAH0640E`), offered authenticator app / e-mail code at AAL2.
- **Fallback.** With several methods Verify shows a choice page listing only the methods the customer has. "Use another method" returns to it. Wrong authenticator code refused; right code signs in (`amr` has `totp`, not `fido2`).
  The e-mail code is the real Verify e-mail (arrives in 2-5 s; the page shows `NNNN`, the mail reads `NNNN-NNNNNN`, the person types the six digits).
- **Add a device / remove a device** (account settings, API level): a second passkey registers, both list with nicknames, one deletes (204). A second options call already excludes credentials the customer holds.
- **Service-side logic.** Identifier first (`/api/methods`), neutral answer for unknown identifiers, nudge (`/api/nudge`, `/settings`) that disappears after enrolment. This is IFC portal logic over Verify's APIs, not a Verify screen.
- **Bring your own SMS gateway.** Webhook (`external_sms`) + SMS provider created and enabled through the API; Verify then POSTs the SMS OTP to IFC's URL (number, text, `category: OTP`, `expiry: 300`, the code itself, correlation); the code verifies at Verify; removing the provider restores the trial's refusal (429).
  Needs a public https URL: `run.js` opens one with `ssh nokey@localhost.run`; if that fails the check is reported SKIP, never PASS.

## What is NOT proven

- `[HUMAN]` A real platform passkey (Touch ID / Windows Hello / phone). The script's authenticator is software; the same API and hosted pages are used, but no OS prompt appears.
- `[HUMAN]` Registering a passkey through IBM's own self-care page `https://trialverify.verify.ibm.com/usc/` (it loads, HTTP 200; its bundle calls the same attestation API). Not driven.
- `[INFER]` Passkey-**only** sign-in (no password typed first). The tenant refuses it: `CSIAH0026E "You are not authorized to use passkey for passwordless login"`, and the login page's `passwordless` flags are `false`. About 33 configuration keys were tried without luck; IBM must enable it. Until then passkey is a **second factor** after the password.
- `[HUMAN]` An SMS arriving on a handset (a carrier behind IFC's gateway), voice OTP (`CSIAP3546E`), IBM's own SMS (`CSIAP3545E`).
- `[LIVE]` **Passkey first** is only true where the policy allows nothing else (AAL3: straight to the passkey page). Where several methods are allowed (AAL2) Verify's choice page lists them in its own order (seen: authenticator app, e-mail, passkey). The portal can steer (send a customer with a passkey to the AAL3 application), the choice page itself cannot be re-ordered through the API.
- `[INFER]` "Required AAL per transaction type": Verify applies a policy per **application**. A per-transaction level (e.g. payment over a threshold) is the portal calling Verify with `acr_values` / `max_age` or sending the customer to the AAL3 application. Not built.

## Human steps (about 15 minutes)

1. **Platform passkey in a real browser (Chrome or Safari, a Mac with Touch ID).**
   ```bash
   node demo/uc02-passkeys/setup.js && node demo/uc02-passkeys/serve.js
   ```
   Passwords and TOTP secrets are in `demo/out/uc02.state.json` (`users.alice.password`, `users.alice.totp.secret`).
   a. Open `https://trialverify.verify.ibm.com/usc/`, sign in as `ifc-demo-uc02-alice`, add a passkey (Touch ID). If the screen asks for a second factor, use the authenticator code (`demo/lib/totp.js`, or scan nothing: the secret is in the state file).
   b. Open `http://localhost:4023`, Sign in, password, then approve the passkey prompt. The page shows `amr: password, fido2, 2fa`.
   c. Open `http://localhost:4022`, sign in, choose "Use another method", pick the authenticator app or e-mail code (bob's mailbox is a mail.tm address printed by `setup.js`).
   d. `http://localhost:4021/settings` after signing in: the passkey list and the nudge banner.
   Tell me what the OS prompt and the self-care page look like; fix the runbook if the labels differ.
2. **SMS to a phone** (optional): run `ssh -R 80:localhost:4031 nokey@localhost.run`, start a gateway on :4031 that forwards to an SMS carrier, then `node demo/uc02-passkeys/setup.js --sms-url https://<host>/sms`. Remove it with `teardown.js`.
3. **Teardown when done:** `node demo/uc02-passkeys/teardown.js`.

## Questions for IBM

- Enable passwordless (passkey-only) sign-in on the Cloud Directory login page: the passkey button, `passwordless.fido`. Currently `CSIAH0026E` on the API route.
- SMS / voice OTP service on the tenant (and quota). The bring-your-own gateway works without it.
- Can a passkey be offered first on the choice page (method order or default method), and can "use another method" be hidden for a level?

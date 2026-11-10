# UC-06: Voicebot (CCaaS) information query, document request and transactions

IFC's requirement (`IAM Modernization Use Cases.pdf`, UC-06): a policyholder calls the contact centre and a voicebot handles an
information query, a document request, a simple transaction or a sensitive transaction. The CIAM service must provide
**an API to generate an OTP, an API to validate it, and an API to send an MFA request to the app on a registered device and
validate the response**. For sensitive requests, step-up is one of three alternatives: approve an in-app notification, use a code
from the in-app generator, or use a passkey.

Evidence tags: `[LIVE]` executed on the tenant, `[DOCS]` from documentation, `[INFER]` reasoning, `[HUMAN]` a person must do it.

## What is here

| File | What it does |
|---|---|
| `../../stubs/voicebot-ccaas/server.js` | The CCaaS / voicebot orchestration stub: `/call /identify /challenge /verify /stepup /stepup/verify /stepup/status /transaction /transcript` |
| `../../stubs/voicebot-ccaas/backends.js` | Mock Billing API, Client 360 API, Policy-change API, plus the demo customer and the risk-tier table |
| `setup.js` | Creates the customer, her TOTP enrolment and the least-privilege CCaaS API client. Idempotent |
| `run.js` | Automated scenarios A to G against the real tenant. Writes `demo/out/uc06.json`. `--push` adds the phone approval |
| `caller.js` | Interactive text "caller" for the presenter. Type real codes, or `auto` to let the script act as the authenticator app |
| `enroll-phone.js` | `[HUMAN]` Creates the QR code to register the IBM Verify app for the customer |
| `verify.js` | Pass / fail / human report |
| `teardown.js` | Removes everything UC-06 created |

Names on the tenant: user `ifc-demo-uc06-marie`, API client `ifc-demo-uc06-ccaas`. `demo/teardown-all.js` finds both.

## Run it

```bash
node demo/uc06-voice/setup.js        # idempotent
node demo/uc06-voice/run.js          # scenarios A-G, no human needed; 20 s to 2 min (see note below)
node demo/uc06-voice/verify.js       # setup state + scenarios + evidence checks; 20 s to 2.5 min
node demo/uc06-voice/caller.js       # interactive, for presenting
node demo/uc06-voice/teardown.js
```

Why the run time varies: Verify accepts each TOTP window once, and only the windows -1/0/+1 around now. A run consumes three codes (scenario A, C and D), so back-to-back runs wait for the next 30 s boundary. A first run after a pause takes about 20 s; repeated runs take up to about 100 s each. Scenario C submits a deliberately wrong code; Verify counts wrong codes per enrolment and can answer 429 `CSIBN0081E` for a while `[LIVE]`. `run.js` waits that out (20 s steps) instead of failing. A soak of 6 back-to-back runs earlier failed from this before the wait loop existed; the loop was then verified with 2 back-to-back runs (32/32 twice), but the lockout branch itself did not trigger in those 2 runs, so it is `[INFER]`-level tested.

The customer's e-mail is the tenant admin's mailbox by default (so the e-mail OTP reaches the presenter). Override with
`UC06_MAILBOX=you@example.com node demo/uc06-voice/setup.js`. The demo policy number is `AUTO-48213`.

## Risk tiers (what the bot enforces)

| Tier | Requests | Proof required |
|---|---|---|
| 1 | outstanding bill, renewal date, proof of insurance (pink slip), put car in storage | One verified factor: e-mail OTP **or** authenticator-app code (TOTP) |
| 2 | change e-mail, change bank account | Tier 1 **plus** a step-up: push approval on the registered phone **or** a NEW authenticator-app code. One step-up approves ONE sensitive action |

Design choices you can defend:
- The OTP goes to the address **on file**, never to one the caller states (anti-takeover).
- Proof of insurance is delivered to the address on file.
- 5 wrong OTP attempts at Verify (`retries: 4`) fail the transaction (`CSIBN0080E`); the bot then locks the call and hands over to an agent. Three unknown policy numbers also lock the call.
- The voicebot never holds the 165-entitlement admin credential. It uses an API client with 5 entitlements (see below).

## What is proven, and what is not

### Proven `[LIVE]` (see `demo/out/uc06.json`, 32/32 checks, each Verify call has an `x-correlation-id`)

| Requirement in IFC's text | Verify API used | Result |
|---|---|---|
| API to **generate an OTP** | `POST /v2.0/factors/emailotp/transient/verifications` (`correlation`, `emailAddress`) | 201. Returns `id`, `expiry` (5 min), `retries: 4`. Real e-mail sent |
| API to **validate the OTP** | `POST /v2.0/factors/emailotp/transient/verifications/{id}` (`otp`) | Wrong code 400 `CSIBN0021E`; 5th wrong attempt 400 `CSIBN0080E` (transaction FAILED); reuse 400 `CSIBN0025E` |
| Code from the **in-app code generator** (option 2) | `POST /v2.0/factors/totp` (enrol), `POST /v2.0/factors/totp/{id}` (`otp`) | Right code 204; wrong 400; replay of a used code 400; adjacent 30 s windows -1/0/+1 accepted; too many wrong codes 429 `CSIBN0081E`, which cleared by itself within about 20 s |
| Look the caller up | `GET /v2.0/Users?filter=userName eq "..."` | 200 |
| Know which step-up factors the caller has | `GET /v2.0/factors/totp?search=userId="..."`, `GET /v1.0/authnmethods/signatures?search=owner="..."` | 200 |
| Risk-tiered decision | stub logic | Sensitive request without step-up is refused (403); step-up approves one action only |
| Least privilege | `POST /v1.0/apiclients` | The CCaaS client holds `readUsers, authnAnyUser, readEnrollMFAMethodAnyUser, readAuthenticatorsAnyUser, mfaPush`. It gets 403 on create user, delete user, list API clients |

Entitlement mapping, measured by removing one entitlement at a time and watching for 403: `readUsers` is needed for the SCIM lookup;
`authnAnyUser` for creating and attempting OTPs; `readEnrollMFAMethodAnyUser` for listing TOTP and push enrolments.
`readAuthenticatorsAnyUser` and `mfaPush` are included for the push call `[INFER]`: they could not be proven necessary without a registered phone.

### Not proven

| Item | Why | Tag |
|---|---|---|
| **Push approval** (`POST /v1.0/authenticators/{id}/verifications`, then poll `GET .../verifications/{txnId}` for `VERIFY_SUCCESS`) | No phone is registered. The request body shape follows the API reference. A fake authenticator id returns 404, a malformed body returns 400, so the route and validation are real, but a notification was never sent or approved | `[DOCS]` + `[HUMAN]` |
| **Passkey step-up** (option 3) | Needs a WebAuthn ceremony in a browser on an HTTPS origin and a registered passkey. The bot answers `501 passkey_not_built`. See UC-02 | `[HUMAN]` |
| **SMS and voice OTP** | The tenant refuses: `429 CSIAP3545E "SMS messages are not supported for this account"` and `CSIAP3546E` for voice. The demo uses e-mail OTP. In production IFC would configure SMS (or bring its own gateway via the `external_sms` webhook purpose, which is unverified) | `[LIVE]` blocked |
| Reading the e-mail OTP and entering it | Needs the mailbox. The OTP is really sent in scenario E; `caller.js` option 1 lets you read it | `[HUMAN]` |
| Real telephony, speech-to-text, voice biometrics | Out of scope. Voice is simulated by text. Verify does not do voice biometrics | n/a |

## `[HUMAN]` steps (in order)

1. Install **IBM Verify** on a phone.
2. `node demo/uc06-voice/enroll-phone.js`: scan the QR it opens (`Add account` > `Scan QR code`). It waits and confirms.
3. `node demo/uc06-voice/run.js --push`: approve the notification on the phone. If it passes, `verify.js` shows `PASS push step-up approved on a real phone`.
4. `node demo/uc06-voice/caller.js`: choose `1` (e-mail me a code), read the code from the mailbox (the digits after the dash), then try request 5 or 6 and choose `push`.

## Gotchas found while building `[LIVE]`

- `POST /v1.0/apiclients` returns **201 with an empty body**. List, then `GET /v1.0/apiclients/{id}` to read `clientId` and `clientSecret`.
- A user can have **one** TOTP enrolment (`409 CSIBN0019E`). Setup keeps the existing one.
- A TOTP window is **single-use** (replay rejected). `nextTotpCode()` in `common.js` tracks the last window used; scripted runs therefore sleep to the next 30 s boundary when they run out of windows.
- E-mail OTP: the user types the digits **after** the `NNNN-` prefix. Typing the prefix gives `CSIBN0018E`.
- **Email suppression list:** after a delivery failure Verify suppresses the address and `POST .../emailotp/...` then returns `400 CSIBN0075E`. `example.com` addresses end up suppressed. Check with `GET /v1.0/notification/suppression/email/{address}`, clear with `DELETE` on the same path. This will bite you if you set `UC06_MAILBOX` to a fake address.
- `GET /v2.0/factors/totp/{id}` with `Accept: image/png` returns 406; the QR is only returned on creation. The Verify app registration QR comes from `POST /v1.0/authenticators/initiation` with `Accept: image/png`.
- `deleteUser` in `demo/lib/idempotent.js` deletes the user's IBM Verify app registrations first, as a precaution `[INFER]`: whether Verify cascades that delete was not tested because no phone was ever registered.

# UC-04: Trusted device registration for OTP push notifications

A customer registers more than one trusted device (phone) with IBM Verify, receives a push on a device, approves or denies it, and can revoke any device herself. The server side is proven end to end with a **simulated IBM Verify app**. A real phone is still `[HUMAN]`.

## IFC requirement (verbatim from "IAM Modernization Use Cases.pdf", UC-04)

> Support more than one trusted device per user. A user self-service way to revoke trusted devices. IdP integration with IFC mobile apps for push (proprietary SDK, Firebase, Salesforce Marketing Cloud).
> **Main flow:** The user signs in to the mobile app from a trusted device, selects "Register Device", and gets a push on successful registration.
> **Demo:** A user registered with 2 trusted devices, plus extras such as location. A vendor that supports only one device must state the limitation.

**Answer:** IBM Verify supports several devices per user (2 shown, 13 reached while exploring, no limit hit). The vendor limitation question does not apply to the number of devices.

## What is built

| Piece | Where |
|---|---|
| Customers `ifc-demo-uc04-marie` (2 devices) and `ifc-demo-uc04-olivier` (isolation check) | tenant |
| API client `ifc-demo-uc04-device-service` (5 entitlements, no SCIM) | tenant |
| Authenticator client `ifc-demo-uc04-ifc-mobile-app` (registration profile of IFC's own app) | tenant |
| Policy `ifc-demo-uc04-policy-push` (password + approval on a registered device) and apps `-app-login` (code + PKCE), `-app-console` (password grant = the signed-in customer) | tenant |
| Software IBM Verify app (register, enrol approval key, poll, sign, answer) | `demo/lib/verifyDevice.js` |
| Device logic: list, QR, push, poll, revoke | `stubs/device-portal/devices.js` |
| "My trusted devices" web page, port 4041 | `stubs/device-portal/server.js` |
| `setup.js`, `run.js`, `verify.js`, `teardown.js`, `serve.js`, `enroll-phone.js` | this folder |
| `teardown-all.js` now also removes authenticator clients | `demo/teardown-all.js` |

## Commands

```bash
node demo/uc04-devices/setup.js            # idempotent
node demo/uc04-devices/run.js              # 57 automated checks, about 65 s (simulated phone, no human)
node demo/uc04-devices/verify.js           # reads demo/out/uc04.json, pass/fail
node demo/uc04-devices/serve.js            # live demo: http://localhost:4041
node demo/uc04-devices/enroll-phone.js     # [HUMAN] QR for a REAL phone; run once per phone
node demo/uc04-devices/enroll-phone.js --push   # [HUMAN] real push to every registered device
node demo/uc04-devices/teardown.js         # removes every ifc-demo-uc04-* object (users take their devices with them)
```

## The flow

1. **Register Device.** The customer, signed in, calls `POST /v1.0/authenticators/initiation {clientId, accountName}` with her **own** token (no `owner`). With `Accept: image/png` the answer is the QR image; with JSON it is the payload `{code, registrationUri}`.
2. The app redeems the code (`POST <registrationUri>`), enrols its approval key (`signature_userPresence`) and finalizes. The registration goes ENROLLING to ACTIVE. The simulated app does the same steps in about 0.9 s.
3. **More devices:** repeat. `GET /v1.0/authenticators` lists them (name, platform, state).
4. **Push:** `POST /v1.0/authenticators/{id}/verifications` with the message, IP and location (`additionalData originLocation`). Answer 202 PENDING. The device sees it within about 0.4 s, answers, and the state becomes VERIFY_SUCCESS, USER_DENIED, USER_FRAUDULENT, VERIFY_FAILED or TIMEOUT.
5. **Sign-in step-up:** a policy with `ACTION_MFA_ALWAYS` and method `signatures` makes the hosted login ask for approval. With 2 devices the customer chooses one.
6. **Revoke:** `DELETE /v1.0/authenticators/{id}` with the customer's own token (204). The device is dead at once.

## Findings [LIVE 2026-11-13]

- **Several devices per user: yes.** 13 registered for one user, no limit reached.
- **Self-service works with the customer's own token:** initiation, list (own devices only), push to own device, delete own device. Another customer's device: 403 `CSIBH0002E`.
- `platformType` must be `IOS` or `Android` (`ANDROID` is 400 `CSIBH0005E`). `signedData` is plain base64 (base64url is 400 `CSIBH0024E`).
- Push body needs `logic: "OR"` (else 400 `CSIAK2802E`) and `authenticationMethods:[{id: <signature id>, methodType:"signature"}]`. The signature id comes from `GET /v1.0/authnmethods/signatures` (match `attributes.authenticatorId`).
- **Entitlements for the back-end service:** list `readAuthenticatorsAnyUser`; initiation and delete `manageAuthenticatorsAnyUser`; signature lookup `readEnrollMFAMethodAnyUser`; creating and polling a push `authnAnyUser`. **`mfaPush` alone does not enable push** (403).
- Disable and enable: `PATCH` with `Content-Type: application/json-patch+json` and `[{op:'replace',path:'/enabled',value:false}]` (204). Other content types are 415. A push to a disabled device is 400 `CSIBH0036E`.
- Device-side errors: wrong key 400 `CSIBH0031E` (state VERIFY_FAILED), replay 400 `CSIBH0030E`, other device's request 404 `CSIBH0028E`, cancel (DELETE of a request) 405.
- Hosted login with 2 devices shows a choice page whose **order is not stable**: pick the device by its name. Deny gives `CSIAH3102E`. With one device it goes straight to the pending page.
- Audit: `GET /v1.0/events` (readReports). Device events have `resource: mfa_device` and `action: created | modified | deleted`, `self: "true"` for devices the customer registered herself. Push sign-ins have `mfamethod: "IBM Verify Push"` and `mfaresult`. Lag is 25 to 40 s. `event_type` / `search` filters do not work (400 `CSIAU1017E`): read a window and filter client-side.
- **Number matching** (`correlationEnabled`) is accepted in the push body and has no effect.
- **IFC's own app:** `POST /v1.0/authenticators/clients` takes only a `name`. Registrations made with that client id work with the same push API. Firebase / APNs fields are rejected, so IFC's proprietary push channel needs the IBM Verify MFA SDK in IFC's app and IBM to attach the credentials `[DOCS]/[HUMAN]`.

## Honest gaps

- `[HUMAN]` **No real phone was used.** The simulated app polls Verify for the request instead of receiving an APNs/FCM notification. Face ID, Touch ID and the real app's screen (location text, approve button) are not proven.
- `[HUMAN]` The "Register Device" tap in IFC's own mobile app is not run (that app does not exist here).
- `[DOCS]` Firebase, proprietary SDK and Salesforce Marketing Cloud push: not configurable through the API. Ask IBM.
- The push message on the real app is shown by IBM Verify's own template. IFC wording via `transactionData` and `pushNotification` is accepted, but how it renders on the phone is `[HUMAN]` to see.

## For the presenter (human steps)

```bash
node demo/uc04-devices/setup.js
node demo/uc04-devices/enroll-phone.js     # scan with IBM Verify on phone 1
node demo/uc04-devices/enroll-phone.js     # scan with phone 2 (or a second account on the same phone)
node demo/uc04-devices/enroll-phone.js --push
node demo/uc04-devices/serve.js            # http://localhost:4041 : list, push, revoke
```

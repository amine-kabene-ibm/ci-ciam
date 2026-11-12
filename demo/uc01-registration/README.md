# UC-01: Self-service registration and progressive profiling

A new customer registers with **only an e-mail address and a password**. IBM Verify sends the verification e-mail, IFC's registration service checks for duplicates (e-mail, phone, policy number), links the customer to their Client 360 record, and asks for the rest of the profile one small question at a time on later visits.

## IFC requirement (from "IAM Modernization Use Cases.pdf", UC-01)

Minimal identifier at signup; a verification challenge; set authentication factors; link to the policy / customer record; progressive profiling instead of one long form; duplicate detection on e-mail, phone and policyholder ID. Demo: first-time signup, progressive profiling, duplicate detection on a matching e-mail.

**Honest gaps:**
- **Flow designer is not enabled** on this tenant (403 `CSIBZ0098E`), and no self-registration configuration API exists. The orchestration is therefore **IFC code** (`stubs/registration-portal`) calling Verify's APIs. Verify does the identity work (e-mail OTP, user store, password policy, hosted sign-in, tokens); the wizard around it is a stand-in for IFC's own portal.
- Factor choice at signup (passkey, TOTP) is not covered: e-mail OTP verifies the address, password is the credential. SMS OTP is not covered.
- Multi-brand / multi-tenant registration is not demonstrated.

## What is built

| Piece | Where |
|---|---|
| Custom attributes `client360Id`, `policyNumber` (unique), `hasVehicle` | tenant: `ifc-demo-uc01-client360-id`, `-policy-number`, `-has-vehicle` |
| Group of self-registered customers | tenant: `ifc-demo-uc01-customers` |
| Registration service identity (`readUsers`, `manageUsers`, `authnAnyUser`, `manageGroupMembers`) | tenant: API client `ifc-demo-uc01-registration` |
| Portal sign-in app (code + PKCE, password grant for scripts, `sendAllKnownUserAttributes`) | tenant: `ifc-demo-uc01-portal` |
| Client 360 stand-in, port 4010 | `stubs/client360/server.js` |
| Registration service (duplicate rules, OTP, create, progressive stages) | `stubs/registration-portal/service.js` |
| Portal web page + API, port 4011 | `stubs/registration-portal/server.js` |
| `setup.js`, `run.js`, `verify.js`, `teardown.js`, `serve.js`, `common.js` | this folder |
| `ensureCustomAttribute`, `deleteAttributesByPrefix` | `demo/lib/idempotent.js` |

No customer is created by `setup.js`: customers register themselves. Self-registered customers use their e-mail as `userName`, so teardown finds them as members of `ifc-demo-uc01-customers`.

## Commands

```bash
node demo/uc01-registration/setup.js     # idempotent
node demo/uc01-registration/run.js       # 52 automated checks, about 40-90 s (reads REAL Verify e-mails from disposable mail.tm inboxes)
node demo/uc01-registration/verify.js    # reads demo/out/uc01.json, pass/fail + secret scan
node demo/uc01-registration/serve.js     # live demo: http://localhost:4011 (Client 360 stand-in on :4010)
node demo/uc01-registration/teardown.js  # removes every ifc-demo-uc01-* object and the registered customers
```

## The flow

1. **Start.** `POST /api/register/start {email, policyNumber?, postalCode?}`. The service validates, asks Client 360 once (policy + postal code must match to link), runs the duplicate rules with SCIM filters, then calls `POST /v2.0/factors/emailotp/transient/verifications`. Verify sends the e-mail (`NNNN-NNNNNN`; the person types only the digits after the dash, the first four are the on-screen correlation number).
2. **Complete.** `POST /api/register/complete {txn, code, password}`: verify the code (`POST …/verifications/{id}`), re-run the duplicate rules, `POST /v2.0/Users` with e-mail + password only (plus the Client 360 id in `employeeNumber` and `client360Id`), add to the group.
3. **Sign in.** Verify's hosted login (authorization code + PKCE). The ID token carries `employee_id` = Client 360 id. There is no Client 360 call at sign-in.
4. **Progressive profiling.** `GET /api/me` says what is missing; `POST /api/profile/{address|about}` writes one stage by SCIM PATCH. Stage 1 asks postal code and language, stage 2 asks about a vehicle (+ optional mobile number).

## Findings that matter [LIVE 2026-11-12]

- **Custom attributes do not reach the ID token or userinfo** (tested with `tags:["sso"]`, `sendAllKnownUserAttributes`, several mapping payloads). Enterprise attributes do: `employeeNumber` appears as `employee_id`, `department` as `department`, `title` as `job_title`, mobile phone as `mobile_number`, when the app has `sendAllKnownUserAttributes: "true"`. So the Client 360 id is stored in `employeeNumber` (and in `client360Id`).
- Custom attribute SCIM names must be alphanumeric (`client360_id`, `a-b`, `x_y` give 400 `CSIAI0096E`). The internal name must be a free slot `customAttributeN`.
- `constraints.unique: true` is enforced on user create/update: a second user with the same value gets 400 `CSIAI0313E` ("value … already exists"). It is the backstop for "one account per policy number".
- Verify blocks only an identical `userName` (409, case-insensitive). A different `userName` with the same e-mail is **not** blocked (201). The e-mail / phone / policy rules therefore live in the registration service.
- SCIM filters work on `emails.value`, `phoneNumbers.value`, `externalId`, the enterprise `employeeNumber` (full URN prefix) and custom attributes (`urn:ietf:params:scim:schemas:extension:ibm:2.0:User:customAttributes.<scimName>`).
- E-mail OTP needs the **`authnAnyUser`** entitlement (`generateOTP` gives 403). Adding to a group needs **`manageGroupMembers`**. SCIM password-policy errors carry the code in `detail` (`CSIAI0020E`, `PWD_TOO_SHORT`), not in `messageId`.
- OTP: 5 attempts (`retries: 4`); wrong code 400 `CSIBN0021E`; the fifth wrong attempt 400 `CSIBN0080E`.
- Sign-in by userName only (an e-mail that differs from the userName gives `CSIAQ0264E`), so the e-mail is the userName.
- `GET /v2.0/Me` works with the customer's token; `PATCH /v2.0/Me` is 405. The portal writes the profile with its own API client.
- Disposable inboxes (mail.tm) receive Verify's e-mail (4 s to about 2 min), so the scripts can read the OTP without a human. mail.tm answers 429 on bursts; `common.js` retries.

## What is a [HUMAN] step

- Registering in a real browser with your own mailbox: run `serve.js`, open http://localhost:4011, type your address, read the e-mail, type the digits after the dash. (The page also offers a disposable test inbox that reads the code for you.)
- The hosted Verify sign-in page is the standard one; branding is not available on the trial.

## Limits to state

- The wizard is a **stub portal**; IFC's real portal would call the same two endpoints. Client 360 is a stand-in with two policies (`AUTO-31877` / `H2X 1Y4`, `HOME-40412` / `M5V 2T6`).
- Registration transactions are held in memory; a restart drops pending registrations.
- Nothing is written to the directory before the e-mail is proven, so an abandoned registration leaves no trace.

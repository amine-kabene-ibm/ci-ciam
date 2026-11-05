# Intact (IFC) Demo Build Guide: how each demo gets built

**Audience:** the engineer building the demos (Bob or a human).
**Companion docs:**
- [`INTACT-USE-CASE-FEASIBILITY-AND-DEMO-PLAN.md`](INTACT-USE-CASE-FEASIBILITY-AND-DEMO-PLAN.md): the feasibility verdicts and rationale.
- [`DEMO-RUNBOOK-UI.md`](DEMO-RUNBOOK-UI.md): how a human presents each demo on the UI.
- [`VERIFY-PLAYBOOK.md`](VERIFY-PLAYBOOK.md): platform and repo knowledge.

**Tenant:** `https://trialverify.verify.ibm.com` (EU, trial).

---

## 0. Read this first: what is proven vs. not proven

Everything below is tagged by how I know it.

| Tag | Meaning |
|---|---|
| `[LIVE]` | I executed it against the real tenant on 2026-11-05 and saw the result. |
| `[DOCS]` | From official docs or the API reference. Not executed. |
| `[INFER]` | Reasoning. Test before promising it. |
| `[HUMAN]` | A person must do this step (phone, browser, console, IBM request). |

### 0.1 Live facts that shape every build `[LIVE]`

| # | Finding | Consequence |
|---|---|---|
| 1 | The privileged API client in `.env` works. `client_credentials` returns a token, 7199 s lifetime. It holds **165 entitlements** (all the ones in the plan, plus more). | All API-driven builds can proceed. |
| 2 | **Flow designer is NOT enabled.** `GET /v1.0/config/models` returns 403 `CSIBZ0098E`: "tenant is not subscribed to this feature: CI-49771". | UC-01 Track B, UC-11 option 2 and every Flow-based option are blocked until IBM enables it. Track A / option 1 paths are used instead. |
| 3 | **Branding is NOT enabled on the trial.** `POST /v1.0/branding/themes` returns 403 `CSIAZ3060E`: "Trial subscriptions do not support the branding feature." | The demo app's custom theme cannot be registered. The app runs with the `default` theme. **This also blocks UC-10 (per-brand themes and FR/EN) until IBM enables branding.** |
| 4 | Dynamic client registration `POST /oauth2/register` works (201) and `DELETE /oauth2/register/{id}` works (204). | UC-15 dynamic client demo is buildable. Also the quickest way to create test clients. |
| 5 | `private_key_jwt` client registered via DCR with a JWKS; a signed client assertion with `aud = <tenant>/oauth2/token` returned a token. | UC-09 `private_key_jwt` is proven end to end. |
| 6 | `tls_client_auth` client with certificate-bound access tokens registers fine (201). **The actual mTLS handshake is NOT tested.** | UC-09 mTLS still needs a handshake test (section UC-09). |
| 7 | CIBA app created via `POST /v1.0/applications` with `grantTypes.ciba=true` and backchannel settings (poll, email). **You must set `"applicationState": true`**, otherwise `/oauth2/ciba` returns `invalid_client`. With it enabled, `/oauth2/ciba` is reachable and returned `unknown_user_id` for a fake user. | UC-14 is buildable. The approval step needs a human (email link or phone). |
| 8 | SCIM `PATCH active=false` returns 204. A token issued earlier then introspects `active:false` **within the same second** and a new token request returns `CSIAQ0281E The account is not active.` | **UC-13 core claim is proven:** deactivation immediately kills existing access tokens and blocks new logins. |
| 9 | `DELETE /v1.0/auth/sessions/{userId}` returns 204. `GET` on sessions with no session returns `{}`. | Session revoke API works. A real browser session is needed to see it killed (human step). |
| 10 | SCIM filter `emails.value eq "..."` finds an existing user. | UC-01 duplicate detection is buildable. |
| 11 | DPCM purposes API works and the three purposes the app uses exist (`communications`, `paperless-billing`, `terms`). | UC-15 base is in place. |
| 12 | Access policy **v5.0** create works. Valid rule condition types: `adaptiveAttributes, adaptiveRiskScoreAttributes, authnMethods, cia, contextAttributes, customAttributes, factorLifetimeAttributes, geoLocation, integrationAttributes, ipAddress, location, postAuth, subjectAttributes, threatInsights, timeAttributes, trusteer, webhooks`. Policies with `geoLocation`, `threatInsights`, `trusteer`, `webhooks` conditions were **accepted** (201). `ipAddress` takes opCodes `MATCH`/`NOMATCH`. | Policy building (UC-02, 03, 05, 08) is possible by API. Acceptance of `trusteer` is not proof Adaptive access is licensed; it still needs a real login to evaluate. |
| 13 | Threat detection config exists but is **`status: inactive`** (5 rules incl. credential stuffing, brute force). | UC-05 threat intel needs IBM to activate it. |
| 14 | Webhook purposes available: `identity_proofing`, `external_mfa`, `external_risk`, `notifications`, `external_sms`. | **New finding:** `external_risk` lets a policy call an external information point, and `external_sms` routes SMS to an external provider. Both help UC-05 and UC-02 (see those sections). |
| 15 | STS client create works (201) with `tokenSettings.signingAlg` set (the error `CSIAQ0134E` says it's required). | UC-09 token exchange / UC-07 buildable. |
| 16 | FIDO2 relying party create works: `POST /v2.0/factors/fido2/relyingparties {"origin":"https://..."}` returns 200. | UC-02 buildable. `GET` on that path returns 405 (not a list endpoint). |
| 17 | `GET /v1.0/authenticators` returns 0 registrations. `GET /v1.0/authenticators/discovery` lists one client, "Verify Profile". | UC-04/06/14: no phone is registered yet. `[HUMAN]` |
| 18 | Sub-tenant API returns 405 `CSIAG0746E`: "This tenant does not have a partner reseller offering enabled". | **Resolves the open UC-10 question:** sub-tenants are a **reseller** feature, not a per-brand admin feature. Not available. |
| 19 | The token endpoint for `grant_type=password` is not allowed on the default app client. DCR clients can enable it. | Use DCR clients for scripted user logins in tests. |
| 20 | The `ifc` demo user created through SCIM with a password has "password must be changed" on first login unless header `usershouldnotneedtoresetpassword: true` is sent. | All scripted test users must send that header. |

### 0.2 Blockers found and fixed during this session

| ID | Problem | State |
|---|---|---|
| B1 | `.env` API credentials were placeholders | **Fixed by you.** Token works. |
| B2 | Callback URI not registered | **Fixed.** The app's registration includes `http://localhost:3000/oauth/callback`; `/authorize` now redirects to the login page instead of failing. |
| B3 | Trailing slash on `OIDC_CI_BASE_URI` | **Already removed** in `.env`. |
| B4 (new) | The demo app's `/setup` crashed with `TypeError: Cannot read properties of undefined (reading '0')` in `functions.js`. Cause: it called the **access policy v3.0 API, which IBM removed** (the endpoint now returns 200 with an empty body, so `policies` is undefined). | **Fixed** in `functions.js`: lookup and create now use `/v5.0/policyvault/accesspolicy`, with the v5 rule schema and a correctly quoted `search=name="..."` filter. |
| B5 (new) | `response.statusCode` was used on axios responses (axios only has `.status`), so group, rule and purpose creation checks always fell into the "else" branch. | **Fixed** in `functions.js`. |
| B6 (new) | Theme registration returns 403 on trial (finding 3). | **Cannot be fixed by us.** Needs IBM to enable branding. `/setup` now completes (HTTP 200) with the default theme. |

After the fixes, running `POST /setup` completed with HTTP 200: it created the `MFAGroup` group, the access policy `Require 2FA for MFAGroup` (id 2001235), applied it to the `TrustMeInsurance` app, and left the three DPCM purposes in place. The app serves `/`, `/login`, `/setup`, `/terms.html`.

### 0.3 State left on the tenant (all created by the app's `/setup`, plus my probes cleaned up)

- App: `TrustMeInsurance` (OIDC, auth-code, redirect `http://localhost:3000/oauth/callback`)
- Group: `MFAGroup`
- Access policy: `Require 2FA for MFAGroup` (id 2001235), attached to the app
- DPCM purposes: `communications`, `paperless-billing`, `terms`
- Users: only the tenant admin (`Amine.Kabene@…`)
- All probe objects (test users, DCR clients, STS clients, probe policies, CIBA apps, FIDO relying party) were **deleted**. One exception to confirm: the FIDO relying party probe for `https://ifc-demo.example.com` was created and I could not list/delete it because the list endpoint returns 405. See "Cleanup note" in UC-02.

---

## 1. Common foundation (build once)

### 1.1 Files to create (nothing is created yet; this is the plan to execute)

```
demo/
  lib/verify.js          token cache, request wrapper, evidence logger, SCIM content-type handling
  lib/idempotent.js      "ensure*" helpers (ensureUser, ensureGroup, ensureApp, ensurePolicy ...)
  config/                JSON for policies, purposes, apps
  00-probe.js            re-runs the live probes in section 0.1 and prints a pass/fail table
  teardown-all.js        deletes every object whose name starts with "ifc-demo-"
  out/                   evidence JSON per use case (gitignored)
  ucNN-*/                setup.js, run.js, verify.js, teardown.js, README.md
stubs/                   small Express services (voicebot, client360, legacy store, rules engine, ops queue, RPs)
```

### 1.2 Rules for `demo/lib/verify.js` (learned the hard way, all `[LIVE]`)

1. **SCIM calls (`/v2.0/Users`, `/v2.0/Groups`) need `Content-Type: application/scim+json`.** With `application/json` and an `Accept` that is only `application/scim+json`/`json`, the API returned **406 `CSIAI0211E`** and **415 `CSIAI0212E`**. Use `scim+json` for both headers on SCIM paths; use `application/json` elsewhere.
2. Some endpoints return **HTTP 400 with an empty body**. Always log the status, `x-correlation-id` response header and the raw body so failures can be traced.
3. Create users with header `usershouldnotneedtoresetpassword: true`, otherwise logins fail with `CSIAQ0267E The password must be changed.`
4. Use **axios `.status`**, never `.statusCode`.
5. New OIDC apps via `/v1.0/applications` are created **disabled** unless you pass `"applicationState": true`.
6. Token lifetime is ~2 hours. Cache it and refresh on 401.
7. Name everything `ifc-demo-<uc>-<thing>` so `teardown-all.js` can find it.
8. The API rate limit header showed `x-isv-ratelimit: 25` requests per second window. Throttle bulk scripts.
9. For scripted end-user logins, register a **DCR client** with `grant_types:["password","authorization_code"]` and `all_users_entitled:true`.

### 1.3 Run the baseline

```bash
node bin/www                      # app on :3000
curl -X POST localhost:3000/setup # idempotent, already run once
node demo/00-probe.js             # when built: prints the table in 0.1
```

---

## 2. Per-use-case build instructions

Legend per use case: **Status** (can Bob build it fully?), **Build steps** (automatable), **Human steps** (`[HUMAN]`), **Verification**, **Teardown**, **Open risks**.

---

### UC-01: Self-service registration and progressive profiling

**Status:** Bob can build **Track A** fully (app + API). Track B (Verify Flow) is **blocked: Flow designer not enabled** `[LIVE]`.

**Build steps (Track A)**
1. `demo/uc01-registration/setup.js`: create tenant custom attributes via `POST /v1.0/attributes` (this repo's `createAttributes` already does it): `postal_code`, `preferred_language`, `has_vehicle`, `client360_id`. Group `ifc-demo-customers`.
2. `stubs/client360/server.js` (port 4010): `GET /client360?email=` returns `{ client360_id, segment }` deterministically (hash of email).
3. New route `routes/ifc-register.js` in the demo app:
   - `POST /ifc/register/start {email}`: duplicate check with `GET /v2.0/Users?filter=emails.value eq "<email>"` `[LIVE]` (returns `totalResults`). If found: respond "account exists".
   - Email OTP: `POST /v2.0/factors/emailotp/transient/verifications` `{correlation, emailAddress}` then `POST …/{id}` with the OTP `[DOCS]`. Do **not** assume it returns the OTP; the user reads it from email.
   - `POST /ifc/register/complete`: `POST /v2.0/Users` with email only (minimal data) and header `usershouldnotneedtoresetpassword`. Call the Client 360 stub and `PATCH` `client360_id` into the user's custom attributes.
4. Progressive profiling: on OIDC login callback in `app.js`, read the user; if `postal_code` empty, redirect to `/ifc/profile/step2`, which `PATCH`es `/v2.0/Users/{id}`.
5. Token enrichment: map `client360_id` into the ID token via the app's attribute mapping. `[INFER]` the OIDC app can map custom attributes; **test** that the claim appears.

**Human steps**
- `[HUMAN]` Real inbox to receive the OTP email (or use a mailbox you control).
- `[HUMAN]` Ask IBM to enable **Flow designer** if IFC wants the flow-based showpiece (Track B) and, separately, to enable **User forms**.

**Verification:** a script posts email, reads user back via SCIM, confirms attributes; second attempt with same email returns the duplicate message; decode ID token and assert `client360_id` claim.

**Teardown:** delete users in group `ifc-demo-customers`; delete attributes (optional).

**Open risks:** claim mapping unproven; OTP email delivery from a trial tenant; external callout at token time is **not available on trial** `[DOCS]` so the demo stores the Client 360 value on the user ahead of time (that is also the "no latency" story).

---

### UC-02: Passkeys / FIDO2 with OTP and TOTP fallback

**Status:** Bob builds all server-side pieces. The passkey ceremony itself is `[HUMAN]` (needs a browser authenticator).

**Build steps**
1. Hostname: WebAuthn cannot use `localhost` `[DOCS]`. Pick `ifc-demo.local`, add `127.0.0.1 ifc-demo.local` to `/etc/hosts` (needs `sudo` `[HUMAN]`), and serve the demo app over **HTTPS** with a locally trusted cert (`mkcert` `[HUMAN]` one-time install) because browsers require a secure context for WebAuthn on non-localhost names.
2. Create the relying party: `POST /v2.0/factors/fido2/relyingparties {"origin":"https://ifc-demo.local:3443"}` → 200 `[LIVE]`. Response contains the RP id and paths (`attestationOptionsPath`, `assertionOptionsPath`, …) `[DOCS]`.
3. Create the three assurance-level policies via v5 API (`ifc-demo-aal1-password`, `ifc-demo-aal2-otp`, `ifc-demo-aal3-passkey`) using `authnMethods` values (see `GET` of an existing policy; passkey method name must be read from a live policy or the docs; `[INFER]`: `urn:ibm:security:authentication:asf:fido2`) and bind to three apps.
4. Add `routes/passkey.js`: adapt IBM's `verify-webauthn-passkey-sample-web`. It calls the attestation/assertion endpoints with a user-scoped token.
5. TOTP: `POST /v2.0/factors/totp` returns a QR; email OTP via the transient verification APIs `[LIVE]` (both config endpoints respond 200 and are enabled).
6. BYO SMS gateway: webhook purpose `external_sms` exists `[LIVE]`; create a webhook with `POST /config/v1.0/webhooks/` pointing to `stubs/sms-gateway` (logs messages) and attach it. `[INFER]` the attach step lives under SMS provider config (`manageSMSProviders` entitlement is held); **test**.

**Human steps**
- `[HUMAN]` install `mkcert`, edit `/etc/hosts`, trust the cert.
- `[HUMAN]` perform the passkey registration and sign-in in a browser (Touch ID / security key).
- `[HUMAN]` scan the TOTP QR with an authenticator app.

**Verification:** `GET /v2.0/factors` lists the passkey/TOTP enrollment (currently `[]` `[LIVE]`); `GET /v1.0/events` shows the factor used.

**Teardown:** delete enrollments, policies, apps. **Cleanup note:** an FIDO RP for `https://ifc-demo.example.com` was created while probing. The list endpoint is 405, so find its id from the creation response in a re-run (`POST` returns the origin; `DELETE /v2.0/factors/fido2/relyingparties/{id}`), or leave it; it is harmless.

**Open risks:** exact method URN for passkey in policies; SMS gateway attach; WebAuthn secure-context setup.

---

### UC-03: Risk-aware account recovery, agent-assisted

**Status:** Bob can build the API flow and an agent page. Risk signals are limited (see risks).

**Build steps**
1. Policy `ifc-demo-recovery`: v5 policy with a `geoLocation` condition (accepted `[LIVE]`) that demands OTP when country ≠ CA, and a `threatInsights` rule (accepted `[LIVE]`, but threat detection is inactive).
2. Customer-initiated recovery driver `demo/uc03-recovery/run.js`: call the reset APIs (`resetpassword`, validator, complete) `[DOCS]`; read the exact paths from the API reference at build time.
3. Agent console route `GET /agent` in the demo app (agent signs in via OIDC): search user (SCIM), button "Send reset" (`PATCH /v2.0/Users/{id}/passwordResetter`), button "End all sessions" (`DELETE /v1.0/auth/sessions/{id}` `[LIVE]` 204), table of last events for the user (`GET /v1.0/events?filter_key=…`).
4. Evidence: write event ids to `demo/out/uc03.json`.

**Human steps:** `[HUMAN]` open a second browser profile / VPN to change apparent country for the "risky context" scenario; `[HUMAN]` receive the reset email.

**Verification:** reset event and session-revoke event appear in `/v1.0/events`.

**Open risks:** no AI risk score without Adaptive access. Events API worked (`200`, returned management/sso events) `[LIVE]`.

---

### UC-04: Trusted devices (two devices), push, self-service revoke

**Status:** **Mostly `[HUMAN]`.** Bob builds the scripts; a real phone with the IBM Verify app is required.

**Build steps**
1. `demo/uc04-devices/setup.js`: create user `ifc-demo-device-user`.
2. `register.js`: `POST /v1.0/authenticators/initiation {owner, clientId:"5280f51a-…" (Verify Profile) , accountName}` returns a QR `[DOCS]`; the script saves `demo/out/qr-A.png`. The Verify Profile client id was returned by `/authenticators/discovery` `[LIVE]`.
3. `push.js`: `POST /v1.0/authenticators/{id}/verifications` with `transactionData.message`, `originIpAddress`; poll `GET /v1.0/authenticators/{id}/verifications/{txnId}` `[DOCS]`.
4. `revoke.js`: `DELETE /v1.0/authenticators/{id}`.

**Human steps**
- `[HUMAN]` Install **IBM Verify** on phone(s) and scan `qr-A.png` and (second phone or second account on the same phone) `qr-B.png`.
- `[HUMAN]` Approve/deny pushes.

**Verification:** `GET /v1.0/authenticators?filter=…` shows 2 entries for the user. **If the second registration is rejected, record it: the PDF accepts "state the limitation".**

**Open risks:** unproven that one user can hold two IBM Verify registrations; Firebase/APNs custom authenticator is out of scope.

---

### UC-05: Risk-based adaptive authentication and fraud signals

**Status:** **Partial.** Bob can build the policy and event-collection scripts. Live risk scoring and threat intel depend on IBM.

**What `[LIVE]` told us**
- Policy conditions `trusteer`, `threatInsights`, `geoLocation`, `webhooks` are accepted by the policy API.
- Threat detection config is `inactive`.
- Webhook purpose `external_risk` exists: "Perform additional access policy checks with an external information point". **This is the realistic way to demo IFC's proprietary signals**: the policy calls IFC's (our stub) risk service and acts on its answer.

**Build steps**
1. `stubs/risk-engine` (port 4020): `POST /risk {user, ip, ua}` returns `{score, level, reasons[]}`; deterministic rules plus a "credential stuffing" counter.
2. `POST /config/v1.0/webhooks/` with purpose `external_risk` pointing at the stub (public URL needed, see Tunnel below).
3. Policy `ifc-demo-risk`: rule using `webhooks` condition: deny on `high`, MFA on `medium`, allow on `low`.
4. Attack simulation `demo/uc05-risk/stuffing.js`: loops login attempts with rotating `X-Forwarded-For` and user agents against the app's login; the stub increments counters.
5. Admin view: `GET /v1.0/events` filtered to this app, printed as a decision table.

**Human steps:** `[HUMAN]` ask IBM to **activate threat detection** and enable Adaptive access (Trusteer). `[HUMAN]` provide a public HTTPS URL (tunnel, e.g. ngrok/cloudflared) for the webhook.

**Open risks:** `X-Forwarded-For` spoofing may not be honoured by the SaaS edge; webhook policy wiring unverified; message to IFC: proprietary signals work as policy inputs via `external_risk`, not as Trusteer model features.

---

### UC-06: Voicebot (CCaaS) information query and transactions

**Status:** Bob can build it entirely, except approval on a phone for the push step.

**Build steps**
1. `stubs/voicebot-ccaas/server.js` (port 4030) with `/identify`, `/challenge`, `/verify`, `/transaction`.
2. `/identify`: SCIM lookup `GET /v2.0/Users?filter=…` `[LIVE]`.
3. `/challenge`: email OTP transient verification `POST /v2.0/factors/emailotp/transient/verifications` (SMS config is enabled with default quota unknown `[LIVE]`: `charset/length/expiry/retries` returned).
4. `/verify`: attempt endpoint with the OTP.
5. Step-up for sensitive actions: push via `POST /v1.0/authenticators/{id}/verifications` (needs a registered phone) or passkey assertion.
6. `demo/uc06-voice/caller.js`: an interactive CLI "caller" that talks to the stub and prints a transcript.

**Human steps:** `[HUMAN]` read the OTP from the inbox/phone; approve the push on the phone.

**Verification:** transcript saved to `demo/out/uc06.json`, including Verify transaction ids.

---

### UC-07: App-to-voice transfer without re-authentication

**Status:** Bob builds all of it.

**Build steps**
1. Create STS client (proven shape `[LIVE]`): `POST /v1.0/sts/oauth/clients` with `clientName`, `enabled`, `clientAuthentication{clientAuthMethod, clientSecret}`, `tokenSettings{signingAlg:"RS256"}`, `tokenExchangeSettings{subjectTokenTypes, requestedTokenTypes}`. **Note:** list response uses `clientId`, not `id`; delete with `DELETE /v1.0/sts/oauth/clients/{clientId}` `[LIVE]` 204.
2. In the demo app, add `POST /ifc/handoff`: sends the logged-in user's access token to the voice stub.
3. The stub validates it with `POST /oauth2/introspect` (using the CCaaS client credentials) and, optionally, exchanges it via `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
4. Policy decides which actions still need step-up.

**Human steps:** none beyond running the app and logging in `[HUMAN]` once.

**Verification:** introspection `active:true` with `sub`; exchange response contains the new token.

---

### UC-08: SSO across apps and global logout

**Status:** Bob can build; a browser is required to observe SSO.

**Build steps**
1. `stubs/rp-a`, `rp-b`, `rp-c` (ports 4001-4003), each a tiny OIDC RP (reuse `passport-openidconnect` from this repo) that exposes `/backchannel-logout`.
2. Register them with `POST /oauth2/register` (proven `[LIVE]`), including `backchannel_logout_uri` `[DOCS]` (field name in DCR; test) or through `POST /v1.0/applications` with `additionalConfig.logoutOption:"back_channel"`, `logoutURI`.
3. Public reachability: back-channel logout calls come from the tenant, so the RPs need public URLs (tunnel).
4. Persona separation: two groups (`ifc-demo-brokers`, `ifc-demo-consumers`) and two policies (brokers MFA always; consumers allow). Attach per app.
5. `demo/uc08-sso/verify.js`: uses `GET /v1.0/auth/sessions/{userId}` before and after logout to prove the session list shrinks.

**Human steps:** `[HUMAN]` sign in once in a browser, open the three apps, log out from one.

**Open risks:** session-policy objects (idle/absolute timeouts) have no API found; use per-app token lifetimes.

---

### UC-09: API security

**Status:** Bob builds all of it. mTLS handshake is the one unknown.

**Proven `[LIVE]`:** DCR with `private_key_jwt` + inline `jwks`, then `client_credentials` with a client assertion whose `aud` is `https://trialverify.verify.ibm.com/oauth2/token`: **token issued**. DCR with `tls_client_auth` + `tls_client_certificate_bound_access_tokens:true` registered.

**Build steps**
1. `demo/uc09-api/keys.sh`: `openssl genrsa` + JWKS builder (the exact script worked).
2. `setup.js`: DCR clients: `ifc-demo-m2m-pkjwt`, `ifc-demo-m2m-mtls`, plus an STS client `ifc-demo-partner` with `actorCriteria` (CEL) restricting actors.
3. `run.js`: sign assertion, get token, call `stubs/ifc-api` which introspects (`POST /oauth2/introspect`) and enforces scopes; show a wrong-key rejection.
4. Key rotation: `POST /v2.0/clients/{id}/secrets` `[DOCS]` for secret clients; for `private_key_jwt`, add a second key to `jwks` (update client via `PUT /oauth2/register/{id}`), prove both keys work, remove the old one.
5. On-behalf-of: policyholder token as `subject_token`, partner token as `actor_token`; assert `act` claim.
6. mTLS handshake test: call `POST /oauth2/token` with `curl --cert c.pem --key k.pem`. `[INFER]` the SaaS edge may not request client certs on the main host; if the handshake fails or ignores the cert, **do not claim mTLS**; fall back to DPoP using `verify-saas-resources/apps/oauth/dpop`.

**Human steps:** none unless mTLS needs an IBM-provided mTLS hostname `[HUMAN]` (ask IBM).

---

### UC-10: Per-brand login

**Status:** **Blocked on trial** for themes. Partially buildable otherwise.

**What `[LIVE]` told us**
- Theme registration: **403, branding not supported on trial**.
- Sub-tenants: **405, reseller-only**.

**Build steps (what we can do now)**
1. Two apps `ifc-demo-brandA`, `ifc-demo-brandB`, each with its own policy (A: password+OTP, B: passkey-first) and groups.
2. One user signs in to both (proves one account across brands).
3. Prepare theme zips for both brands from `ci-theme/` (script `demo/uc10-brands/make-themes.sh` copies the 596-file theme, swaps logo/colours, adds FR strings) so they are ready to upload the moment branding is enabled.
4. `register-themes.js`: `POST /v1.0/branding/themes` (multipart `configuration`, `files`); will start working once enabled.

**Human steps:** `[HUMAN]` ask IBM to enable **branding** on the trial and to answer: multiple custom IdP domains per tenant; delegated admin scoped per brand.

**Open risks:** the three IFC asks (custom domains, scoped admin, multi-tenancy) remain unconfirmed or negative; report honestly.

---

### UC-11: Legacy IAM migration

**Status:** Bob can build **bulk import**. JIT depends on Flow designer (blocked) or the Verify Bridge (needs IBM registry access).

**Build steps**
1. `stubs/legacy-auth-store`: users with a legacy hash. Choose the hash IFC uses; the supported `{TYPE}` prefixes must be confirmed (doc shows `{SSHA256}`).
2. Bulk: `demo/uc11-migration/bulk.js`: `GET /v2.0/CSV/headerNames?filter=user` returned the header list `[LIVE]` (`preferred_username` required, `externalId`, …). Build CSV with `password` column of `{SSHA256}…` values, then `POST /v2.0/CSV/importUsers` (multipart) with `notifyType=NONE`. Header `usershouldnotneedtoresetpassword: true`.
3. Prove a migrated user logs in with the original password using a DCR password-grant client `[LIVE pattern]`.
4. JIT option 1 (Bridge): `POST /config/v1.0/onpremagents` (`purpose: EXTAUTHN`) then `POST /v2.0/identitysources`; run the Bridge agent with Podman. Needs the Verify Bridge image from IBM Container Registry `[HUMAN]`. Note: `GET /config/v1.0/onpremagents` returned 404 `CSIBS0035E` "unable to find a configuration", meaning the Bridge feature isn't configured on this tenant yet.
5. JIT option 2: Flow designer. **Blocked** `[LIVE]`.

**Human steps:** `[HUMAN]` ask IBM for Flow designer and for Bridge image access; ask for supported hash list and a financial-services migration reference.

---

### UC-12: ReBAC

**Status:** Bob can build the external engine demo. Not a Verify-native feature.

**Build steps**
1. `stubs/rules-engine`: run **OpenFGA** with Podman (`/opt/podman/bin/podman` is installed `[LIVE]`) and load a model: `brokerage → broker → client → policy`.
2. `demo/uc12-rebac/seed.js`: create SCIM users for brokers and clients and mirror them as tuples.
3. Gateway stub `stubs/policy-api`: validates the Verify access token with introspection, then calls OpenFGA `check` / `list-objects`.
4. `reassign.js`: move a broker to another brokerage (tuple update); re-check; access changes instantly with no re-login.
5. Optional (paid tenant): attribute-function HTTP callout to add a coarse claim. Not available on trial `[DOCS]`.

**Human steps:** none. **Message:** present as "Verify + external ReBAC engine".

---

### UC-13: SCIM broker lifecycle and immediate revocation

**Status:** Bob builds it fully. **Core behaviour proven `[LIVE]`.**

**Proven:** token issued, introspect `active:true`; `PATCH active=false` (204); token introspect `active:false` within 0 s; new token request fails with `CSIAQ0281E The account is not active`; `DELETE /v1.0/auth/sessions/{id}` returns 204.

**Build steps**
1. `stubs/ops-queue`: webhook receiver (port 4040) that stores events (success and failure).
2. Webhook: `POST /config/v1.0/webhooks/` for notification events (purpose `notifications`); needs a public URL (tunnel) `[HUMAN]` for a real delivery. List with `GET /config/v1.0/webhooks/` (`{"webhooks":[]}` `[LIVE]`).
3. `demo/uc13-lifecycle/run.js`: create broker (SCIM) → get token (DCR password client) → deactivate (PATCH) → measure time to first `active:false` and first rejected login → write `demo/out/uc13.json`.
4. Failure path: PATCH a non-existent id; confirm the error goes to the ops-queue stub.

**Human steps:** `[HUMAN]` browser session shown being killed (optional); tunnel.

---

### UC-14: CIBA agent-initiated authentication

**Status:** Bob builds it. The approval is `[HUMAN]` (email link or phone push).

**Proven `[LIVE]`:** CIBA app creation shape and `applicationState:true`; `/oauth2/ciba` returns `unknown_user_id` for unknown users (so the app and credentials are valid).

**Build steps**
1. `setup.js`: `POST /v1.0/applications` with `name`, `templateId:"1"`, `applicationState:true`, `providers.oidc.properties.grantTypes.ciba:"true"` and `additionalConfig.backchannelSettings{deliveryMode:"poll", supportUserCode:false, proximityCheck:"disabled", userAuthChannels:["email"]}`. Read the client id/secret via `GET /v1.0/applications/{id}`.
2. Agent console `GET /agent/verify` in the demo app: form for username; backend `POST /oauth2/ciba` with `scope=openid`, `login_hint`, `binding_message="IFC agent #482 verifying your identity"`; poll `POST /oauth2/token` with `grant_type=urn:openid:params:grant-type:ciba&auth_req_id=…` every `interval` seconds until success or `expired`.
3. After success: show "verified" and enable "Unlock account" (`PATCH /v2.0/Users/{id}` `active:true`) and an audit panel (events API; binding message is attached to SSO events `[DOCS]`).
4. Switch channel to `["push","email"]` once a phone is registered.

**Human steps**
- `[HUMAN]` the caller opens the verification email link (or approves the push).
- Use a test user whose email you control; **do not point CIBA at real customers**.

**Verification:** `auth_req_id` issued, polling returns `authorization_pending` then tokens; audit event visible.

---

### UC-15: Consent management (PIPEDA)

**Status:** Bob can build almost all of it. This repo already has DPCM code.

**Proven `[LIVE]`:** purposes API works and the three purposes exist; DCR works.

**Build steps**
1. `demo/uc15-consent/setup.js`: create attributes and purposes: `claims_processing`, `fraud_analytics`, `marketing`, with `defaultConsentDuration` set; `POST /config/v1.0/privacy/purposes` `[DOCS]`; the app's `createPurpose` also publishes via `PATCH state=1`.
2. Dynamically register two third-party clients: repair-shop and comparison-site (`POST /oauth2/register`, proven), each requesting different scopes.
3. `run.js`: user consents (app `routes/consent.js` already stores consents via DPCM); issue short-lived consent (`endTime = now+60s`) with `PATCH /v1.0/privacy/consents` (`op:"add"`) `[DOCS]`; show enforcement after expiry.
4. `export.js`: dumps `GET /config/v1.0/privacy/consents` filtered by subject + events into JSON/CSV.
5. `stubs/dsar`: records a deletion request, starts an SLA timer, calls consent delete + user delete, stamps completion.

**Human steps:** `[HUMAN]` log in as the test user and click through the consent screen.

---

## 3. Human-only checklist (what you must do, in order)

| # | Action | Unblocks | Effort |
|---|---|---|---|
| 1 | **Email IBM now** (template in section 4). | UC-01 Track B, UC-05, UC-10, UC-11 | 10 min to send, days to get answers |
| 2 | Install **IBM Verify** app on 1-2 phones. | UC-04, UC-06, UC-14 push | 10 min |
| 3 | Create a **public tunnel** (ngrok/cloudflared) for webhooks and back-channel logout. | UC-05, UC-08, UC-13 | 15 min |
| 4 | `mkcert -install`, add `127.0.0.1 ifc-demo.local` to `/etc/hosts`. | UC-02 | 15 min |
| 5 | Provide a test mailbox you can read (or several aliases). | UC-01, UC-03, UC-06, UC-14 | 5 min |
| 6 | Run the passkey ceremony once in a browser. | UC-02 | 5 min |
| 7 | Decide whether Podman images (OpenFGA, Verify Bridge) may be pulled on this machine. | UC-11, UC-12 | 5 min |

## 4. Message to IBM (copy/paste)

> Tenant `trialverify.verify.ibm.com` (EU trial) for the Intact RFP technical evaluation. Please enable:
> 1. Flow designer (API reports "not subscribed: CI-49771") and User forms.
> 2. Branding/themes (trial returns CSIAZ3060E).
> 3. Adaptive access (Trusteer) and activate Threat detection (config is `inactive`).
>
> Please also confirm: (a) multiple custom IdP domains on one tenant; (b) delegated admin scoped to a subset of users/apps; (c) mTLS client authentication endpoint on SaaS; (d) supported password-hash prefixes for CSV import and the recommended JIT migration pattern; (e) whether one user can register more than one IBM Verify authenticator; (f) a prior financial-services migration reference; (g) the external-callout (HTTP) capability in attribute functions on a paid tenant.

## 5. Recommended build order (updated by live findings)

1. **Foundation** (`demo/lib`, `00-probe.js`).
2. **UC-13, UC-09, UC-14, UC-15** (proven or nearly proven).
3. **UC-07, UC-06, UC-01 Track A, UC-03**.
4. **UC-02, UC-08, UC-04** (need browser/phone/tunnel).
5. **UC-12, UC-11 bulk, UC-05, UC-10** (blocked or partial).

## 6. Changes made to the repo during this session

| File | Change | Why |
|---|---|---|
| `functions.js` | `getPolicyId` and `createMfaPolicy` now use `/v5.0/policyvault/accesspolicy`, the v5 rule schema (`meta`, array conditions, string `action`), and a quoted `search=name="…"` | v3.0 API is gone; `/setup` crashed |
| `functions.js` | `response.statusCode` → `response.status` (4 places) | axios exposes `.status` only |
| `.env` | No change by me (B3 was already fixed) | |

Not yet committed to git.

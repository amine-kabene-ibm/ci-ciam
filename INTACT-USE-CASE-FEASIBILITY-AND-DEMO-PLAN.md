# Intact Financial Corp (IFC): Use-Case Feasibility and API-Driven Demo Plan

**Platform:** IBM Verify SaaS, trial tenant `https://trialverify.verify.ibm.com/`
**Input:** `IAM Modernization Use Cases.pdf` (15 use cases, "Broker and Customer Access Management Modernization")
**Companion doc:** [`VERIFY-PLAYBOOK.md`](VERIFY-PLAYBOOK.md) (platform knowledge, repo architecture, runbook)

**Design constraint from the user:** every demo is built and torn down through the Verify **REST API, `verifyctl`, SDKs and scripts committed to this repo**. Nobody clicks through the admin console to build anything. The admin console is used only to *show* results to IFC, never to create them.

---

## 0. How to read this document

### Evidence tags

| Tag | Meaning |
|---|---|
| `[DOCS]` | Stated in the official docs hub (docs.verify.ibm.com guides). |
| `[API]` | Operation, path and request schema read from the official API reference (the OpenAPI spec embedded in each reference page). |
| `[LIVE]` | Observed against the real trial tenant. |
| `[CODE]` | Observed in this repo or in IBM's public sample repos. |
| `[INFER]` | My reasoning. Not confirmed. **Must be tested before promising it to IFC.** |

### What this assessment is and is not

- **Doc-and-schema based.** The only live evidence I have is the tenant's public OIDC discovery document and token-endpoint behaviour. I have **not** been able to call any privileged API, because `API_CLIENT_ID` / `API_SECRET` in `.env` are still placeholders (token call returns `invalid_client`, CSIAQ0155E, re-checked this session). So nothing below has been executed against your tenant.
- **Tenant feature flags are unknown.** I can't see the admin console. Flow designer, Adaptive access, Threat detection and others may or may not be on. The plan lists the exact checks (section 3).
- **Verdict scale**

| Verdict | Meaning |
|---|---|
| **YES** | Verify does this natively, and the whole demo can be API-built. |
| **YES, with caveats** | Doable, but depends on a tenant flag, a phone/hardware, or a small simulated component outside Verify. |
| **PARTIAL** | Verify covers part of the ask. The rest needs an external component or isn't API-configurable. Say so to IFC. |
| **NO** | Not demoable on Verify SaaS as written. (None of the 15 land here, but UC-10 and UC-12 come close on specific sub-requirements.) |

---

## 1. Executive summary

### 1.1 Verdict matrix

| UC | Use case | Verdict | Main Verify features | Biggest risk / gap |
|---|---|---|---|---|
| 01 | Self-registration, progressive profiling | **YES, with caveats** | SCIM, email/SMS OTP APIs, Flow designer (models API), token enrichment | No user-form create API found; external Client 360 callout is not available on trial |
| 02 | Passkeys + OTP/TOTP fallback | **YES** | FIDO2 relying-party API, TOTP/OTP factor APIs, access policy v5 | FIDO2 can't use `localhost`; "AAL" is a naming convention we map to policies |
| 03 | Risk-aware account recovery, agent-assisted | **YES, with caveats** | Password-reset APIs, admin reset, session revoke, events API | "Risk signals" need Adaptive access enabled |
| 04 | Multi-device trusted devices, push | **YES, with caveats** | Authenticators API (`/v1.0/authenticators`), push verification | Needs real phones; multi-device per user must be proven early |
| 05 | Adaptive auth and fraud signals | **PARTIAL** | Adaptive access, access policy risk levels, threat intel, events | Needs IBM enablement; custom proprietary signals can't feed the risk model; a scripted attack from a laptop won't look like a real attack |
| 06 | Voicebot: info query + step-up | **YES** | OTP transient verification, push verification, token validation | Voicebot/CCaaS is a stub we build |
| 07 | App-to-voice with no re-auth | **YES** | Token introspection/JWKS, token exchange (STS) | Same stub |
| 08 | SSO and cross-app federation, global logout | **YES, with caveats** | OIDC/SAML apps API, front/back-channel logout, `rplogout` | No session-policy API found for per-persona session lifetimes |
| 09 | API security: mTLS/`private_key_jwt`, token exchange | **YES** | API clients, STS clients, token types, cert-bound and DPoP tokens | mTLS endpoint exposure on SaaS must be tested; DPoP is the fallback |
| 10 | Per-brand login (domains, themes, FR/EN, delegated admin) | **PARTIAL** | Themes API (13 locales), per-app policies, one directory | Custom IdP domains are an IBM sales/vanity-domain item; per-brand scoped admin not found |
| 11 | Legacy IAM migration (JIT + bulk) | **YES, with caveats** | CSV import with hash prefixes, external-authn identity source / Flow designer JIT | Bridge-agent image access or Flow designer needed; legacy store is simulated |
| 12 | ReBAC (brokerage, broker, client, policy) | **PARTIAL** | Token enrichment maps, groups/dynamic groups | **No native ReBAC.** Needs an external engine; token-time callout is not on trial |
| 13 | SCIM broker lifecycle, instant revoke | **YES** | SCIM `/v2.0/Users`, session revoke, grant revoke, webhooks/events | Must measure "time to revoke" and prove existing tokens die |
| 14 | CIBA agent-initiated caller authentication | **YES** | CIBA grant (poll), push or email channel, binding message | Poll mode only today; push needs the Verify app, email does not |
| 15 | PIPEDA consent management | **YES** | DPCM purposes, consents, time-bound, dynamic client registration, events | Access/deletion-request SLA tracking is not native |

**Count:** 7 YES (02, 06, 07, 09, 13, 14, 15), 5 YES-with-caveats (01, 03, 04, 08, 11), 3 PARTIAL (05, 10, 12), 0 NO.

### 1.2 What I'd tell IFC honestly

1. **UC-12 (ReBAC) is the weakest fit.** Verify is the identity provider and token issuer. It is not a relationship-graph authorization engine. We can show Verify carrying identity and (on a paid tenant) enriching tokens from an external engine. We should position the graph itself as a partner/open-source component (e.g. OpenFGA) and be upfront about it.
2. **UC-10 (brands and domains)** is mostly a commercial/provisioning conversation for the custom-domain part. Themes, languages and per-brand policies are fully demoable.
3. **UC-05 (adaptive)** depends on IBM turning features on. A convincing live demo of credential stuffing on a trial may not be possible. A pre-recorded or IBM-assisted run may be the honest answer.
4. **The "everything via API" mandate is realistic for ~90% of the work.** The gaps are specific and listed in section 3.4.

---

## 2. Tooling: how the "API/CLI only" mandate is met

### 2.1 What `verifyctl` actually covers `[CODE]`

I inspected `github.com/ibm-verify/verifyctl` (latest release `v0.0.9-alpha`, i.e. alpha). Commands: `auth` (aliased `login`), `get`, `create`, `replace`, `delete`, `set`, `logs`.

| Resource | create | get | replace | delete |
|---|---|---|---|---|
| user | yes | yes | yes | yes |
| group | yes | yes | yes | yes |
| application | yes | yes | yes | yes |
| api client | yes | yes | yes | yes |
| access policy | yes | yes | yes | yes |
| attribute | yes | yes | yes | yes |
| identity provider | yes | yes | yes | yes |
| identity agent | yes | yes | yes | yes |
| password policy | yes | yes | yes | yes |
| personal / signer cert | yes | yes | yes | yes |
| themes | `set` | `get` | `set` | n/a |
| logs (events) | `logs` | n/a | n/a | n/a |

**Not covered by `verifyctl`:** Flow designer models, user forms, privacy/consent (DPCM), FIDO2 relying parties, factor enrollments, authenticators/devices, sessions, grants, STS clients and token types, webhooks, dynamic client registration, SCIM bulk/PATCH specifics.

**Conclusion:** `verifyctl` is a convenience for the common objects. It is **not** enough on its own. The primary mechanism is **Node scripts calling the REST API**, built on this repo's existing helpers in [`functions.js`](functions.js) (≈45 helpers already: token, OTP, SCIM, policies, apps, DPCM, themes). `verifyctl` is optional where it saves time (e.g. `verifyctl logs` during demos). It requires Go to build; there is no Homebrew package I could confirm, and Go is not installed on this machine, so I'd download a release binary. `[CODE]`

### 2.2 Proposed repo layout (to be built, nothing created yet)

```
demo/
  README.md                    # how to run everything
  lib/verify.js                # token cache + typed request wrapper over functions.js
  lib/idempotent.js            # create-or-update helpers, "ifc-demo-" naming/tagging
  config/                      # declarative JSON: apps, policies, purposes, themes, flows
  00-bootstrap.js              # creates privileged API client scopes check, base attrs, groups, personas
  uc01-registration/ ... uc15-consent/    # each: setup.js, run.js, verify.js, teardown.js, README.md
  stubs/                       # voicebot-ccaas, legacy-auth-store, client360, rules-engine, ops-queue
  teardown-all.js              # deletes everything tagged ifc-demo-*
package.json scripts: demo:setup, demo:ucNN, demo:verify, demo:teardown
```

Rules every script follows:
- **Idempotent** (safe to re-run), all objects named `ifc-demo-<uc>-<thing>` so `teardown-all` can find them.
- **Declarative config in `config/`**, not hard-coded in scripts.
- **Every script prints the evidence an IFC reviewer would want** (HTTP status, request id, timestamps) and writes it to `demo/out/ucNN.json`.
- **Admin-console screens are only for showing the result.** Each README lists "what to open on screen after the script finishes".

### 2.3 Auth model for all scripts

Per `[DOCS]` `api-access-privileged-api-clients` and the existing `getAccessToken` pattern: a **privileged API client** uses `client_credentials` against `POST https://<tenant>/v1.0/endpoint/default/token`. Its power is its **entitlements**, set at client creation. Section 3.1 lists the ones needed.

---

## 3. Prerequisites (do these before any build)

### 3.1 Blocker B1: a working privileged API client

`.env` currently has placeholders, so every privileged call fails. Someone must create a privileged API client **once** (this is the only unavoidable console step, because you need a credential to bootstrap everything else; alternative: IBM can provide it, or the tenant admin can use `verifyctl auth` with the device flow). It needs these entitlements, taken from the API reference `[API]`:

| Area | Entitlements |
|---|---|
| Users/groups/SCIM | `manageUsers` (or `manageUserGroups`), `resetPasswordAnyUser`, `updateAnyUser`, `manageDevicesAnyUser` |
| Sessions/tokens | `manageLoginSessions`, `revokeAllSessions`, `listSessions`, `manageOidcGrants` |
| Applications | `manageAppAccessAdmin` |
| Policies | `manageAccessPolicies` |
| Factors/FIDO/OTP | `manageEnrollMFAMethodAnyUser`, `authnAnyUser`, `manageMFAMethods`, `manageAuthenticatorsAnyUser`, `readAuthenticatorsAnyUser`, `manageAuthenticatorsConfig` |
| Flow designer | `manageFlows`, `readFlows` |
| Branding | `manageTemplates` |
| Privacy/DPCM | `managePurpose`, `managePrivacyPolicy`, `managePrivacyConsent`, `createPrivacyConsent`, `readPrivacyConsent` |
| Token exchange / STS | `manageSTSClients`, `manageOidcDynamicClient` |
| Identity sources / agents | `manageIdentitySources`, `manageExternalAgents` |
| Attributes | `manageAttributes` |
| Reports/events | `manageReports` / `readReports` |
| Webhooks | the webhook-management entitlement (name not shown in the pages I read; confirm) |

### 3.2 Blockers B2 and B3 (small, already known)

- **B2:** register `http://localhost:3000/oauth/callback` on the existing OIDC application (error CSIAQ0167E today). This can be done by API: `PUT /v1.0/applications/{id}` `[API]`.
- **B3:** remove the trailing slash from `OIDC_CI_BASE_URI` in `.env`. Today `app.js` builds a double-slash issuer and `passport-openidconnect@0.1.1` enforces `iss` equality. Say the word and I'll fix it.

### 3.3 Tenant checks to run first (script `demo/00-bootstrap.js --probe`)

Each is a harmless GET; the result decides several verdicts:

| Probe | Call | Decides |
|---|---|---|
| Flow designer on? | `GET /v1.0/config/models` | UC-01, 05, 08, 11 flow approaches |
| Adaptive access on? | try creating a policy rule with adaptive risk levels (`POST /v5.0/policyvault/accesspolicy`) | UC-05, 03 |
| Threat detection on? | `GET /v1.0/itdr/configurations/default` | UC-05 |
| Custom attribute functions with HTTP callouts? | `GET /v1.0/attributefunctions`, then try a rule using `hc.GetAsJson` | UC-01, 12 |
| Dynamic client registration enabled? | `POST /oauth2/register` | UC-15 |
| Authenticator clients present / push works? | `GET /v1.0/authenticators/discovery` | UC-04, 06, 14 |
| SMS quota? | `GET /config/v2.0/factors/smsotp`, then a test send | UC-02, 06 |
| mTLS reachable? | discovery has **no** `mtls_endpoint_aliases` `[LIVE]`; test `tls_client_auth` | UC-09 |
| Sub-tenants? | `GET /v1.0/identitysources/subtenants/{id}` | UC-10 |

### 3.4 Things I could not find an API for (be explicit with IFC)

Searched the 781-operation API reference index by name `[API]`:

| Capability | Result | Impact |
|---|---|---|
| Create/edit **User forms** (Flow designer `UserForm` task, `formId`) | No operation found | UC-01. Workaround: build the form in the demo app, or import a pre-made flow that references an existing form |
| **Session policy** (lifetime, idle timeout per persona) | No operation found | UC-08. Workaround: per-app access policies and token lifetimes |
| **Custom/vanity domain** configuration | Not in the API; docs say "via sales" `[DOCS]` | UC-10 |
| **Delegated admin scoped to a brand/subset of users** | Admin entitlements can be granted to users/groups `[API]`, but scoping to a subset isn't documented | UC-10 |
| **ReBAC / relationship graph** | None | UC-12 |
| **JIT migration with arbitrary legacy hash verification** inside Verify | Not native; done through external-authn agent or a Flow Function `[DOCS]` | UC-11 |

---

## 4. Per-use-case plan

Each section: **Verdict, what Verify provides, what we build (API/CLI only), the demo script, validation, risks and IBM asks.**

---

### UC-01: Self-service registration and progressive profiling (B2C)

**Verdict: YES, with caveats**

**Provided natively**
- SCIM user creation: `POST /v2.0/Users` `[API]`. Email/SMS OTP verification: `POST /v2.0/factors/emailotp/transient/verifications` and the `smsotp` equivalent, then the matching `attempt…verification` call `[API]`.
- Flow designer: create, update, export and publish flow models via API: `POST /v1.0/config/models` (multipart: `reference`, `name`, `description`, `model` DSL), `PUT …/{reference}`, `POST …/{reference}/publish`, `GET …/{reference}/export` `[API]`. IBM publishes importable registration flows (account claiming, risk evaluation, identity proofing) in `verify-saas-resources` `[CODE]`. Flow task types seen: `Start, Page, UserForm, CreateUser, FetchUser, ConditionPoint, Function, Redirect, IdentityProofing, End` `[CODE]`.
- A flow `Function` task can make HTTP calls to external services (`hc.Post(...)` appears in IBM's Aadhaar flow) `[CODE]`. This is the hook for IFC's "callouts to external registration APIs".
- Token enrichment: per-endpoint maps on the OIDC app (`tokenResponseMap`, `userInfoResponseMap`, `introspectResponseMap`, each entry can reference a custom rule) `[API]`.

**Gaps**
- User forms cannot be created via API (section 3.4). A flow's `UserForm` task needs an existing `formId`.
- The tenant-side HTTP callout in attribute rules (`hc.GetAsJson`) is **not available to Trial instances** `[DOCS]`. The Flow `Function` HTTP callout may differ; probe it.
- "Multi-tenancy" is addressed under UC-10.

**Build (API-only), two tracks**

*Track A (safe, works on any tenant): app-driven registration, which this repo already half-does.*
1. `demo/uc01-registration/setup.js`: create custom attributes (`POST /v1.0/attributes`) for progressive-profiling fields (e.g. `preferred_language`, `postal_code`, `has_vehicle`, `client360_id`); create a group `ifc-demo-customers`.
2. Registration step 1 (minimal data = email only): app calls email-OTP transient verification, then `POST /v2.0/Users` with `userName=email` only.
3. Progressive profiling on a later login: after OIDC login, app reads the user (`GET /v2.0/Users/{id}`), sees `postal_code` empty and prompts for it; saves with `PATCH /v2.0/Users/{id}`.
4. Duplicate detection: before create, `GET /v2.0/Users?filter=emails.value eq "<email>"` (SCIM filter) `[API]`. On a match, return "account exists, sign in or recover". Also demo the account-claiming pattern from IBM's flow `[CODE]`.
5. Client 360 stub (`stubs/client360`): tiny Express service returning `{client360_id, segments}` for an email. Called by the registration step (server-side), result stored in the custom attribute. Tokens then carry it through attribute mapping with **no runtime callout**, which is exactly IFC's "enrich tokens without latency" requirement.

*Track B (showpiece, needs Flow designer enabled): same journey as a Verify flow.*
1. `demo/uc01-registration/flow.json` derived from IBM's `user_registration_with_account_claiming.json`, with the Function task calling the Client 360 stub for the external registration API callout.
2. Script: `POST /v1.0/config/models` then `POST …/publish`. `formId` placeholders replaced with pre-existing form ids (the one console dependency; if forms can't be pre-made, use Track A).
3. Pages/themes for the flow pushed with `POST /v1.0/branding/themes` `[API]`.

**Demo script**
1. `npm run demo:uc01:setup`.
2. Register with email only: show a verified, working account created in seconds.
3. Log in the next day (script simulates): app asks for postal code only; save.
4. Attempt registering the same email: duplicate blocked with a helpful path.
5. Decode the issued token: shows `client360_id` claim.

**Validation:** SCIM read-back shows attributes; duplicate attempt returns the expected error; token contains the claim; timing log shows token issuance latency with no external call.

**Risks / asks:** confirm Flow designer enablement; confirm whether Function-task HTTP callouts work on trial; ask IBM about a forms API.

---

### UC-02: Passkeys / FIDO2 with OTP and TOTP fallback

**Verdict: YES**

**Provided natively**
- Create a custom FIDO2 relying party: `POST /v2.0/factors/fido2/relyingparties` with `{origin}` `[DOCS][API]`. Registration: `…/{id}/attestation/options` then `…/attestation/result`. Authentication: `…/{id}/assertion/options` then `…/assertion/result` `[API]`.
- IBM publishes a working sample: `verify-webauthn-passkey-sample-web` `[CODE]`, plus passkey-IFA flow in `verify-saas-resources`.
- TOTP: `POST /v2.0/factors/totp` (returns QR); email/SMS OTP via the transient verification APIs; list a user's enrollments `GET /v2.0/factors` `[API]`.
- Access policy v5 (`POST /v5.0/policyvault/accesspolicy`) selects which factors satisfy which app/transaction.

**Gaps and honest notes**
- **`localhost` cannot be a FIDO relying-party origin** `[DOCS]`. Use a hostname (e.g. `ifc-demo.local` in `/etc/hosts` or a tunnel). The demo app currently runs on `localhost:3000`, so the passkey demo needs a different origin; plan for that.
- **"AAL" is not a Verify object.** We implement "required assurance level per app or transaction" as **named access policies** (e.g. `ifc-demo-aal1-password`, `aal2-otp`, `aal3-passkey`) and attach them to apps. The console shows the mapping. Say "mapped to policies", not "native AAL".
- "BYO SMS/email gateways": Verify supports generic external MFA providers driven by a webhook (`POST /config/v1.0/mfaproviders`, type `generic`) and authenticated email domains (`POST /config/v1.0/email-domain-auth`) `[API]`. Confirm that this covers SMS delivery for IFC's gateway; I'd mark SMS-gateway replacement as **to be verified**.
- Enrollment nudging: implement app-side (check `GET /v2.0/factors`, prompt if no passkey). Verify's policy-based enrollment guide covers part of it `[DOCS]` (`policy-based-usc-factors-enrollment`).

**Build (API-only)**
1. `setup.js`: create FIDO RP for the demo hostname; create three access policies; create three OIDC apps (low/medium/high value), each bound to a different policy; enable TOTP/email OTP config via `/config/v2.0/factors/*`.
2. App: adapt the IBM passkey sample into `routes/passkey.js` (register + authenticate), reusing `functions.js` for tokens.
3. Fallback path: policy allows `[fido2, totp, emailotp]` for AAL2, only `[fido2]` for AAL3.

**Demo script:** register a passkey; sign in with it; open a high-assurance app and show it refuses password+OTP; open a medium app and show TOTP accepted; deliberately cancel the passkey prompt to show fallback; attempt to re-register the same authenticator (duplicate) and show the response.

**Validation:** `GET /v2.0/factors` shows the enrollment; events API shows the factor used; the policy mapping is printed by the script.

**Risks / asks:** hostname/tunnel for WebAuthn; confirm SMS gateway replacement path; SMS quota on trial.

---

### UC-03: Risk-aware account recovery, agent-assisted

**Verdict: YES, with caveats**

**Provided natively**
- Self-service password reset APIs: `resetpassword`, `resetpasswordvalidator`, `resetpasswordcomplete` (v1.0 usc endpoints) and username recovery `[API]`.
- Admin/agent reset: `PATCH /v2.0/Users/{id}/passwordResetter` (optional notification to the user) `[API]`.
- End sessions on reset: `DELETE /v1.0/auth/sessions/{userId}` (entitlements `manageLoginSessions` or `revokeAllSessions`) `[API]`.
- Audit record: `GET /v1.0/events` (management, SSO, authentication events) `[API]`.
- Risk-aware step-up: access policy with adaptive risk levels `[DOCS]`.

**Gaps:** "show risk signals" requires Adaptive access to be enabled. Without it, we can only show *contextual* signals (IP, geo, device) from events, not an AI risk score.

**Build**
1. `setup.js`: policy for the recovery journey (OTP to verified channel; require stronger factor if risk is high).
2. Customer path: script drives the reset APIs end to end: request, validator, OTP, complete.
3. Agent console: a small page in the demo app (`views/agent/*`, route `/agent`) using the agent's privileged token. Actions: look up user, trigger `passwordResetter`, call session revoke, show the last 10 events for that user.
4. On reset: script calls `DELETE sessions` and optionally revokes grants; sends notification (reset notification option, or webhook to a stub).
5. Evidence: `demo/out/uc03.json` lists event ids.

**Demo script:** customer starts recovery from an unfamiliar context (second browser profile/IP), show the step-up; then the agent-assisted variant; open the event log; show old session killed.

**Risks / asks:** Adaptive access enablement for the risk story.

---

### UC-04: Trusted devices (multiple), push, self-service revoke

**Verdict: YES, with caveats**

**Provided natively `[API]`**
- Authenticator registrations: `POST /v1.0/authenticators/initiation` returns a QR for IBM Verify or a custom SDK app; `GET /v1.0/authenticators` (list/search/filter), `GET/PATCH/DELETE /v1.0/authenticators/{id}`.
- Push transaction: `POST /v1.0/authenticators/{id}/verifications` (message, origin IP/user agent, push notification text). Remains PENDING until approved/denied/cancelled.
- Authenticator clients (for custom apps): `POST /v1.0/authenticators/clients` to create; `GET /v1.0/authenticators/discovery` to list what is available.
- Self-service revoke: `DELETE /v1.0/authenticators/{id}` with the "manage own" entitlement.
- Location: verification `transactionData.originIpAddress`; CIBA `proximityCheck` (country/state/city) `[DOCS]`.

**Gaps and honesty**
- **Needs a real phone** (or two) with the IBM Verify app. The two-trusted-devices demo means two registrations for one user. The docs I read don't state a per-user maximum; `GET /v1.0/authenticators` returning a list implies multiple, but this is `[INFER]`. **Test first.** If only one is allowed, say so to IFC, as their PDF explicitly allows.
- Custom branded authenticator via the Verify SDK needs a Firebase/APNs setup; that's a separate mobile build, so I'd keep this demo on the stock IBM Verify app.

**Build**
1. `setup.js`: create demo user; call `POST /v1.0/authenticators/initiation` and print the QR as a PNG in `demo/out/` for scanning (twice, two phones).
2. `run.js`: list authenticators; send a push verification to device A, then to device B; show approve/deny result polling `GET /v1.0/authenticators/{id}/verifications/{txrnId}`.
3. Self-service revoke: user token calls `DELETE /v1.0/authenticators/{id}`; show device B stops receiving pushes.

**Demo script:** register two phones; push to each; revoke one; push again (fails for the revoked one).

---

### UC-05: Risk-based adaptive authentication and fraud signals

**Verdict: PARTIAL**

**Provided natively**
- Adaptive access (Trusteer-backed) evaluates risk from user/device/activity/environment/behaviour; access policies take actions for Very High/High/Medium/Low `[DOCS]`.
- Native-app adaptive SDK (`adaptive-browser-sdk`, `adaptive-proxy-sdk-javascript`) and SSO adaptive access `[DOCS][CODE]`.
- Threat Analyzer for credential stuffing, brute force and login anomalies across all tenants; **must be enabled by IBM Support** `[DOCS]`. Config API: `/v1.0/itdr/configurations` `[API]`.
- Events API for the admin view of decisions: `GET /v1.0/events` with filters `[API]`.

**What does not work as the PDF imagines**
1. **Custom proprietary signals:** there is no documented way to feed IFC's own signals into the Trusteer risk model. What we *can* do: bring signals in as **user attributes** or via a **Flow `Function`** and let access-policy conditions act on them. That is rules-based, not part of the ML score. `[INFER]`
2. **Credential-stuffing simulation:** adaptive risk depends on browser/device collection (the SDK) and on cross-tenant threat intel. A script hammering the token endpoint from one laptop won't look like a real distributed attack. Using proxy IPs is possible but unreliable. `[INFER]`
3. Needs Adaptive access and Threat detection enabled by IBM.

**Build (if enabled)**
1. `setup.js`: policy with adaptive levels (low = allow, medium = OTP, high = deny); a second policy keyed on an attribute-based signal (`fraud_flag=true` set by a stub fraud engine via SCIM PATCH).
2. `run.js`: login attempts through the Adaptive Browser SDK flow with varied user agents/IPs; then pull `GET /v1.0/events` and print decision + reasons.
3. Stub fraud engine (`stubs/fraud-signals`) simulates IFC's proprietary signals and sets the attribute; policy reacts.

**Recommendation:** ask IBM to run/assist this one, or present it with a recorded session, and be explicit that proprietary signals act as **policy inputs**, not model features.

---

### UC-06: Voicebot (CCaaS) information query and simple transactions

**Verdict: YES**

**Provided natively**
- Generate/validate OTP: `POST /v2.0/factors/smsotp/transient/verifications` (or email) then `POST …/{id}` attempt with the OTP `[API]`.
- Push approval to the app: `POST /v1.0/authenticators/{id}/verifications` `[API]`, or CIBA (UC-14) for the same pattern.
- Passkey step-up: assertion options/result APIs (UC-02).
- IBM documents a chatbot integration pattern with exactly these calls (lookup user, send OTP, verify OTP, reset) `[DOCS]` (`chat-bot-integration-patterns`).

**Build**
1. `stubs/voicebot-ccaas`: Express service exposing CCaaS-style endpoints `/identify`, `/challenge`, `/verify`, `/transaction`. It plays the CCaaS side; it calls Verify with an API client. No real telephony needed. A CLI "caller" script walks the conversation.
2. Flow: caller gives account id (lookup via SCIM filter), bot sends OTP (email in trial if no SMS quota), caller reads digits, bot verifies, then returns policy info from a mock policy API. For a sensitive step (e.g. change address), bot demands step-up: in-app push approval, in-app TOTP code, or passkey.
3. Output: transcript and the Verify transaction ids to `demo/out/uc06.json`.

**Demo script:** run the CLI caller; show OTP path, then a sensitive action that triggers push approval on the phone.

**Risks:** SMS quota on trial; use email OTP if needed, and state that SMS is a configuration difference.

---

### UC-07: App-to-voice transfer without re-authentication

**Verdict: YES**

**Provided natively**
- The CCaaS validates the app's token: **introspection** (`POST /v1.0/endpoint/default/introspect` or `/oauth2/introspect`) or **JWT validation** via the JWKS `[API]`.
- **Token exchange** (RFC 8693) lets the app's token be traded for a channel-specific token: STS client `POST /v1.0/sts/oauth/clients`, custom token types `POST /v1.0/sts/tokentypes`; grant `urn:ietf:params:oauth:grant-type:token-exchange` is advertised `[LIVE]`.
- Reverse bridge (voice to web): bearer token to browser session via `POST /v1.0/auth/session` `[API]`.

**Build**
1. `setup.js`: STS client `ifc-demo-ccaas` allowed to exchange `subject_token` (app access token) for a short-lived `voice-channel` token. **Corrected by UC-07 `[LIVE]`:** `audience` is ignored; the token's `aud` is the STS client id.
2. Mobile/web app simulated by the demo app: user logs in, app calls the voice stub's `/handoff` with its access token.
3. Voice stub introspects/exchanges; skips OTP and answers account questions; policy decides which actions still need step-up.

**Demo script:** log in to the app, click "Call us", the voice stub already knows the caller; attempt a sensitive action and show step-up still enforced.

**Validation:** introspection response (`active:true`, `sub`, `exp`) printed; exchange shows the new token's `sub`, lifetime and `grant_type`. **Corrected by UC-07 `[LIVE]`:** no `act` claim is returned. See `DEMO-BUILD-GUIDE.md` UC-07.

---

### UC-08: SSO and cross-app federation, global logout

**Verdict: YES, with caveats**

**Provided natively**
- Create multiple OIDC (and SAML) apps by API: `POST /v1.0/applications` `[API]`. OIDC logout settings per app: `logoutOption` (`none`/`front_channel`/`back_channel`), `logoutURI`, `logoutRedirectURIs`, `sessionRequired` `[API]`. RP-initiated logout at `/oauth2/rplogout`; discovery advertises both front- and back-channel logout `[LIVE]`.
- Session visibility/revocation: `GET /v1.0/auth/sessions/{userId}`, `DELETE …` `[API]`.

**Gaps:** I found no API/guide for **session policy** (idle/absolute timeouts per persona) `[DOCS]` searched. Broker vs B2C distinctions can be shown through **different access policies and token lifetimes** per app (`accessTokenExpiry`, `refreshTokenExpiry` on the app `[API]`), but "session policy" as a tenant object is unverified.

**Build**
1. `setup.js`: create 3 relying-party apps (Express stubs `stubs/rp-a`, `rp-b`, `rp-c` on ports 4001-4003), each with back-channel logout URI; create persona groups `brokers`, `consumers`; two access policies (brokers: MFA always; consumers: adaptive/lighter) bound per app/persona.
2. `run.js`: log in once at RP-A (browser or headless), open RP-B and RP-C with no prompt; trigger logout at RP-A; confirm RP-B/C received back-channel logout and their sessions are gone.
3. Print session list before/after via the sessions API.

**Demo script:** sign in once, open three apps, log out in one, refresh the others: all signed out.

**Risks / asks:** confirm session-policy configuration path with IBM; back-channel logout receivers must be reachable from the SaaS tenant (tunnel such as a public hostname for the stubs).

---

### UC-09: API security (client credentials, mTLS / `private_key_jwt`, token exchange, key lifecycle)

**Verdict: YES**

**Provided natively**
- Machine clients: API clients (`POST /v1.0/apiclients`) and OIDC apps with client_credentials `[API]`.
- Client authentication methods advertised: `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `tls_client_auth` `[LIVE]`. App settings: `clientAuthMethod`, `allowedClientAssertionVerificationKeys`, `validateClientAssertionJti`, `tlsClientAuthAttribute(+Value)`, `certificateBoundAccessTokens`, `dpopBoundAccessTokens`, `jwksUri` `[API]`.
- Token formats/lifetimes per app; introspection `[API]`.
- **Token exchange / on-behalf-of:** STS client with `tokenExchangeSettings` (`subjectTokenTypes`, `actorTokenTypes`, `requestedTokenTypes`, `actorTokenRequired`, `actorCriteria` as a CEL expression) `[API]`; delegation vs impersonation explained in `[DOCS]` `oauth-20-token-exchange`.
- **Key lifecycle:** `POST /v2.0/clients/{id}/secrets` (rotate), `rotatedSecrets` (overlap window), JWKS URI keys `[API]`; personal/signer certificate APIs `[API]`.
- DPoP as a sender-constrained alternative, with IBM sample code `[DOCS][CODE]`.

**Gaps:** the discovery document has **no `mtls_endpoint_aliases`** `[LIVE]`, so I can't confirm where a client presents its certificate on the SaaS edge. Docs describe cert-bound tokens working on the tenant, so it's likely supported, but **must be tested**. If it doesn't work on the trial edge, demo `private_key_jwt` + DPoP and flag mTLS as an IBM confirmation.

**Build**
1. `setup.js`: generate an RSA/EC key pair with `openssl` (local), build a JWKS, create `ifc-demo-m2m-pkjwt` app (`clientAuthMethod=private_key_jwt`) and `ifc-demo-m2m-mtls` app (`tls_client_auth`, with a locally generated client cert).
2. `run.js`: sign a client assertion JWT, get a scoped token; call a mock IFC API (stub) that validates via introspection/JWKS; show wrong key rejected; rotate a secret with overlap and prove both work then only the new one.
3. OBO: STS client `ifc-demo-partner`; policyholder token as `subject_token`, partner token as `actor_token`; `actorCriteria` restricts to allowed partners. Show resulting token with `act` claim and a denied non-partner actor.

**Demo script:** machine token with `private_key_jwt`; bad key fails; scope limits; token exchange for a partner acting for a policyholder; key rotation.

---

### UC-10: Customizable login per brand

**Verdict: PARTIAL**

**Provided natively**
- **Themes:** register via `POST /v1.0/branding/themes` (multipart zip, `configuration`), list/update/delete; templates per locale `[API]`. This repo already ships a 596-file theme zip with 13 locales (including `fr`) and a CLI `ci-theme/manage-theme.js` `[CODE]`. French/English are supported.
- **Per-brand policies and apps:** each brand = its own app + access policy + theme id `[API]`.
- **One account across brands:** a single Cloud Directory is shared by definition.
- The app already passes `themeId` at login (`app.js`) `[CODE]`.

**Gaps (be upfront)**
1. **Custom IdP domains per brand** (e.g. `login.brandA.ca`): not configurable via API; docs say vanity domains go through IBM sales `[DOCS]`. Multiple custom domains on one tenant is a commercial/feasibility question for IBM.
2. **Delegated admin per brand (RBAC scoped to a brand's apps/users):** admin entitlements can be granted to users and groups (`grantrevokeadminentitlementtogroup`) `[API]`, but I found nothing that *scopes* them to one brand. `role-delegation` is only for certification campaigns `[DOCS]`.
3. **Multi-tenancy:** there are `identitysources/subtenants/{subtenantUuid}` endpoints `[API]` suggesting a sub-tenant construct, but I found no guide for it. **Ask IBM** whether sub-tenants provide per-brand isolated admin; treat as unproven.

**Build**
1. `setup.js`: create two themes (`ifc-demo-brandA`, `ifc-demo-brandB`) from the existing theme with different logos/colours and EN/FR strings; two apps, two policies (A: password+OTP, B: passkey-first); both in the same directory.
2. `run.js`: open each brand's login URL with its `themeId` (both on the same tenant hostname); show different look, language, factors.
3. Demonstrate "one account across brands": same user signs in to both.
4. Admin: create a group `brandA-admins` with limited admin entitlements; show what it can and cannot do (documents the scoping gap honestly).

**Demo script:** side-by-side login screens; FR toggle; same user, both brands. State the custom-domain and scoped-admin items as "confirmed with IBM" or "roadmap/commercial" depending on IBM's answer.

---

### UC-11: Legacy IAM migration (JIT on first login + bulk)

**Verdict: YES, with caveats**

**Provided natively**
- **Bulk:** CSV import API `POST /v2.0/CSV/importUsers`, with `GET /v2.0/CSV/headerNames`; supports plaintext or **pre-hashed passwords** by prefixing `{TYPE}` (e.g. `{SSHA256}`); `notifyType=NONE` suppresses emails; flag to avoid forced reset `[API][DOCS]`. SCIM bulk also exists.
- **JIT, option 1: external-authn identity source** (Verify Bridge agent + an "external agent" web service with a documented contract: `password-verify` / `password-change`, returns attributes and groups for JITP; docs also cover "Provision password migration" to copy the credential into Cloud Directory on first successful login) `[DOCS]` (`developing-external-agent-ws`, `flow-designer-ldap_to_okta_migration`). APIs: `POST /config/v1.0/onpremagents`, `POST /v2.0/identitysources`.
- **JIT, option 2: Flow designer.** IBM's `ldap_to_okta_migration` flow shows a `FetchUser` + `Function` + `Redirect` pattern keyed on a "migrated" attribute `[CODE]`. A Function can `hc.Post` to a legacy verification service, then a `CreateUser` task writes the user with the verified password.
- **Rollback:** keep the legacy store authoritative until cutover; the "migrated" flag lets us route a user back; bulk import is reversible by user delete (`DELETE /v2.0/Users/{id}`).

**Gaps:** the Verify Bridge image comes from IBM Container Registry (needs entitlement/login), and this machine has Podman, not Docker `[LIVE]`. Option 2 needs Flow designer. One of the two must be available. The legacy store itself is simulated.

**Build**
1. `stubs/legacy-auth-store`: Express service with sample users and a legacy hash (e.g. salted SHA-1/SSHA, which IFC can name), implementing the `password-verify` contract.
2. Bulk: `run-bulk.js` generates a CSV with `{SSHA256}`-style prefixes, calls `importUsers`, then proves login works with the *original* password.
3. JIT (option 1): create the agent configuration and identity source by API, enable identity linking + JITP + password migration, run the bridge with Podman. Or (option 2): import the flow via `POST /v1.0/config/models`.
4. Show the user doesn't exist in Verify, logs in once with the legacy password, then exists and authenticates locally without touching the legacy store (stop the stub to prove it).

**Demo script:** first login migrates; second login works with the legacy store switched off; bulk-import example with reset; rollback explanation.

**Asks:** confirm which JIT option IBM recommends; ask about hash algorithms supported by `{TYPE}` prefixes (the docs show `{SSHA256}` and the repo's helper uses `{SHA256}`; get the full list for IFC's legacy algorithm). Also request a reference for a prior financial-services migration (the PDF asks for it).

---

### UC-12: Relationship-based authorization (ReBAC)

**Verdict: PARTIAL (Verify is the identity layer, not the graph)**

**What Verify provides**
- Identity, groups and **dynamic groups** (rule-based membership; reevaluate API) `[API]`, entitlements to apps, attribute mapping to tokens.
- Token enrichment maps on the OIDC app (`tokenResponseMap`, `introspectResponseMap`, `enrichClientCredentialsFlow`) that run **custom rules** `[API]`.
- IFC's requirement ("IdP calls the external rules engine during token minting to write claims") maps to an attribute function with an HTTP callout (`hc.GetAsJson`) `[DOCS]`, which is **not available on Trial** `[DOCS]`.

**What it does not provide:** a relationship graph, inherited-access evaluation, or "list all resources this user can access." I found no documentation for ReBAC/fine-grained authorization in the docs hub `[DOCS]` (keyword search across ~160 guides).

**Honest architecture** (what I'd present)
- External authorization service (e.g. **OpenFGA** or SpiceDB, run locally with Podman) holds the model: brokerage → broker → client → policy.
- Verify authenticates and issues tokens with `sub` and (optionally) enriched claims.
- Resource server asks the engine at **request time** with the token's `sub`. Reassigning a broker takes effect instantly with no token reissue, which is *better* than claims baked into tokens.
- On a paid tenant, add the token-time callout to mint coarse claims (e.g. `brokerage_id`) for convenience.

**Build**
1. `stubs/rules-engine`: OpenFGA container + `model.fga` + seed script (brokerages, brokers, clients, policies).
2. `setup.js`: create demo users/groups in Verify via SCIM; mirror identities into the engine.
3. `run.js`: login via OIDC, call a mock "Policy API" gateway that checks `check(user, viewer, policy)` against OpenFGA; reassign a broker to another brokerage via a tuple update and re-check; call `ListObjects` for "all resources this user can access."
4. Optional (paid tenant): attribute function callout enriching a token; probe first.

**Recommendation:** present UC-12 as "Verify + external ReBAC engine," and ask IBM whether there is a roadmap or partner pattern. Do not claim native ReBAC.

---

### UC-13: Broker lifecycle via SCIM 2.0 with immediate revocation

**Verdict: YES**

**Provided natively `[API]`**
- SCIM: `POST /v2.0/Users`, `PATCH /v2.0/Users/{id}` (SCIM PatchOp; the existing helper `disableUser.go` in IBM's repo disables via a password patch, and `active` can be tested as the standard route `[INFER]`), `DELETE`.
- Immediate session kill: `DELETE /v1.0/auth/sessions/{userId}` `[API]`.
- Token/grant kill: `DELETE /v2.0/appgrants/app/{appId}/grant/{gid}`; token revoke `POST /v1.0/endpoint/default/revoke`; IBM's `revokeTokens.go` sample uses `DELETE /v1.0/grants/{id}` `[CODE][API]`.
- Events/webhooks: `GET /v1.0/events`; webhook CRUD `POST /config/v1.0/webhooks/` with retry and dead-letter queue endpoints (`webhooklistdeadletters`, `webhookflushdeadletter`) `[API]`. That maps neatly onto "errors go to an ops queue."

**Build**
1. `stubs/ops-queue`: webhook receiver that logs successes and failures; Verify webhook created via API for user/session events.
2. `run.js`:
   1. SCIM create broker `B-123`; broker logs in at an RP stub (session + token issued).
   2. SCIM deactivate (PATCH). Start a timer.
   3. Script also calls session revoke + grant revoke.
   4. Poll: broker's token introspection returns `active:false`; RP back-channel logout (UC-08) fires; resource stub returns 401.
   5. Record time deltas in `demo/out/uc13.json` (target: seconds).
3. Failure path: attempt to deactivate a non-existent id; show the error landing in the ops-queue stub / dead-letter list.

**Validation:** report "event timestamp, revoke timestamp, first-401 timestamp" and the webhook delivery logs.

**Key thing to prove (don't assume):** that **disabling the user alone** kills existing access tokens. If not, the revoke calls are part of the mandatory sequence and IFC's source system must call them. Test early.

---

### UC-14: Agent-initiated authentication of the caller via CIBA

**Verdict: YES**

**Provided natively `[DOCS][API][LIVE]`**
- CIBA is live on the tenant: `backchannel_authentication_endpoint = https://trialverify.verify.ibm.com/oauth2/ciba`, grant `urn:openid:params:grant-type:ciba` advertised.
- **Poll mode only today** (ping "planned"). User approval via **push to IBM Verify app** or **email link**. `login_hint` (username or `{"username","realm"}`), `binding_message`, `requested_expiry`, `proximityCheck` (country/state/city) `[DOCS]`.
- Create the CIBA app by API: `POST /v1.0/applications` with `additionalConfig.backchannelSettings` and `grantTypes.ciba=true` `[DOCS]` (exact JSON given in the guide).
- Agent actions: `PATCH /v2.0/Users/{id}` (e.g. unlock/enable), `passwordResetter`; audit: binding message is attached to SSO audit events, readable via `GET /v1.0/events` `[DOCS][API]`.

**Build**
1. `setup.js`: create app `ifc-demo-agent-console` with CIBA enabled, channels `["push","email"]` (email-only if no phone), proximity `disabled` (optional `country` demo).
2. `stubs/agent-console` (or `views/agent` in the demo app): agent types a caller's username; backend POSTs to `/oauth2/ciba` with `binding_message="IFC agent #482 verifying your identity"`; polls `/oauth2/token` with the `auth_req_id`; shows `authorization_pending` until approval; on success marks the caller "verified" and unlocks agent actions.
3. After verification, agent clicks "Unlock account" which patches the user; audit tab queries the events API.

**Demo script:** agent starts verification; customer approves on phone (or by email link on a laptop); console flips to verified; agent unlocks account; open audit log showing the binding message and agent id.

**Caveats:** email channel needs no phone, push does. The token returned authorizes only what the CIBA client's scopes allow; keep scopes minimal.

---

### UC-15: Consent management (PIPEDA)

**Verdict: YES**

**Provided natively `[API][DOCS]`**
- DPCM objects: purposes (`POST /config/v1.0/privacy/purposes`, with `defaultConsentDuration`, `attributes[]`, `accessTypes`, `retentionPeriod`), rules (`POST /config/v1.0/privacy/rules`), consent records (`GET /config/v1.0/privacy/consents`, bulk `PATCH /v1.0/privacy/consents` with `startTime`/`endTime`/`state`), delete consent, consent providers.
- **Time-bound consent with renewal:** `endTime` on records plus purpose default duration.
- **Consent enforced at login to restrict scopes/claims:** OIDC app `consentAction`, `requireConsentAttributeMapClaimNames`, and the external-consent-provider option (needs `CI-131365` enabled) `[API]`.
- **Dynamic client registration with scopes:** `POST /oauth2/register` (+ GET/PUT/DELETE `/oauth2/register/{id}`) `[API]`; requires `manageOidcDynamicClient` if bearer-protected.
- Audit export: consents + events APIs; pagination and search `[API]`.
- This repo already integrates DPCM (`lib/dpcm/dpcmClient.js`, `routes/consent.js`) `[CODE]`.

**Gaps:** access/deletion **request SLAs** (DSAR clocks) aren't a native workflow. Model as a thin ticket/SLA stub (`stubs/dsar`) that records request time, calls `DELETE consent`/user APIs, and stamps completion. Be clear it's an integration, not a Verify feature.

**Build**
1. `setup.js`: define attributes (`email`, `postal_code`, `claims_history`, `driving_record`), purposes (`marketing`, `claims_processing`, `fraud_analytics`) with different durations; privacy rules.
2. Dynamically register 2 third-party clients (e.g. repair-shop, comparison-site) each requesting different scopes, via `/oauth2/register`.
3. `run.js`: user logs in via client A; consent screen shows only requested purposes; user grants some; check issued token claims are restricted; set a purpose to expire in 1 minute (demo-friendly `endTime`), show the app being refused after expiry and renewal prompt.
4. `export.js`: dump one identity's complete consent history (JSON/CSV) from the consents + events APIs.
5. DSAR stub: submit "delete my data" request, show SLA timer and completion record.

**Demo script:** dynamic registration; consent grant; restricted token; time-bound expiry and renewal; revoke; audit export.

---

## 5. Cross-cutting components to build (summary)

| Component | Used by | Effort |
|---|---|---|
| `demo/lib/verify.js` (token cache, retries, evidence logging), `demo/lib/idempotent.js`, `teardown-all.js` | all | S |
| `stubs/voicebot-ccaas` + CLI caller | UC-06, 07 | M |
| `stubs/client360` | UC-01 | S |
| `stubs/legacy-auth-store` (+ optional Bridge agent via Podman) | UC-11 | M |
| `stubs/rules-engine` (OpenFGA via Podman + model + seed) | UC-12 | M |
| `stubs/rp-a/b/c` (OIDC RPs with back-channel logout) | UC-08, 13 | M |
| `stubs/ops-queue` (webhook receiver) | UC-13 | S |
| `stubs/fraud-signals` | UC-05 | S |
| `stubs/dsar` | UC-15 | S |
| `views/agent` console | UC-03, 14 | M |
| Passkey routes (adapt IBM sample) + hostname/tunnel | UC-02 | M |
| Public tunnel for webhooks and back-channel logout (needs a public URL) | UC-08, 13, 05 | S |

(S ≈ ≤0.5 day, M ≈ 1 to 2 days, assuming a working API client and tenant flags.)

---

## 6. Recommended build order and effort

| Phase | Content | Why first | Est. |
|---|---|---|---|
| 0 | Unblock B1-B3; run tenant probes (3.3); build `demo/lib` | Everything depends on it; probes settle several verdicts | 0.5 to 1 d |
| 1 (quick wins, high confidence) | UC-14 CIBA, UC-13 SCIM + revoke, UC-09 API security, UC-15 consent | Native, well-documented, strongest proof points | 4 to 5 d |
| 2 | UC-02 passkeys, UC-06/07 voice, UC-03 recovery, UC-01 registration | Native with stubs | 5 to 6 d |
| 3 | UC-08 SSO + logout, UC-04 devices, UC-11 migration | Need extra infra or devices | 4 to 5 d |
| 4 (honest-limits) | UC-10 brands, UC-05 adaptive, UC-12 ReBAC | Partial; depend on IBM answers | 3 to 4 d |
| 5 | Rehearsal script, teardown, evidence pack for IFC | Repeatable demo | 1 to 2 d |

Total ≈ **18 to 24 working days** for all 15 end to end, less if we prioritise per IFC's scoring weight.

---

## 7. Questions and asks for IBM (send now, long lead time)

1. Enable on the trial tenant: **Flow designer, User forms, Adaptive access, Threat detection**. Threat detection requires IBM Support.
2. **User forms API:** is there a supported way to create/import forms programmatically?
3. **Session policy:** where/how is session lifetime configured per persona, and is there an API?
4. **Custom domains:** can one tenant serve multiple custom IdP domains (UC-10)? Is it a sales/provisioning item? Lead time?
5. **Sub-tenants / delegated admin per brand:** what do the `identitysources/subtenants` endpoints represent, and can admin entitlements be scoped to a subset?
6. **External callouts at token time:** are attribute functions with HTTP callouts available on this trial or only paid? Any latency/timeout limits (UC-01 and UC-12)?
7. **mTLS client authentication and certificate-bound tokens on SaaS:** which endpoint do clients connect to?
8. **JIT migration:** supported hash algorithms for `{TYPE}`-prefixed imports; recommended JIT pattern (Bridge external-authn vs Flow designer); access to the Verify Bridge image for the trial.
9. **Multi-device per user** for the IBM Verify authenticator, and limits.
10. **SMS quota** for the trial, and the supported way to use IFC's own SMS/email gateways.
11. **ReBAC:** any roadmap, partner pattern or reference architecture.
12. **Prior financial-services migration reference** requested in UC-11.

---

## 8. Immediate next steps (what I need from you)

1. **A working privileged API client** (client id + secret) with the entitlements in 3.1, or tell me you want me to document the one-time console steps to create it. Without it I can't run any of the plan.
2. Permission to **fix B3** (trailing slash in `.env`) and to register the callback URI by API once B1 is solved.
3. Tell me which **phase 1 use cases to start with**, or say "go" and I'll begin with Phase 0 (probes + `demo/lib`) followed by UC-14, UC-13, UC-09 and UC-15.
4. Confirm whether **two phones with the IBM Verify app** are available (UC-04, 06, 14 push), and whether a **public tunnel/hostname** is acceptable (UC-02, 08, 13).

---

## 9. Sources

- Official docs hub: https://docs.verify.ibm.com/verify (≈163 guide pages read, including `oauth-20-grant-type-ciba`, `oauth-20-token-exchange`, `oauth-20-cert-bound-access-tokens`, `policy-based-authentication`, `first-factor-authentication-fido2-login`, `migration-user-migration-csv-import`, `developing-external-agent-ws`, `flow-designer*`, `privacy-and-consent`, `chat-bot-integration-patterns`, `external-callout-based-attributes`, `threat-intelligence-in-verify`, `role-delegation`).
- API reference: https://docs.verify.ibm.com/verify/reference/<operationId> (≈40 operations read in detail: sessions, CIBA, STS, flow models, DPCM, themes, authenticators, FIDO, factors, SCIM patch/reset, applications schema).
- Tenant discovery document: `https://trialverify.verify.ibm.com/oauth2/.well-known/openid-configuration` `[LIVE]`.
- Repos: `ibm-verify/verifyctl` (v0.0.9-alpha), `ibm-verify/verify-saas-resources` (flows, DPoP samples, user-management utilities), `ibm-verify/verify-webauthn-passkey-sample-web`, `ibm-verify/verify-sdk-*`, `ibm-verify/verify-mcp`.
- This repo: `functions.js`, `app.js`, `lib/dpcm/dpcmClient.js`, `routes/*`, `ci-theme/`.

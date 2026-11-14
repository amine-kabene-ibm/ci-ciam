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
| 3 | **Branding is NOT enabled on the trial.** `POST /v1.0/branding/themes` returns 403 `CSIAZ3060E`: "Trial subscriptions do not support the branding feature." | The demo app's custom theme cannot be registered. The app runs with the `default` theme. **This blocks the UC-10 brand look and legal text until IBM enables branding** (languages still work: finding 34). |
| 4 | Dynamic client registration `POST /oauth2/register` works (201) and `DELETE /oauth2/register/{id}` works (204). | UC-15 dynamic client demo is buildable. Also the quickest way to create test clients. |
| 5 | `private_key_jwt` client registered via DCR with a JWKS; a signed client assertion with `aud = <tenant>/oauth2/token` returned a token. | UC-09 `private_key_jwt` is proven end to end. |
| 6 | `tls_client_auth` client with certificate-bound access tokens registers fine (201). **The mTLS handshake was tested (UC-09, 2026-11-10): the edge sends no `CertificateRequest`, so no client certificate can be presented on this host [LIVE].** A `curl --cert` to the token endpoint returns 401 `CSIAQ0155E` for a dummy client, which is not a valid mTLS proof. | UC-09 does **not** claim mTLS. It uses `private_key_jwt` and DPoP. Only an IBM-side change (client-certificate edge option) could enable mTLS. |
| 7 | CIBA app created via `POST /v1.0/applications` with `grantTypes.ciba=true` and backchannel settings (poll, email). **You must set `"applicationState": true`**, otherwise `/oauth2/ciba` returns `invalid_client`. With it enabled, `/oauth2/ciba` is reachable and returned `unknown_user_id` for a fake user. **Superseded by finding 49:** the full flow, including the e-mail approval, has now been run. | UC-14 is built. The approval step needs a human (email link or phone). |
| 8 | SCIM `PATCH active=false` returns 204. A token issued earlier then introspects `active:false` **within the same second** and a new token request returns `CSIAQ0281E The account is not active.` | **UC-13 core claim is proven:** deactivation immediately kills existing access tokens and blocks new logins. |
| 9 | `DELETE /v1.0/auth/sessions/{userId}` returns 204. `GET` on sessions with no session returns `{}`. | Session revoke API works. A real browser session is needed to see it killed (human step). |
| 10 | SCIM filter `emails.value eq "..."` finds an existing user. | UC-01 duplicate detection is buildable. |
| 11 | DPCM purposes API works and the three purposes the app uses exist (`communications`, `paperless-billing`, `terms`). | UC-15 base is in place. |
| 12 | Access policy **v5.0** create works. Valid rule condition types: `adaptiveAttributes, adaptiveRiskScoreAttributes, authnMethods, cia, contextAttributes, customAttributes, factorLifetimeAttributes, geoLocation, integrationAttributes, ipAddress, location, postAuth, subjectAttributes, threatInsights, timeAttributes, trusteer, webhooks`. Policies with `geoLocation`, `threatInsights`, `trusteer`, `webhooks` conditions were **accepted** (201). `ipAddress` takes opCodes `MATCH`/`NOMATCH`. | Policy building (UC-02, 03, 05, 08) is possible by API. Acceptance of `trusteer` is not proof Adaptive access is licensed; it still needs a real login to evaluate. |
| 13 | Threat detection config exists but is **`status: inactive`** (5 rules incl. credential stuffing, brute force). | UC-05 threat intel needs IBM to activate it. |
| 14 | Webhook purposes available: `identity_proofing`, `external_mfa`, `external_risk`, `notifications`, `external_sms`. | **New finding:** `external_risk` lets a policy call an external information point, and `external_sms` routes SMS to an external provider. Both help UC-05 and UC-02 (see those sections). |
| 15 | STS client create works (201) with `tokenSettings.signingAlg` set (the error `CSIAQ0134E` says it's required). | UC-09 token exchange / UC-07 buildable. UC-07 later proved the exchange itself (finding 26). |
| 16 | FIDO2 relying party (RP): the older `POST /v2.0/factors/fido2/relyingparties {"origin"}` returns 200 but creates nothing visible. **Correction (UC-02, 2026-11-12):** the real config API is `GET/POST /config/v2.0/factors/fido2/relyingparties` (list works; create needs the full body: `name, rpId, origins, enabled, webAuthn, metadataConfig, allowedAttestationFormats, allowedAttestationTypes, attestationCredProtect, pubKeyCredParams`, 201) and `DELETE .../{id}` (204). The earlier "405, not a list endpoint" was the wrong path. | The tenant already has a default RP: rpId = the tenant host. Use it; never delete it. See findings 54-60. |
| 17 | `GET /v1.0/authenticators` returns 0 registrations. `GET /v1.0/authenticators/discovery` lists one client, "Verify Profile". | UC-04/06/14: no REAL phone is registered. UC-04 registers a simulated IBM Verify app instead (rows 69-74). A real phone stays `[HUMAN]` |
| 18 | Sub-tenant API returns 405 `CSIAG0746E`: "This tenant does not have a partner reseller offering enabled". | **Resolves the open UC-10 question:** sub-tenants are a **reseller** feature, not a per-brand admin feature. Not available. |
| 19 | The token endpoint for `grant_type=password` is not allowed on the default app client. DCR clients can enable it. | Use DCR clients for scripted user logins in tests. |
| 20 | The `ifc` demo user created through SCIM with a password has "password must be changed" on first login unless header `usershouldnotneedtoresetpassword: true` is sent. | All scripted test users must send that header. |
| 21 | `POST /v2.0/factors/smsotp/transient/verifications` returns 429 `CSIAP3545E` "SMS messages are not supported for this account"; voice OTP returns `CSIAP3546E`. E-mail OTP works. (Found while building UC-06, 2026-11-10.) | SMS and voice OTP cannot be demoed on this tenant. Use e-mail OTP + TOTP. Add "enable SMS" to the IBM message if needed. |
| 22 | TOTP API works end to end: enrol (201), verify (204), replay rejected (400), windows -1/0/+1 accepted, lockout 429 that clears in about 20 s, one enrolment per user. (UC-06) | UC-02 TOTP fallback and UC-06 step-up are buildable without a phone. |
| 23 | `POST /v1.0/apiclients` creates a least-privilege API client (201, **empty body**; read `clientId`/`clientSecret` via `GET /v1.0/apiclients/{id}`). Requests beyond its entitlements return 403 `CSIAK4300E`. (UC-06) | Third-party/CCaaS components can run on a client with 5 entitlements instead of the admin client. |
| 24 | Email suppression list: a delivery failure suppresses the address; later OTPs to it return 400 `CSIBN0075E`. `GET`/`DELETE /v1.0/notification/suppression/email/{address}`. | Do not use fake `@example.com` mailboxes for OTP demos. |
| 25 | `POST /v1.0/authenticators/initiation` with `Accept: image/png` returns the IBM Verify app registration QR. | UC-04 and UC-06 phone enrolment can be scripted up to the scan. |
| 26 | Token exchange and introspection work (UC-07, 2026-11-10): `POST /oauth2/introspect` with an STS client (HTTP Basic) returns `active`, `sub`, `amr`, `exp`, `client_id`, `grant_type`; `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` returns a token of `tokenSettings.accessTokenLifetime`. `audience` is ignored, no `act` claim, the exchanged token survives revocation of the original but not user deactivation. Access tokens are opaque (no offline validation). | UC-07 is built on this. UC-09 token exchange / on-behalf-of reuses it: the `audience` and `act` expectations in the plan are wrong. **Confirmed again in UC-09 (2026-11-10).** |
| 27 | SSO and logout (UC-08, 2026-11-10): discovery advertises `frontchannel_logout_supported`, `backchannel_logout_supported`, `end_session_endpoint` = `/v1.0/endpoint/default/rplogout`. DCR takes `frontchannel_logout_uri` / `backchannel_logout_uri` (+ `_session_required`, `post_logout_redirect_uris`); if both are sent, front-channel wins and the back-channel URI is silently dropped. `PUT` on the application (full GET document) changes `logoutOption`, `accessTokenExpiry`, `authPolicy`. | UC-08 is built on this. |
| 28 | Cross-app SSO (UC-08): the 2nd/3rd app's `/authorize` returns a code with no page; all apps share one `sid`; one entry in `GET /v1.0/auth/sessions/{userId}`. `ACTION_MFA_ALWAYS` on a later app re-asks only TOTP; `ACTION_MFA_PER_SESSION` does not re-ask. Policy group conditions compare to the token's `groupIds`, which holds group **names**, not SCIM ids. A TOTP enrolment must be validated once (`POST /v2.0/factors/totp/{id}` `{otp}` = 204) before login can use it. | Per-persona/per-app assurance without a session-policy object. |
| 29 | Global logout (UC-08): `rplogout?id_token_hint&post_logout_redirect_uri&state` returns an HTML page with one iframe per app (`<rp>/frontchannel-logout?iss&sid`) plus the tenant's own, then auto-submits a status form after 3 s and redirects. **The Verify session is only cleared when that page runs.** Afterwards: sessions `{}`, access token `active:false` at once, refresh `invalid_grant`. `DELETE /v1.0/auth/sessions/{userId}` = 204 and kills tokens at once, but an app trusting its own cookie stays signed in. | Front-channel needs the browser to stay open about 3 s; back-channel is the answer for admin kills. |
| 30 | ID token carries `acr`, `amr`, `auth_time`, `sid`, `sub`, `iss`, `groupIds`. **Correction to finding 19/UC-07:** only *introspection* lacks `auth_time`/`acr`; the ID token and userinfo have them. `state`/`nonce` need 8+ chars. No session-policy API exists (every candidate path answers with the console login page). | Idle/absolute timeouts cannot be scripted; use per-app `accessTokenExpiry`. |
| 31 | On-behalf-of scope (UC-09, 2026-11-10): an exchange **without** `scope` returns a token with no scope (the policyholder's `openid` is not carried). An exchange **with** `scope=ifc.policy.read` returns a token carrying exactly that scope. The exchanged token keeps `sub` = policyholder and `client_id` = the partner STS client. Without an actor token the exchange returns 400 CSIAQ5242E. `actorCriteria` (CEL) is stored as `{}` and not enforced: a disallowed actor still gets a token. | UC-09 requests the scope on the exchange and checks the policyholder rule in the API stub. `actorCriteria` is not a control: the API scope and policyholder check are. |
| 32 | Delegated admin is real, per application (UC-10, 2026-11-11). Setting `owners:[userId]` on an application (GET full document, change, PUT) auto-grants the user the role `applicationowners`. With their own password-grant token the owner calls `/v1.0/owner/applications`: lists only their apps, manages entitlements of their app; another brand's app gives 400 `CSIAD0047` on write and an empty shell on read. Owner PUT accepts only `name` and `provisioning`; no policy or theme change. 403 on `/v1.0/applications`, access policies, group create. **An owner can read the whole SCIM directory and another brand's entitlement list.** | **Corrects the plan ("nothing scopes admin to a brand").** UC-10 capability 1 is demonstrable; state the limits. |
| 33 | Per-brand customers (UC-10): a DCR client with `all_users_entitled:false` refuses non-entitled users with `CSIAQ0279E` (401, localized). Entitle with `POST /v1.0/owner/applications/{appId}/entitlements` `{additions:[{assignee:{subjectId,subjectType:'user'},grantType:'DISC'}]}`, revoke with `{deletions:[id]}`. **A `group` entitlement is accepted (200) but does not admit the members.** `appId` = numeric tail of `_links.self.href`. | Entitle users one by one; helpers `ensureAppEntitlement` etc. in `demo/lib/idempotent.js`. |
| 34 | Language works without branding (UC-10): the default Verify pages (login, TOTP, errors) switch with `ui_locales=fr|en` or `Accept-Language` (`fr-CA` gives French). With neither: English. The stock French title is "S'inscrire - IBM Verify". | FR/EN per brand can be shown today; a French-first brand must send `ui_locales=fr`. Look and legal text still need a theme. |
| 35 | Consent page (`consent_action: always_prompt`) is per application and localized, but shows only `client_name`: `client_uri`, `policy_uri`, `tos_uri` and the description are not shown (UC-10). | Brand consent wording and links need the theme. |
| 36 | Custom domains (UC-10): a request to the tenant IP with an unregistered `Host` returns 400; `GET /v1.0/identitysources/subtenants` 405; `GET /config/v1.0/email-domain-auth` 400 `CSIAP3564E` ("Sender customization is not enabled"); `/v2.0/tenant/properties` lists only the tenant host. | `idp.brand1.com` cannot be improvised; IBM / sales. Brand portals run on `*.localhost` (DCR accepts those redirect URIs). |
| 37 | One tenant host means one browser session (UC-10): after Aurora, Boréal asks only its second factor. | Hard isolation between brands needs separate tenants. |
| 38 | **CSV import (UC-11, 2026-11-11):** `POST /v2.0/CSV/importUsers?notifyType=NONE`, multipart field **`file`**, returns **202 `{_id}`** (async job); status at **`GET /v2.0/CSV/jobs/{id}`** (`state`, `statistics.processedCount/errorsCount/errors[{id,failureReason}]`; the earlier guess `importStatus` is 404). Header `usershouldnotneedtoresetpassword: true` keeps the imported password usable; without it the user must change it (`CSIAQ0267E`). A row with a blank user name makes the whole job vanish (job id 404). An existing user is **never overwritten** (`CSIAI0047E`). Needs only `readUsers` + `manageUsers` (a 2-entitlement API client works). | UC-11 bulk is built on this. `GET /v2.0/CSV/headerNames` lists the columns. |
| 39 | **Which pre-hashed password prefixes work (UC-11), tested by importing and signing in with the original password:** works = `{SSHA256} {SHA256} {SSHA384} {SHA384} {SSHA512} {SHA512} {SSHA} {SHA} {MD5}` (salts of 4, 8 and 16 bytes, non-ASCII and comma/quote passwords). Does **not** work = `{SMD5}`, `{SHA1}` (the spelling; `{SHA}` works), `{PBKDF2}`, `{CRYPT}`, `{PLAIN}`, a bcrypt string: the import reports **success** and stores the text literally as the password, so the customer cannot sign in. | Answers the "supported `{TYPE}` list" question for 9 formats `[LIVE]`; **always filter by format before importing**. IBM should still confirm the official list. The earlier "repo helper uses `{SHA256}`" doubt is resolved: it works. |
| 40 | **Password policy and imports (UC-11):** minimum length is 8 (7 gives `CSIAI0020E`) for SCIM create. A **pre-hashed** import skips the check (a 5-character password imported as `{SSHA256}` signs in). Password change: SCIM `PATCH` replace `password` with the no-reset header is 204 and the new password works at once; without the header the user is flagged for change; re-using the old password gives `CSIAI0021E`. | JIT with a plaintext password must handle a legacy password shorter than 8 (UC-11 scenario H). |
| 41 | **Forced password change on the hosted page (UC-11):** a user created/imported without the no-reset header gets the Verify page "Change the initial password" (`CSIAH0307I`, Skip Now button) after a correct login; a script that posts `operation=verify` with `oldpassword`, `newpassword`, `confirmpassword` to the page's action completes it (the new password then works, the old one does not). Password-grant sign-in says `CSIAQ0267E`. | The "bulk with reset" half of IFC's requirement is handled by Verify itself. |
| 42 | **Linkage attributes survive import and SCIM create (UC-11):** `externalId`, enterprise `department` and `employeeNumber` (CSV columns `externalId`, `department`, `employee_id`), `preferredLanguage`, and the custom attribute `accountId` (CSV column `accountId`, SCIM `urn:ietf:params:scim:schemas:extension:ibm:2.0:User.customAttributes`). SCIM filters work on `externalId` (`eq`, `sw`) and `urn:...enterprise:2.0:User:department`; the bare `department`/`employeeNumber` filters give 400 `CSIAI0050E`; a filter on the custom attribute is unknown (400). | Account-to-policy and account-to-brokerage links are preserved and queryable; use `externalId` for the legacy customer id. |
| 43 | **Verify Bridge / external-authentication agent is not just unconfigured but not creatable (UC-11):** `GET /config/v1.0/onpremagents` = 404 `CSIBS0035E`; `POST` (several body shapes) = **401 `CSIBS0033E`** although the admin client holds `manageExternalAgents` and related entitlements. `POST /v1.0/identitysources` with type 1, 2, 3, 9 to 14, 17 is accepted (201) but those are social/OIDC types, not external authentication (probe objects deleted). | Native JIT option 1 (Bridge) is an IBM-enablement item, not a Podman item. Corrects the guide's "run the Bridge agent with Podman" as the next step. |
| 44 | **JIT pattern that works on this tenant (UC-11):** a gateway in front of Verify (password grant first; if the user is unknown to Verify, check the legacy store; if valid, `POST /v2.0/Users` with the verified plaintext so Verify hashes it itself, then sign in). First login ~1.5 to 2.2 s, later logins ~0.2 to 0.3 s with no legacy call; a legacy outage returns 503 for un-migrated users only. Verify's own error for a wrong password and for an unknown user is the same (`CSIAQ0264E`). | Built as `stubs/migration-gateway`. It is a pattern IFC would own, not a Verify feature. |
| 45 | **OpenFGA runs natively, Podman is not needed (UC-12, 2026-11-11):** `podman machine start` reports success but the socket stays refused (`127.0.0.1:56232`), so no container could be pulled. The OpenFGA release `v1.22.1` is a single binary: download `openfga_1.22.1_darwin_arm64.tar.gz` plus `checksums.txt` from GitHub, check SHA-256, run `openfga run --datastore-engine memory --http-addr 127.0.0.1:4171 --grpc-addr 127.0.0.1:4172`. Gotchas: `openfga version` prints to **stderr**; **Node here runs under Rosetta (`process.arch` = `x64`) on an Apple Silicon Mac**, so pick the binary with `sysctl hw.optional.arm64`, not `process.arch`; store names must match `^[a-zA-Z0-9\s.\-/^_&@]{3,64}$`; writing an existing tuple or deleting a missing one is HTTP 400 (so sync by diff); at most 100 tuples per write by default. | The "Podman may pull the image" question (human item 7) is closed. `stubs/rules-engine/openfga.js` downloads and starts the engine. |
| 46 | **Tokens and directory facts for authorization (UC-12):** the password-grant **access token is opaque** (not a JWT); the ID token is a JWT. `POST /oauth2/introspect` returns `sub` = the Verify user id (e.g. `8A60005FSE`), `preferred_username`, `active`. An **STS client can introspect** tokens issued to another client (200, `active:true`), so the gateway needs no admin credential. With `sendAllKnownUserAttributes: "true"` on the application the ID token and `/userinfo` also carry `department`, `job_title`, `email`, `given_name`, `family_name`, `uid`. SCIM `PATCH` with `op: add` on `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department` / `:employeeNumber` and on `title` returns 204 and replaces the value; a 2-entitlement API client (`readUsers`, `manageUsers`) is enough. A token issued before a SCIM `active=false` PATCH introspects `active:false` at once. | The gateway authenticates by introspection and authorizes by the engine on `sub`. Directory attributes are a snapshot in the token: a token issued before a move still says the old brokerage. |
| 47 | **No token-time callout and no custom attribute source on this tenant (UC-12):** `GET /v1.0/attributefunctions` lists 13 built-ins only (`uppercase`, `lowercase`, `base64Encode/Decode`, `encodeURI*`, `decodeURI*`, `generateUuidIfNull`, `currentTimeInSeconds/Milliseconds`, `sha256`, `sha512`); `POST` on it is 405 `CSIAK4305E`. `POST /v1.0/attributes` accepts only source types `STATIC, CREDENTIAL, SCHEMA, PROFILE, ORG` (400 `CSIBE2716E`); `rule` is deprecated (400 `CSIBE2758E`). Putting `tokenResponseMap` in the application's `oidc.properties` is refused (400); no other placement was tried. | The PDF's "IdP calls the rules engine while minting the token" cannot be shown here. Say so; the request-time pattern is the demo. Whether `tokenResponseMap`/`introspectResponseMap` exist elsewhere in the model is `[INFER]` unproven. |
| 48 | **A relationship model that survives "a broker who leaves" (UC-12):** `servicing = placed_by and member from brokerage` (an intersection) means the placing broker keeps access only while still a live member of the client's brokerage; deleting one membership tuple removes access on the next check, without touching client records. `viewer = servicing or manager from brokerage`; `editor = servicing` (a policy choice). OpenFGA v1.22.1 supports `list-objects` and `list-users` (the "all resources a user can access" and "who can access" asks). 8,120 relationships loaded in ~0.8 s; check ~1 to 6 ms, list-objects ~1 to 2 ms on this laptop, in memory (a hint, not a benchmark). | The model is in `stubs/rules-engine/model.js`. IFC's real roles and volumes are unknown. |
| 49 | **CIBA end to end (UC-14, 2026-11-12):** app settings go under `providers.oidc.properties` (see UC-14 section; `additionalConfig` beside `properties` is a 400). Channels are only `push` and `email`. The app admits **entitled users only** (403 `CSIAQ0279E`). `login_hint` is the user name only. A real e-mail approval returned tokens; the poll and audit behave as documented. **No unlock endpoint:** only a SCIM password replace clears a lockout. The events API needs `readReports`. A locked account still gets a 200 request but **no e-mail arrived** (observed once). | UC-14 is demonstrable on e-mail; push needs a phone. The lock is applied after the approval in the demo. |
| 50 | **Custom attributes never reach the ID token or userinfo (UC-01, 2026-11-12).** Tested with `tags:["sso"]`, `credName`, `sendAllKnownUserAttributes:"true"` and several mapping payloads: the claim is absent. Enterprise attributes DO arrive when the app has `sendAllKnownUserAttributes:"true"`: `employeeNumber` -> `employee_id`, `department` -> `department`, `title` -> `job_title`, mobile phone -> `mobile_number`. | **Corrects the old UC-01 step 5 ("map `client360_id` into the ID token via attribute mapping").** The Client 360 id is stored in `employeeNumber` (token claim `employee_id`) AND in the custom attribute `client360Id` (queryable). |
| 51 | **Custom attribute creation (UC-01):** `POST /v1.0/attributes/` with `Content-Type: application/scim` returns 201 `{id}`. `schemaAttribute.scimName` must be **alphanumeric** (`client360_id`, `a-b`, `x_y` give 400 `CSIAI0096E`); `schemaAttribute.name` must be a free slot `customAttributeN`; `constraints.unique:true` is enforced on user create (400 `CSIAI0313E` "value ... already exists"). `DELETE /v1.0/attributes/{id}` 204. SCIM filter on a custom attribute needs the full URN prefix: `urn:ietf:params:scim:schemas:extension:ibm:2.0:User:customAttributes.<scimName> eq "x"`. | Names in the old guide (`postal_code`, `client360_id`) are not valid; use `client360Id`, `policyNumber`, `hasVehicle`. Postal code and language use the standard SCIM `addresses` and `preferredLanguage`. |
| 52 | **Duplicate behaviour (UC-01):** a second `POST /v2.0/Users` with the same `userName` is 409 (case-insensitive). A different `userName` with the same e-mail is **201** (not blocked). | The e-mail / phone / policy duplicate rules cannot be left to Verify: they run in IFC's registration service with SCIM filters (`emails.value`, `phoneNumbers.value`, custom attribute). The `unique` attribute is the backstop. |
| 53 | **E-mail OTP details (UC-01):** `POST /v2.0/factors/emailotp/transient/verifications {correlation, emailAddress}` 201; the e-mail reads `NNNN-NNNNNN` (first 4 = correlation); the person types the 6 digits; 5 attempts (`retries:4`); wrong code 400 `CSIBN0021E`, 5th wrong `CSIBN0080E`. The API client needs **`authnAnyUser`** (with only `generateOTP`: 403 `CSIAK4300E`); adding a user to a group needs **`manageGroupMembers`**. SCIM errors carry the code in `detail` (e.g. `CSIAI0020E`), OTP errors in `messageId`. | Least-privilege registration client = `readUsers, manageUsers, authnAnyUser, manageGroupMembers`. Disposable mail.tm inboxes receive the Verify e-mail (4 s to about 2 min), so a script can read the real OTP without a human. |
| 54 | **Passkey ceremony works from a script `[LIVE]` (UC-02).** Registration: `POST /v2.0/factors/fido2/relyingparties/{rp}/attestation/options {userId, authenticatorSelection:{residentKey,userVerification}, attestation:"none"}` returns the options (user id is the Verify id), then `POST .../attestation/result {id, rawId, type, response:{attestationObject, clientDataJSON}, nickname, enabled}`: `nickname` is required and extra fields (`transports`, `clientExtensionResults`) are rejected `CSIBN0005E`; 200 with `validated:true`. `GET /v2.0/factors/fido2/registrations?search=userId="X"` lists, `DELETE .../registrations/{id}` 204 (PATCH 405). Assertion: `.../assertion/options` + `.../assertion/result` (counter increments; wrong signature 400 `FID003E`; unknown credential `FID031E`; replayed registration `FID024E`; wrong origin `FID003E`). | A software authenticator (`demo/lib/webauthn.js`) proves the whole server side without a phone. Only the OS prompt and a platform/hardware key stay `[HUMAN]`. |
| 55 | **Passkey as a SECOND factor on the hosted login works `[LIVE]`.** Policy `ACTION_MFA_ALWAYS` with `authnMethods:["fido2",...]` (the v5 name is `fido2`; the policy API stores the list alphabetically). One allowed method: Verify goes straight to `authentication/mfa/fido2/passwordless_fido2.html` (serverOptions meta: challenge, rpId, allowCredentials). Several: `.../mfa_selection/combined_mfa_selection.html` with one `<meta name="otpMethod" content="label\|id\|id\|\|\|type">` per enrolled method (`fido2_0`, `totp_0`, `email_0`). Choose with POST `operation=generate&otp.user.otp-method.id=<id>`; passkey answer = POST `operation=authenticate&assertionResponse=<JSON>`; "use another method" = `operation=restart`. The ID token `amr` is `[password, fido2, 2fa]`. A user with no usable method gets `CSIAH0640E`. | AAL3 = passkey only, AAL2 = passkey or code, AAL1 = password: three policies, three apps. |
| 56 | **Passkey-only (no password) sign-in is NOT available on this tenant `[LIVE]` `[INFER]` cause.** Policies with `containsFirstFactor:true` + rule `firstFactor:true` + `fido2` are accepted (201) but the login page `idSourcesMeta` keeps `passwordless:{qr:false,fido:false}`; the passkey route `GET /authsvc/mtfim/sps/apiauthsvc?PolicyId=urn:ibm:security:authentication:asf:fido2&identity_source_id=<id>` then the assertion returns 400 `CSIAH0026E "You are not authorized to use passkey for passwordless login"`. About 33 guessed identity-source property keys and policy variants did not change it. | IBM-side or console-only setting. Passkey is a second factor today. Ask IBM (section 4). |
| 57 | **E-mail OTP on the hosted page uses different field names `[LIVE]`.** The TOTP page takes `otp`; the e-mail page takes `otp.user.otp` (the six digits after the dash) and a hidden `otp.user.otp-hint` (the four-digit number shown on the page, first part of `NNNN-NNNNNN`). Posting only `otp` gives `CSIAH2417E`. Mail arrives in 2-5 s (mail.tm). | Reusable for UC-03, UC-06. |
| 58 | **Bring-your-own SMS gateway works `[LIVE]` (UC-02).** `POST /config/v1.0/webhooks/ {name, type:"realtime", purpose:["external_sms"], urls:[...]}` (200, `{id}`; only types `realtime`/`notification`), `POST /config/v1.0/smsproviders {name, webhookId}` (201, starts disabled), then **`PUT /config/v1.0/smsproviders/{id}` with the FULL body** `{name, webhookId, description (non-empty, plain text), enabled:true, capabilities:["sms"], userContextAttributes:[]}` (204). While enabled, `POST /v2.0/factors/smsotp/transient/verifications` returns 201 instead of 429 and Verify POSTs `{destinationPhoneNumber, content, category:"OTP", language, otp, correlation, expiry:300}` to the webhook URL (text "Your passcode is: NNNN-NNNNNN. It expires in 5 minutes."). The code verifies at `.../verifications/{id}` (wrong 400, right 204). Delete the provider BEFORE the webhook (else refused); once gone SMS is 429 again. Voice OTP stays `CSIAP3546E`. | Answers IFC's "can we integrate our own gateways": yes. The tenant edge sometimes returns a 403 HTML page for some webhook hosts (webhook.site, example.invalid) on create; a public tunnel URL worked. |
| 59 | **Hosted-page passkeys need the default RP `[LIVE]`.** Verify's own pages use the RP whose rpId equals the tenant host. A passkey registered on a custom `localhost` RP is accepted by the API but is invisible to the hosted login. Browsers only let a page use rpId = its own domain, so a page on `localhost` cannot register a passkey for the tenant RP: registration in a real browser goes through Verify's self-care page `https://<tenant>/usc/` (its bundle calls the same `.../attestation/options`). | No `mkcert` / `ifc-demo.local` hostname needed for the demo. The UC-02 build guide steps 1-2 are replaced. |
| 60 | **Choice page order and AAL notes `[LIVE]`.** On the method choice page Verify lists methods in its own order (seen: authenticator app, e-mail, passkey), not passkey first; "passkey first" is exact only where the policy allows nothing else. `GET /factors/v2.0/factors/discover` lists the enabled factor types and RPs. `GET /v1.0/identitysourcetypes` works. Authorize `state` must be long enough (a 2-character state gives `invalid_state`). | Say so in the talk track; portal steers a customer with a passkey to the AAL3 application. |
| 61 | **Hosted "Forgot password" is OFF by default and has its own switch `[LIVE]` (UC-03).** The login page has `forgotPasswordOptions.enabled:false` and the forgot URL answers `CSIAH0325E Reset password is disabled`. Enable it with `PUT /v1.0/identitysources/{id}` of the Cloud Directory source (`sourceTypeId 5`): send the full GET document plus property `{key:"passwordResetEnabled", value:"true", sensitive:false}` (204). Other candidate names are stored but do nothing. It is tenant-wide, not an `ifc-demo-` object: `setHostedPasswordReset(bool)` in `demo/lib/idempotent.js`, restored by both teardowns. The `/v1.0/usc/resetpassword*` paths in the old UC-03 steps do not exist (they return the console login page). | UC-03 self-service recovery is the hosted flow, not an API you drive. |
| 62 | **Hosted reset flow `[LIVE]`.** Login page `idSourcesMeta` -> `forgotPasswordUrl` -> POST `{operation:verify, username}` -> `CSIAH0323I` (same answer for unknown users: no enumeration) -> e-mail "Your password reset information" (link valid 30 minutes, arrives in 1-4 s) -> page with `<meta name="action">`; POST `{operation:verify, username:'', oldpassword:'', newpassword, confirmpassword}` (lowercase) -> `CSIAH0324I`. Rejections carry the text in `<meta name="errorMessage">`: weak password `CSIAH0315I` (also the template title), mismatch `CSIAH0331I`; after a rejection the page issues a NEW form action. Link is single use (`CSIAH0328E`). The 3rd request in a row gives `CSIAH0327I` (limit lasted under 16 min). | `demo/uc03-recovery/hosted.js` plays it. |
| 63 | **What the hosted reset does `[LIVE]`.** The old password stops working, the new one signs in, an **already-issued access token goes inactive**, and a **locked account is unlocked**. The page promises a notification e-mail ("A password change notification email is sent") but none arrived in 4 runs `[LIVE: not proven]`. It is not risk-aware: the link is sent to every account. | IFC's portal must decide who may use it. |
| 64 | **Agent reset `[LIVE]`.** `PATCH /v2.0/Users/{id}/passwordResetter` body `{schemas:[PatchOp], operations:[{op:"replace", value:{password:"auto-generate", "urn:ietf:params:scim:schemas:extension:ibm:2.0:Notification":{notifyType:"EMAIL", notifyPassword:true, notifyManager:false}}}]}` (note lowercase `operations`) -> 204; Verify e-mails "Password reset" with a temporary password the agent never sees; the user must change it (`CSIAQ0267E`). **An already-issued access token STAYS ACTIVE**: also call `DELETE /v1.0/auth/sessions/{id}` (204, tokens inactive in about 1 s). `notifyType:"NONE"` also gives 204. A SCIM `PATCH password` (the UC-14 unlock) clears a lock but only sends "User profile modified". | Use `passwordResetter` + sessions DELETE. |
| 65 | **Least privilege for a recovery console `[LIVE]`, each removed in turn gives 403:** `readUsers` (SCIM), `resetPasswordAnyUser` (passwordResetter), `revokeAllSessions` (DELETE sessions; `manageLoginSessions` also works), `readReports` (events), `readEnrollMFAMethodAnyUser` (factor list), `authnAnyUser` (e-mail OTP create/verify and TOTP verify). With these 6: 403 for list API clients, create/delete/deactivate a user, change the e-mail, read access policies. | `AGENT_ENTITLEMENTS` in `demo/uc03-recovery/common.js`. |
| 66 | **Risk signals Verify exposes `[LIVE]`.** Events (`GET /v1.0/events`, `readReports`): `data.origin` (IP), `data.devicetype` (the User-Agent string), `geoip.{country_iso_code, city_name, region_name, as_org}`, `data.result`, `data.cause`. **Lag 15 to 90 s** (12 to 17 s measured). `search`/`filter` are ignored (200 but unfiltered): read a time window (`range_type=time`, `size` up to 1000, `search_after` object for the next page) and filter client-side. SCIM: `lastLogin`, `pwdChangedTime`, `pwdAccountLockedTime`, `meta`. Factor list: `created`, `validated`. Management events: `reset password` (`CSIAI1027I`, `performedby_clientname`), TOTP enrolment (`mfa_device`). | The recovery console reads these. |
| 67 | **Access policy conditions `[LIVE]`.** `ipAddress` IS evaluated on a real hosted sign-in: `{type:'ipAddress', opCode:'MATCH'|'NOMATCH', values:['<ip or CIDR>']}` (flat, no `attributes`). `geoLocation` (`{type:'geoLocation', opCode:'IS'|'IS_NOT', geoLocationAttributes:[{name, opCode:'EQ', values}]}`) is accepted but the inner `name` is not validated and ~40 names and values never changed a sign-in outcome: **not proven, do not claim it**. `X-Forwarded-For` is ignored (events keep the real IP), so a foreign country cannot be produced from a laptop. | The old UC-03 step 1 (geoLocation) is replaced by `ipAddress`. |
| 68 | **E-mail OTP has an account quota `[LIVE]`.** After a day of many sends (UC-01, UC-06, UC-03 runs), `POST /v2.0/factors/emailotp/transient/verifications` answers 429 `CSIAP3523E` "Email quota for account reached" and stayed so for 10+ minutes. The hosted reset e-mails kept arriving. | Do not rehearse the OTP demos in a loop; keep the quota for the presentation. |
| 69 | **A software "IBM Verify app" registers and answers push on the real tenant `[LIVE]`.** Protocol (from the open-source `ibm-verify/verify-sdk-ios`): `POST /v1.0/authenticators/initiation {clientId, accountName[, owner]}` returns `{code, registrationUri}` (same JSON as inside the QR PNG); the device redeems `POST <registrationUri>?skipTotpEnrollment=false {code, attributes}` -> `{id, accessToken, refreshToken, metadata}`; enrols `signature_userPresence` (`signedData` = RSA-SHA256 over the registration id, **plain base64**; `publicKey` = SPKI DER base64); finalizes with `POST <registrationUri>?metadataInResponse=false {refreshToken, attributes}` (ENROLLING -> ACTIVE). `platformType` must be `IOS` or `Android` (else 400 `CSIBH0005E`). Implemented in `demo/lib/verifyDevice.js`. | UC-04's server side is provable without a phone. APNs/FCM delivery, Face ID and the real app screen stay `[HUMAN]`. |
| 70 | **One user can hold several trusted devices `[LIVE]`.** 13 registrations for one user succeeded, no limit hit. `GET /v1.0/authenticators` lists them with `attributes.deviceName`, `platformType`, `state`. | Answers the old open risk "unproven that one user can hold two registrations": **yes**. The RFP's "state the limitation" clause does not apply to the number of devices. |
| 71 | **Self-service works with the customer's OWN token `[LIVE]`.** With a password-grant token (no `owner`): `POST /v1.0/authenticators/initiation` 200, `GET /v1.0/authenticators` lists only her devices, `POST .../verifications` pushes to her own device (202), `DELETE /v1.0/authenticators/{id}` 204. Another customer's device: 403 `CSIBH0002E` for GET and DELETE. | "Register Device" and "Revoke" in IFC's app need no admin API client. |
| 72 | **Push request shape `[LIVE]`.** `POST /v1.0/authenticators/{id}/verifications` body: `transactionData{message, originIpAddress, originUserAgent, additionalData:[{name:'originLocation',value},{name:'type',value}]}`, `pushNotification{title,message,send:true}`, `authenticationMethods:[{id:<signature id>, methodType:'signature'}]`, **`logic:'OR'`** (without it 400 `CSIAK2802E`), `expiresIn`. The signature id = `GET /v1.0/authnmethods/signatures` entry whose `attributes.authenticatorId` is the device. Final states: VERIFY_SUCCESS, USER_DENIED, USER_FRAUDULENT, VERIFY_FAILED (wrong key, 400 `CSIBH0031E`), TIMEOUT. Replay 400 `CSIBH0030E`; another device 404 `CSIBH0028E`; cancel (DELETE of the request) 405; disabled device 400 `CSIBH0036E`; revoked device 404 `CSIBH0018E`. `correlationEnabled` (number matching) is accepted and has no effect. | Corrects the `[DOCS]` step 3 of the old UC-04: the body needs `logic` and the signature id. |
| 73 | **Entitlements for a push service `[LIVE]`, measured with a 403 matrix.** `readAuthenticatorsAnyUser` = list; `manageAuthenticatorsAnyUser` = initiation + delete; `readEnrollMFAMethodAnyUser` = signature lookup; **`authnAnyUser` = create/poll a push**. **`mfaPush` does NOT enable push** (403). `readReports` = events. No SCIM without `readUsers`. | Corrects row 52/UC-06 `CCAAS_ENTITLEMENTS` (`mfaPush` was an `[INFER]`, now measured wrong). |
| 74 | **Revoke/disable/audit `[LIVE]`.** Disable/enable: `PATCH /v1.0/authenticators/{id}` with `Content-Type: application/json-patch+json` and `[{op:'replace',path:'/enabled',value:false}]` (204; other content types 415). Hosted login with `ACTION_MFA_ALWAYS` + `['signatures']`: 1 device -> pending page; 2 devices -> choice page (`otpMethod` metas, **order not stable, choose by device name**); approve -> code; deny -> `CSIAH3102E`. Events (`readReports`, 25-40 s lag): `resource:mfa_device`, `action: created|modified|deleted`, `self:"true"` for self-registered; push sign-ins `mfamethod:"IBM Verify Push"`, `mfaresult`, `mfadevice`. Valid policy `authnMethods` include `signatures`, `signatures_userPresence`, `anyFactor`. | Audit and step-up for UC-04 are provable. `signatures_userPresence` alone matched no device (`CSIAH0640E`): use `signatures`. |
| 75 | **IFC's own app: authenticator client `[LIVE]`, push channel `[DOCS]`.** `POST /v1.0/authenticators/clients {name}` -> 201; extra fields (`firebase`, `type`, ...) are rejected 400. Initiation with that client id works and a device registers under it; the same push API works. `GET/DELETE /v1.0/authenticators/clients[/{id}]` list and delete. `teardown-all.js` now sweeps them. | The registration profile for IFC's branded app exists; Firebase/APNs/SFMC credentials are not settable via API: ask IBM. |

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
- All probe objects (test users, DCR clients, STS clients, probe policies, CIBA apps, FIDO relying party) were **deleted**. The FIDO relying party probe is moot: the list endpoint exists (finding 16 corrected) and only the tenant's default RP is present.

---

## 1. Common foundation (build once)

### 1.1 Files (foundation built 2026-11-10: `lib/verify.js`, `lib/idempotent.js`, `lib/totp.js`, `00-probe.js`, `teardown-all.js`; `config/` not needed so far)

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
node demo/00-probe.js             # 12 live checks, prints PASS/FAIL (blocked features must stay blocked)
node demo/teardown-all.js --list  # every ifc-demo-* object on the tenant (drop --list to delete)
```

---

## 2. Per-use-case build instructions

Legend per use case: **Status** (can Bob build it fully?), **Build steps** (automatable), **Human steps** (`[HUMAN]`), **Verification**, **Teardown**, **Open risks**.

---

### UC-01: Self-service registration and progressive profiling

**Status: BUILT and VERIFIED, Track A** (2026-11-12). `node demo/uc01-registration/verify.js` 52/52 PASS (`demo/out/uc01.json`, 0 failed, secret scan clean), teardown leaves only UC-13/14/15 objects, setup repeats from scratch. Track B (Verify Flow) is **blocked: Flow designer not enabled** `[LIVE]` (403 `CSIBZ0098E`), and no self-registration configuration API was found. The browser pass with your own mailbox is `[HUMAN]`.

**Proven `[LIVE]`** (all executed against the tenant; the OTP e-mails are real Verify e-mails, read by the script from disposable mail.tm inboxes)
- Minimal identity: SCIM create with e-mail + password only (no name, phone or address), about 0.3 s, **after** the address is proven; an abandoned registration leaves nothing in the directory. The e-mail is the `userName` (sign-in works by userName only).
- Verification: Verify sends the e-mail (`POST /v2.0/factors/emailotp/transient/verifications`, about 0.3 s to accept); verify via `POST .../{id}`; 4 wrong codes count down, the 5th gives `CSIBN0080E`; reused/unknown transaction refused; a weak password (`CSIAI0020E`) does not cost the code.
- Duplicates (IFC rules in `stubs/registration-portal/service.js`): e-mail incl. capitals/spaces, phone (any format), matched policy number; configurable per rule; the tenant `unique` attribute `policyNumber` refuses a second account even if the application check is skipped (400 `CSIAI0313E`). Someone who only knows a policy number (wrong postal code) is not linked.
- Client 360 link (stub): policy + postal code match -> the owner's `C360-100231`; prospect -> `C360-P<hash>`; Client 360 down -> registration still succeeds, link marked pending. Stored in `employeeNumber` and `client360Id`. **No Client 360 call at sign-in** (stub counter).
- Sign-in: password grant and the portal's authorization code + PKCE through the hosted Verify login; ID token `sub` = Verify id, `employee_id` = Client 360 id.
- Progressive profiling by SCIM PATCH: stage `address` (postal code, language) then stage `about` (vehicle, optional mobile), one at a time, completeness 25 -> 75 -> 100 %; field validation; duplicate phone refused on the second account; answers filterable in the directory. `GET /v2.0/Me` works with the customer token, `PATCH /v2.0/Me` is 405.
- Least privilege: the service runs on a 4-entitlement client (403 on `/v1.0/apiclients`).

**What was built:** `demo/uc01-registration/{common,setup,run,verify,teardown,serve}.js` + README, `stubs/client360/server.js` (:4010), `stubs/registration-portal/{service,server}.js` (:4011), `ensureCustomAttribute`/`deleteAttributesByPrefix` in `demo/lib/idempotent.js`, `teardown-all.js` (attributes, members of `ifc-demo-*` groups).

**Changes to the plan above (the earlier text was wrong or replaced)**
- Token enrichment: custom attributes do **not** reach tokens (finding 50). The Client 360 id travels as `employee_id` (from `employeeNumber`).
- Attribute names: `client360_id` etc. are invalid (finding 51): `client360Id`, `policyNumber`, `hasVehicle`; postal code/language use SCIM `addresses` / `preferredLanguage`.
- `routes/ifc-register.js` in the demo app and the redirect in `app.js` were **not** built: a standalone portal on :4011 keeps the existing app untouched. Progressive profiling is triggered by the portal after sign-in, not by `app.js`.
- Duplicate check is not just `emails.value` (finding 52).

**Not proven / left for you**
- `[HUMAN]` Registering in a real browser with your own mailbox: `node demo/uc01-registration/setup.js && node demo/uc01-registration/serve.js`, open `http://localhost:4011`, follow `DEMO-RUNBOOK-UI.md` UC-01.
- `[LIVE]` Flow designer / Track B and User forms: blocked (IBM). Item 1 of the message to IBM.
- `[DOCS]` Factor choice at signup (passkey, TOTP) and SMS OTP: not covered (e-mail OTP + password). SMS is blocked on this tenant (finding 21).
- `[INFER]` Multi-brand / multi-tenant registration: not demonstrated (UC-10 covers per-brand login).
- Registration transactions live in memory in the portal process; custom attributes are limited to the free `customAttributeN` slots.
- The wizard is a stand-in for IFC's own portal; the hosted Verify pages are IBM-styled (branding refused on the trial).

**Run it:** `node demo/uc01-registration/setup.js`, `node demo/uc01-registration/run.js` (52 checks, 40-90 s, no human), `node demo/uc01-registration/verify.js`, `node demo/uc01-registration/teardown.js`.

---

### UC-02: Passkeys / FIDO2 with OTP and TOTP fallback

**Status: BUILT, PARTIAL (2026-11-12).** Built and verified end to end against the tenant with a software authenticator, the real hosted login pages and a real e-mail OTP: `run.js` 46/46 (`demo/out/uc02.json`), `verify.js` 18 PASS / 0 FAIL / 5 HUMAN, torn down (tenant listed clean) and rebuilt from zero. Files: `demo/uc02-passkeys/{common,setup,run,serve,verify,teardown}.js` + `README.md`, `demo/lib/webauthn.js`, `stubs/passkey-portal/`, `stubs/sms-gateway/` (+ `tunnel.js`), helpers in `demo/lib/idempotent.js`.

**What was built `[LIVE]`**
1. **Three assurance levels as policies** (`ifc-demo-uc02-policy-aal1-password` `ACTION_ALLOW`; `-aal2-otp` `ACTION_MFA_ALWAYS` fido2+totp+emailotp; `-aal3-passkey` `ACTION_MFA_ALWAYS` fido2), each bound to its own application (`-app-aal1/2/3`). The method name in v5 policies is `fido2` (finding 55).
2. **Passkey registration and sign-in** against the tenant's default RP: options, attestation, listing, assertion on the hosted page, ID token `amr` `password,fido2,2fa`, counter moves (findings 54, 55, 59).
3. **Attack handling:** forged signature, replayed or never-issued challenge, wrong origin: all refused.
4. **Fallback:** AAL2 choice page, "use another method", wrong then right authenticator-app code, real e-mail OTP from a mail.tm inbox (finding 57); a customer without a passkey is refused at AAL3 (`CSIAH0640E`) and succeeds at AAL2.
5. **Account settings:** add a second device, list, remove (API); the portal stub shows the nudge and the passkey list; identifier-first answer (`/api/methods`) without account enumeration.
6. **BYO SMS gateway:** webhook + SMS provider via API, Verify POSTs the OTP to IFC's URL through a free tunnel (`ssh nokey@localhost.run`), the code verifies, removal restores 429 (finding 58).

**Corrected from the earlier plan:** no `mkcert`, no `ifc-demo.local`, no custom RP, no `routes/passkey.js` in the base app and no `[INFER]` URN (finding 59, 16, 55). The "attach SMS" step is the SMS provider (finding 58).

**Not proven / left for you**
- `[HUMAN]` A real platform passkey (Touch ID, Windows Hello, phone) and the OS prompt: register via `https://trialverify.verify.ibm.com/usc/`, then sign in at the AAL3 portal (steps in `demo/uc02-passkeys/README.md`).
- `[INFER]` Passkey-only sign-in (no password): refused `CSIAH0026E` (finding 56). IBM must enable it.
- `[HUMAN]` SMS to a handset and voice OTP (carrier behind IFC's gateway; IBM's own SMS and voice are blocked, finding 21).
- `[INFER]` Required AAL per **transaction type**: Verify applies a policy per application; the per-transaction step-up is portal logic (send to the AAL3 app, or `acr_values`/`max_age`). Not built.
- Passkey is not forced first on the AAL2 choice page (finding 60).

**Verification:** `node demo/uc02-passkeys/verify.js`. **Teardown:** `node demo/uc02-passkeys/teardown.js` (users with their passkeys and TOTP, apps, policies, SMS provider then webhook; the default RP is never touched).

**Run it:** `node demo/uc02-passkeys/setup.js`, `run.js` (60-90 s, no human), `verify.js`, `serve.js` for the browser demo, `teardown.js`.

---

### UC-03: Risk-aware account recovery, agent-assisted

**Status: BUILT, PARTIAL.** Built and run on the real tenant by script: `demo/uc03-recovery/` + `stubs/recovery-console/`. The self-service flow, the agent-assisted flow, the risk routing, session end, least privilege, the risk-aware sign-in policy and the audit trail are proven `[LIVE]`. Not proven: a foreign country (cannot be produced from a laptop), the `geoLocation` policy condition (never evaluated), a self-service "password changed" notification e-mail, an AI risk score (needs Adaptive access), and the e-mail-code route of caller verification whenever the trial's e-mail OTP quota is used up (see finding 68). Evidence: `demo/out/uc03.json`; `node demo/uc03-recovery/verify.js` states which verification route is in it.

**Corrections to the earlier build steps `[LIVE]`** (the old text was wrong, do not follow it):
- There is no `resetpassword` / validator / complete API: those paths return the console login page. Self-service recovery is Verify's **hosted "Forgot password"**, which is OFF by default (`CSIAH0325E`) and is switched on through the Cloud Directory identity source (finding 61).
- There is no `/agent` route in the TrustMeInsurance app. The agent console is a standalone stub on `:4030`, as for UC-14.
- `geoLocation` is accepted by the policy API but was never evaluated (finding 67). `ipAddress` is evaluated and is what the demo uses.
- There is no `filter_key` for events. Events ignore `search`/`filter`; the console reads a time window and filters client-side (finding 66).

**What was built** (`node demo/uc03-recovery/setup.js`, `run.js`, `verify.js`, `serve.js`, `teardown.js`)
1. Tenant: hosted "Forgot password" switched on (`setHostedPasswordReset(true)` in `demo/lib/idempotent.js`; `teardown.js` and `teardown-all.js` switch it back off). API client `ifc-demo-uc03-recovery-console` with 6 measured entitlements (finding 65). Users `ifc-demo-uc03-sophie|marc|lena`, each with a disposable mail.tm mailbox so scripts read the real Verify e-mails. Marc's TOTP is enrolled fresh at setup (the "recent factor change" signal). Apps `ifc-demo-uc03-portal` and `-signin` and policy `ifc-demo-uc03-risk-signin` (step-up to TOTP when the sign-in is NOT from the usual network, `ipAddress` NOMATCH).
2. Risk (IFC-side, `stubs/recovery-console/recovery.js` `assess`): reads Verify signals (SCIM lock and last login, factor `created`, events device/IP/country) and scores 3 rules: authenticator added in the last 24 h, recent attempt from a never-seen device, from a never-seen country. A new IP alone and a lock are information, not score. HIGH routes to the agent, LOW to self-service. The customer only learns the route.
3. Self-service (LOW): the hosted flow (finding 62): "Forgot password" -> e-mail link (30 min, single use) -> new password. It ends old sessions and clears a lock (finding 63).
4. Agent-assisted (HIGH): the agent cannot reset until the caller is verified. Verify e-mails a one-time code to the address ON FILE (the agent cannot change it; a factor added inside the recent window is not accepted as proof); then `passwordResetter` (temporary password e-mailed, never seen by the agent) plus `DELETE /v1.0/auth/sessions/{id}`. One verification allows one reset.
5. Audit: `GET /v1.0/events` filtered client-side for the user: sign-ins with device/IP/country, the reset (`CSIAI1027I`, who = the console client), the hosted reset steps; plus the console's own case log.

**Proven `[LIVE]` (run.js, 61 checks, scenarios A to H):** least privilege and 403s; the 7 rule cases on synthetic data; `ipAddress` step-up on a real hosted sign-in; low/high routing from real events (events readable after 12 to 17 s); the whole hosted reset (policy and mismatch errors, old password and old token dead, lock cleared, link single use, unknown user same answer, flood stopped by `CSIAH0327I`); agent reset with verification gate, wrong code refused, temporary password mail, `CSIAQ0267E`, sessions ended, reset-alone-leaves-token-active (F2); audit rows.

**Left for you `[HUMAN]`**
- Run `node demo/uc03-recovery/setup.js && node demo/uc03-recovery/serve.js` and do the click path in `DEMO-RUNBOOK-UI.md` UC-03 once with a person in a browser (the hosted pages were driven by a script that follows the same pages).
- If `run.js` says the e-mail OTP was NOT sent (`CSIAP3523E`), wait for the trial quota to reset and re-run it, so the evidence holds the e-mail-code route.
- Ask IBM (section 4): confirm the e-mail OTP quota, enable Adaptive access for a real risk score, confirm `geoLocation` evaluation, and why the self-service reset sends no "password changed" e-mail.

**Operational limits** (do not rehearse in a loop): the hosted reset allows about 2 requests per user in a short window (`CSIAH0327I` afterwards; it cleared in under 16 minutes in one test, and recreating the user did not clear it); the e-mail OTP quota (`CSIAP3523E`); Marc stops being "recent" after 24 h, so run `setup.js` before each demo.

---

### UC-04: Trusted devices (two devices), push, self-service revoke

**Status:** **Built and verified for the server side** with a simulated IBM Verify app: 57/57 `[LIVE]` checks (`demo/out/uc04.json`), `verify.js` PASS, torn down and rebuilt from zero. **A real phone is still `[HUMAN]`** (actual APNs/FCM push, Face ID, the app's screen).

**What was built** (`demo/uc04-devices/`, `stubs/device-portal/`, `demo/lib/verifyDevice.js`)
1. `setup.js`: users `ifc-demo-uc04-marie` and `-olivier`, API client `-device-service` (5 entitlements, row 73), authenticator client `-ifc-mobile-app`, policy `-policy-push` (`signatures`, `ACTION_MFA_ALWAYS`), apps `-app-console` (password grant = the signed-in customer) and `-app-login` (code + PKCE).
2. `run.js`: A least privilege; B the customer registers 2 devices (iPhone, Android) with her own token, QR as PNG; C push confirmation after registration; D approve / deny / fraud with location in the message, latency; E hosted sign-in with 2 devices (choose, approve -> code, deny -> refused); F wrong key / replay / other device / expiry / another customer; G disable and re-enable; H self-service revoke, then push refused and sign-in offers one device; I IFC's own authenticator client; J 4+ devices, entitlement matrix; K audit via events API.
3. `serve.js`: "My trusted devices" portal on `http://localhost:4041` (register by QR or simulated scan, list, push, revoke).
4. `enroll-phone.js` `[HUMAN]`: QR for a real phone, `--push` for a real push, `--status`.

**Proven `[LIVE]`**: rows 69-75. In short: several devices per user, self-service register/list/push/revoke with the customer's own token, isolation between customers, push approve/deny/fraud/timeout, hosted sign-in step-up with device choice, disable/enable, audit events, IFC's own authenticator client.

**Left for you `[HUMAN]`**
- Install **IBM Verify** on 1-2 phones. `node demo/uc04-devices/enroll-phone.js` (scan; run it again for the second phone or a second account on one phone), then `node demo/uc04-devices/enroll-phone.js --push` and tap Approve.
- Look at the real push on the phone: does it show the location (`originLocation`) and the message you sent? Note it in the runbook.
- Ask IBM (section 4): Firebase / APNs / Salesforce Marketing Cloud credentials for IFC's own app (not settable through the API), number matching (flag accepted, no effect), any per-user device cap above 13.

**Corrections to this guide made by the build:** the old "unproven that one user can hold two registrations" is answered (yes); the old fallback "one registered authenticator per user" in the runbook is not needed; push needs `authnAnyUser`, not `mfaPush`; the push body needs `logic` and the signature id; `PATCH` needs json-patch.

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

**Status: BUILT, PARTIAL.** Built and verified end to end against the tenant with e-mail OTP and authenticator-app (TOTP) step-up (32/32 scripted checks, `demo/out/uc06.json`). **Push approval and passkey step-up are not proven**: they need a phone / browser `[HUMAN]`. Details and exact commands: `demo/uc06-voice/README.md`.

**Built**
- `stubs/voicebot-ccaas/server.js` (+ `backends.js`): `/call /identify /challenge /verify /stepup /stepup/verify /stepup/status /transaction /transcript`, plus mock Billing, Client 360 and Policy-change APIs. Started in-process by `run.js` / `caller.js` (port 4030 if run alone).
- `demo/uc06-voice/`: `setup.js`, `run.js`, `caller.js`, `enroll-phone.js`, `verify.js`, `teardown.js`, `README.md`.
- Tenant objects: user `ifc-demo-uc06-marie`, her TOTP enrolment, API client `ifc-demo-uc06-ccaas` (5 entitlements; the admin client has 165).

**Proven `[LIVE]`**
- OTP generate: `POST /v2.0/factors/emailotp/transient/verifications` with `{correlation, emailAddress}` returns 201 (`id`, `expiry` 5 min, `retries: 4`) and a real e-mail is sent.
- OTP validate: `POST .../verifications/{id}` with `{otp}` returns 204 on success. The user types only the digits **after** the `NNNN-` prefix (typing the prefix gives `CSIBN0018E`). Wrong code `CSIBN0021E`; the 5th wrong attempt returns `CSIBN0080E` and the transaction is `FAILED`; a later attempt returns `CSIBN0025E`.
- "Code from the in-app generator": `POST /v2.0/factors/totp` `{userId, accountName, enabled}` (201, `attributes.secret` returned once), verify with `POST /v2.0/factors/totp/{id}` `{otp}` (204). One enrolment per user (`409 CSIBN0019E`). A used code is rejected (replay), windows -1/0/+1 are accepted, repeated wrong codes give `429 CSIBN0081E` and clear by themselves in about 20 s.
- SCIM lookup, risk tiering (sensitive request refused without step-up, one step-up approves one action), lockout hand-over, and a least-privilege CCaaS API client.
- Least-privilege entitlements, measured with 403 probes: `readUsers` (SCIM lookup), `authnAnyUser` (create/attempt OTP), `readEnrollMFAMethodAnyUser` (list TOTP and push enrolments). `readAuthenticatorsAnyUser` is added for push; **`mfaPush` does NOT enable push (UC-04 row 73): push needs `authnAnyUser`** `[LIVE]`.
- Phone registration QR: `POST /v1.0/authenticators/initiation {owner, clientId, accountName}` with `Accept: image/png` returns a 300x300 PNG.

**Not proven**
- Push: `POST /v1.0/authenticators/{id}/verifications` body `{transactionData{message,originIpAddress,originUserAgent}, pushNotification{title,message,send}, authenticationMethods[{id: <signature enrolment id>, methodType:"signature"}], logic:"OR", expiresIn}`, then poll `GET .../verifications/{txnId}` until `state` is `VERIFY_SUCCESS` (other states: `PENDING TIMEOUT CANCELED USER_DENIED USER_FRAUDULENT BIOMETRY_FAILED VERIFY_FAILED`) `[DOCS]`. A fake authenticator id gives 404 `CSIBH0018E` and a malformed body gives 400, so the route is live; a notification was never sent `[HUMAN]`.
- Passkey step-up `[HUMAN]` (browser + HTTPS origin, see UC-02). The stub returns `501 passkey_not_built`.

**Blocked on this tenant `[LIVE]`**
- **SMS OTP:** `429 CSIAP3545E "SMS messages are not supported for this account"`. **Voice OTP:** `429 CSIAP3546E`. The earlier note in this guide that SMS "is enabled" was wrong; only e-mail OTP works. IFC's text says "OTP or TOTP to the user's device"; the demo uses e-mail OTP and TOTP. Ask IBM to enable SMS if IFC insists on SMS (add to the IBM message).
- `POST /v2.0/factors/otp` (generic OTP, used by IBM's chat-bot sample) returns `501 CSIBN0011E` (feature disabled). The chat-bot sample's `/v1.0/authnmethods/{method}/transient/verification` path returns 404; the working paths are the `/v2.0/factors/...` ones above.

**Human steps `[HUMAN]`:** install IBM Verify; `node demo/uc06-voice/enroll-phone.js` and scan; `node demo/uc06-voice/run.js --push` and approve; `node demo/uc06-voice/caller.js` and read the e-mail OTP from the mailbox.

**Risks:** the e-mail suppression list. A bounce suppresses the address and every later OTP to it fails with `400 CSIBN0075E` (this happened to `example.com` test addresses). Check `GET /v1.0/notification/suppression/email/{address}` (200 = suppressed), clear with `DELETE` on the same path (204).

---

### UC-07: App-to-voice transfer without re-authentication

**Status: BUILT, PARTIAL.** Built and verified end to end against the tenant with a scripted "mobile app" (48/48 scenario checks, `demo/out/uc07.json`; `verify.js` 21 PASS / 0 FAIL / 3 HUMAN). **Not executed:** a real browser login to `TrustMeInsurance` followed by the "Speak with a Voicebot" button, push approval for the sensitive request, passkey, and a real CCaaS vendor `[HUMAN]`. Details and exact commands: `demo/uc07-handoff/README.md`.

**Built**
- `stubs/voicebot-ccaas/server.js` (UC-06 stub, extended): `POST /handoff`, `GET /agent/:callId`, `GET /handoff/latest`; `/transaction` and `/stepup` re-introspect the app token on every request (the "session bridge"). Reuses the UC-06 back-end mocks; new customer `ifc-demo-uc07-marie`, policy `AUTO-77120`.
- Demo app: `routes/ifc-handoff.js`, `views/insurance/call-us.hbs`, a **Help** link in `views/layout.hbs`, mounted at `/app/call-us` in `app.js`. The server posts the session's access token to the voicebot; the token is never rendered or returned to the browser.
- `demo/uc07-handoff/`: `setup.js`, `run.js`, `serve.js`, `voice.js`, `verify.js`, `teardown.js`, `README.md`.
- Shared helpers added (not duplicated per UC): `oauthClient()` and `send()` in `demo/lib/verify.js`; `ensureTotp`, `ensureStsClient`, `ensureDcrClient`, `delete*ByPrefix` in `demo/lib/idempotent.js`; `totpPlayer()` in `demo/lib/totp.js` (UC-06 now uses it too; re-verified 32/32).
- Tenant objects: user `ifc-demo-uc07-marie` + TOTP, API client `ifc-demo-uc07-ccaas` (5 entitlements), STS client `ifc-demo-uc07-ccaas-sts` (300 s tokens), application `ifc-demo-uc07-mobile-app` (DCR, password grant).

**Proven `[LIVE]`**
- **Validate the app's token:** `POST /oauth2/introspect` (HTTP Basic with the STS client) returns `active:true`, `sub`, `amr`, `exp`, `client_id`, `grant_type`. Garbage or tampered token: `active:false`. Wrong client secret `401 CSIAQ0155E`.
- **Token exchange (RFC 8693):** `POST /oauth2/token` (or `/v1.0/endpoint/default/token`) with the STS client, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `subject_token_type`/`requested_token_type` = `urn:ietf:params:oauth:token-type:access_token` returns 200 with a token of the configured lifetime (300 s), same `sub`, `grant_type` token-exchange. A revoked or tampered subject token returns 400 `CSIAQ0158E`.
- **No OTP for tier 1**, step-up kept for tier 2 (TOTP proven), one step-up approves one action.
- **Session bridge ends at once:** `POST /oauth2/revoke` on the app token, next voicebot request refused after 0.3 s; SCIM `PATCH active=false`, refused after 1.0 s and a new login is refused.
- Policy fallback (old app login goes to a code), replay of a voice-channel token as an app token is refused, least privilege (403s), the demo-app route and view with a stand-in session.

**Corrections to the earlier plan `[LIVE]`** (the guide's UC-07 text and the feasibility doc were wrong on these)
- `audience=ccaas` is **ignored**: the exchanged token's `aud` is the STS client id.
- **No `act` claim** is produced, even with an `actor_token`. (`actorTokenRequired:true` makes the actor mandatory, `CSIAQ5242E` otherwise.)
- The exchanged token is **not revoked** when the original is revoked (still `active:true`); it **is** killed by user deactivation. So the bridge checks the app token, not the voice token.
- Access tokens cannot be validated offline (the payload is opaque); introspection is the validation API. The ID token is a JWT (RS256) with `amr`.
- Introspection has no `auth_time` or `acr`; "fresh login" is judged from `iat` `[INFER]`.
- STS lifetime field is `tokenSettings.accessTokenLifetime` (`accessTokenExpiry` gives `CSIAQ0010E`).
- Any API client (even 1 entitlement) can call `/v1.0/endpoint/default/introspect` for another client's token, so API-client credentials are as sensitive as the STS secret.

**Human steps `[HUMAN]`**
1. Browser path: `node demo/uc07-handoff/setup.js`, restart the app (`node ./bin/www`), `node demo/uc07-handoff/serve.js`, sign in at `http://localhost:3000` as `ifc-demo-uc07-marie` (password in `demo/out/uc07.state.json` `user.password`), **Help** > "Speak with a Voicebot", then `node demo/uc07-handoff/voice.js`. If it works, the real-app-client token is proven; if the hand-off is refused, run `node demo/uc07-handoff/run.js` to confirm the tenant side and send me the output.
2. Push step-up: same phone enrolment as UC-06.

**Open risk:** IFC's text keeps "User enters the OTP received via Voicebot" in the UC-07 main flow, which contradicts the title. The demo skips it for a valid app session and uses it as the fallback. Confirm with IFC.

---

### UC-08: SSO across apps and global logout

**Status: BUILT, PARTIAL.** Everything the tenant does is proven by script (37/37 checks, `verify.js` 14 PASS / 0 FAIL / 3 HUMAN). Not executed: the same flow in a real browser, back-channel delivery (needs a tunnel), idle/absolute timeouts (no API).

**Built**
- `stubs/rp-sso/server.js`: a small OIDC relying party (code + PKCE, RS256 ID-token check against the tenant JWKS) with `/login`, `/callback`, `/protected`, `/logout` (global), `/local-logout`, `/frontchannel-logout`, `/backchannel-logout`, `/bc/:name`, `/_events`. Three instances: portal :4001, claims :4002 (brokers only, introspects each request), quote :4003 (high assurance).
- `demo/uc08-sso/`: `setup.js` (`--backchannel https://<public>` switches logout mode), `browser.js` (scripted browser: cookie jars, hosted login, TOTP page, front-channel iframes), `run.js` (scenarios A-H), `serve.js`, `verify.js`, `teardown.js`, `README.md`.
- Helpers added to `demo/lib/idempotent.js`: `updateApplication`, `ensureGroupMember`, `ensurePolicy`, `deletePoliciesByPrefix`.
- Tenant objects: groups `ifc-demo-uc08-brokers`/`-consumers`, users `ifc-demo-uc08-broker` (+ validated TOTP) / `-client`, policies `ifc-demo-uc08-policy-standard` (brokers TOTP once per SSO session) / `-high` (brokers TOTP at every sign-in), applications `ifc-demo-uc08-rp-portal`/`-claims`/`-quote` (token 7200/900/1800 s).

**Proven `[LIVE]`** (details in findings 27-30 above)
- One login, three apps: same `sid`, one session in the sessions API, no second password prompt; per-app assurance (broker TOTP once, again at the high-assurance app; policyholder never).
- App-side persona authorization: claims app answers 403 to a policyholder.
- Global logout from one app clears all three apps, the Verify session list, the access token (`active:false`), the refresh token (`invalid_grant`); the next visit shows the login page. Local logout contrast: app-only logout leaves the Verify session and the app silently signs back in.
- Admin session kill (`DELETE /v1.0/auth/sessions/{id}`): tokens die at once; an app that introspects per request returns 401, an app trusting its own session still returns 200 (honest gap; back-channel closes it `[DOCS]`).
- `prompt=none` / `max_age` behave correctly. DCR accepts `backchannel_logout_uri`; logout with an unreachable receiver still completes (about 650 ms). The RP back-channel handler rejects garbage, an ordinary ID token and tampered tokens.

**Corrections to the earlier plan `[LIVE]`**
- `backchannel_logout_uri` in DCR is accepted (was "[DOCS] test"), but only when `frontchannel_logout_uri` is **not** also sent.
- "Session-policy has no API" was `[INFER]`; it is now `[LIVE]` (all candidate paths return the console login page).
- The build step "RPs need public URLs" applies to **back-channel only**. Front-channel logout works on localhost, because the browser calls the apps.
- Step 5 of the old plan (sessions API before/after) is done: `GET /v1.0/auth/sessions/{userId}`; `GET /v1.0/auth/sessions` without a user is 405.

**Human steps `[HUMAN]`** (commands in `demo/uc08-sso/README.md`)
1. Real browser: `node demo/uc08-sso/setup.js && node demo/uc08-sso/serve.js`, sign in at :4001 as the broker (password in `demo/out/uc08.state.json` `users.broker.password`, TOTP from `totp.secret`), open :4002 and :4003, log out of one.
2. Back-channel: `brew install cloudflared`, `cloudflared tunnel --url http://localhost:4001`, `node demo/uc08-sso/setup.js --backchannel https://<public>`, `node demo/uc08-sso/serve.js`, repeat, check `http://localhost:4001/_events`.

**Open risks:** idle/absolute timeouts have no API (use per-app token lifetimes, or ask IBM whether they are console-only); front-channel logout depends on the browser staying open about 3 s.

---

### UC-09: API security

**Status: BUILT and VERIFIED (2026-11-10).** 25/25 live checks pass (`demo/uc09-api/run.js`), verified by `demo/uc09-api/verify.js`, torn down and rebuilt from zero. mTLS client authentication is **NOT possible** on this tenant host: the handshake sends no `CertificateRequest` `[LIVE]`. The demo uses `private_key_jwt` and DPoP instead.

**Proven `[LIVE]`:**
- `private_key_jwt` machine client: client assertion (`aud` = `<tenant>/oauth2/token`) gets a bearer token; the API accepts it (200). Wrong key → 401 `invalid_client` (CSIAQ5064E).
- Scope comes from the client registration, not from the request (a scope not registered is not granted; the API returns 403 `insufficient_scope`).
- An unlisted, registered machine client gets a Verify token, and the API refuses it (403).
- DPoP-bound tokens: a bearer replay without a proof → 401; a proof from another key → 401 (`key_not_bound_to_token`).
- Key rotation with zero downtime: JWKS holds old and new keys (both 200); after the old key is removed it is refused (401), the new one still works.
- On-behalf-of: the policyholder's token is exchanged (RFC 8693) with a partner actor token, requesting `scope=ifc.policy.read`. The exchanged token has `sub` = policyholder and `client_id` = the partner STS client. The API accepts it for the policyholder's own policy (200) and refuses another policyholder's policy (403).
- Exchange without an actor token → 400 CSIAQ5242E (`actorTokenRequired=true`).
- TLS handshake to the tenant: no `CertificateRequest` (check J).

**Not proven / limits `[LIVE]`:**
- **No `act` claim.** The exchanged token is opaque; introspection does not return the actor. The demo does not claim the partner is recorded as actor. Control = the requested scope plus the policyholder check.
- **`actorCriteria` (CEL) is not enforced.** It is stored as `{}`; an actor the policy would disallow still gets a token. The demo does not claim a partner allow-list on the exchange.
- **mTLS client auth is not possible** on this host (see Status). Not demonstrated.
- The protected API is a local stub (`stubs/ifc-api`) standing in for IFC's gateway.

**Build (as built):** `demo/uc09-api/common.js` (names, constants), `jwt.js` (RS256 client assertion and DPoP), `setup.js` (idempotent: DCR clients `ifc-demo-uc09-m2m-pkjwt`, `-m2m-dpop`, `-m2m-rogue`; STS client `ifc-demo-uc09-partner` with `actorTokenRequired=true`; policyholder user and password-grant app), `serve.js` (stub on 127.0.0.1:4040), `run.js` (scenarios A–J), `verify.js` (reads evidence, secret scan, limits), `teardown.js`, `README.md`. Stub: `stubs/ifc-api/server.js`.

**Human steps:** none for the API flows (terminal only). IBM-side question only if IFC requires mTLS: ask IBM whether the tenant can enable a client-certificate edge option `[HUMAN]`. Until then mTLS is not demonstrated.

---

### UC-10: Per-brand login

**Status: PARTIAL, built and verified (2026-11-11).** 49/49 live checks pass (`demo/uc10-brands/run.js`), `verify.js` 19 PASS / 0 FAIL / 5 HUMAN, torn down and rebuilt from zero. Per-brand policy, language, per-brand customers and delegated administration are proven. **Brand look (theme), consent wording and custom IdP domains are NOT proven**: branding is refused on the trial and custom domains are an IBM matter.

**Proven `[LIVE]`**
- Two brands (fictional Aurora Insurance, Boréal Assurance) = two applications, own client id and redirect host (`aurora.localhost:4101`, `boreal.localhost:4102`), one tenant, one identity: the same `sub` at both.
- Brand policy: Aurora password only (`login`); Boréal password then the authenticator-app page in French (`login,totp`, "Utiliser une autre méthode").
- Language: EN and FR on the login, second-factor and error pages via `ui_locales` / `Accept-Language`.
- Per-brand customers: `all_users_entitled:false` plus per-user entitlement; a non-entitled customer gets `CSIAQ0279E` in French.
- Delegated admin: each brand's owner sees and manages only their application and its customers (revoke/restore effective at once), is refused on the other brand and on tenant-wide APIs (see finding 32).
- Theme ZIPs (brand colour, logo, EN/FR labels, legal text, support link) are built offline from `ci-theme/` and inspected. They are READY, not APPLIED.

**Not proven / limits `[LIVE]`**
- Theme registration: 403 `CSIAZ3060E`. The success path was never executed; the Verify pages stay IBM-styled (only the language changes).
- Custom IdP domains, per-brand sender domain, sub-tenants: unavailable or IBM-only (finding 36).
- Delegated admin cannot change the brand's policy or theme; owners can read all users and the other brand's customer list; `themedeveloper` is tenant-wide.
- Group entitlements do not gate sign-in; consent wording needs a theme; one browser has one session across brands.
- `[INFER]` Registration and recovery pages per brand come from the same themes, so the same enablement applies. Not tested.

**Corrections to the earlier plan `[LIVE]`**
- "Delegated admin: nothing scopes admin to a brand" was wrong: application owners give per-application scope (with the limits above).
- "Languages need the theme" was wrong: the default pages localize.
- `make-themes.sh` / `register-themes.js` became `themes.js` (build + try to register) in `demo/uc10-brands/`; `demo/teardown-all.js` also sweeps themes.

**Build (as built):** `demo/uc10-brands/common.js`, `themes.js`, `setup.js` (idempotent), `run.js` (scenarios A-I), `serve.js`, `verify.js`, `teardown.js`, `README.md`. Stub: `stubs/brand-portal/server.js`. Helpers added to `demo/lib/idempotent.js`: `appIdOf`, `listAppEntitlements`, `ensureAppEntitlement`, `removeAppEntitlement`.

**Human steps `[HUMAN]`** (commands in `demo/uc10-brands/README.md`)
1. Real browser: `node demo/uc10-brands/setup.js && node demo/uc10-brands/serve.js`, open `http://aurora.localhost:4101` and `http://boreal.localhost:4102`, sign in as `ifc-demo-uc10-customer` (password in `demo/out/uc10.state.json` `users.customer.password`, TOTP from `totp.secret`).
2. Passkey at Boréal: register a passkey in a browser, then sign in at Boréal.
3. IBM: enable branding, then `node demo/uc10-brands/themes.js`; ask about several custom IdP domains, per-brand sender domain, per-brand partitioning of users and admins.

**Open risks:** the brand look is the visible part of UC-10 and stays IBM-styled until IBM enables branding; custom domains are unconfirmed.

---

### UC-11: Legacy IAM migration

**Status: PARTIAL, built and verified (2026-11-11).** 52/52 live checks pass (`demo/uc11-migration/run.js`), `verify.js` 11 PASS / 0 FAIL / 5 HUMAN, torn down and rebuilt from zero. **Bulk migration, bulk with forced reset, rollback, linkage preservation and a just-in-time pattern are proven. The just-in-time part is a gateway pattern in front of Verify, not a native Verify feature on this tenant** (Flow designer off, Bridge not creatable). IFC's real legacy hash format is unknown.

**Proven `[LIVE]`**
- Bulk: legacy extract -> CSV with pre-hashed passwords -> `POST /v2.0/CSV/importUsers` -> job report. Customers sign in with the **original** password, no reset (4 policyholders/brokers, 4 hash formats in the run; 9 formats in the matrix, finding 39).
- Bulk with reset: the import without the no-reset header forces a password change on the hosted Verify page (finding 41).
- Bad data is reported per row (`CSIAI0096E`) while the good rows import; re-running changes nothing (`CSIAI0047E`).
- Linkage: legacy customer id (`externalId`), policy number (`accountId`), brokerage (`department`) and broker id (`employeeNumber`) are preserved and queryable (finding 42).
- JIT pattern: first login verifies against the legacy store, creates the user (Verify re-hashes), carries the linkage; afterwards the legacy store can be switched off. Covers formats the import cannot read (`{PBKDF2}`, `{SMD5}`) and legacy passwords below the new minimum (asks for a new one).
- Rollback: delete migrated users, legacy store untouched, customers migrate again. The migration tooling runs as a 2-entitlement API client and is refused elsewhere (403).

**Not proven / limits `[LIVE]`**
- Native JIT inside Verify: Flow designer 403 `CSIBZ0098E`; Bridge `onpremagents` 404 `CSIBS0035E`, create 401 `CSIBS0033E` (finding 43). IBM must enable it.
- IFC's legacy algorithm, volume (only 11 records tested), import limits, the official hash-prefix list, and a prior financial-services migration reference (the PDF asks for it): `[HUMAN]` / IBM.
- A person has not looked at the gateway page or the hosted change-password page in a browser (only a scripted browser has).

**Corrections to the earlier plan `[LIVE]`**
- "Run the Bridge agent with Podman" is not the blocker: the agent configuration cannot be created (401), so it is an IBM enablement, not an image pull.
- "`{SSHA256}` is the only documented prefix / the helper uses `{SHA256}`": nine prefixes work, three popular ones silently do not (finding 39).
- "`GET /v2.0/CSV/importStatus`": the job endpoint is `/v2.0/CSV/jobs/{id}`; the multipart field is `file`.

**Build (as built):** `stubs/legacy-auth-store/{hashes,server}.js`, `stubs/migration-gateway/server.js`, `demo/uc11-migration/{common,setup,bulk,rollback,run,serve,show,verify,teardown}.js`, `README.md`. No change to `demo/lib` (all helpers reused).

**Human steps `[HUMAN]`** (commands in `demo/uc11-migration/README.md`)
1. Browser pass: `node demo/uc11-migration/setup.js && node demo/uc11-migration/serve.js`; open `http://localhost:4051`, sign in as `ifc-demo-uc11-jean` (password in `demo/out/uc11.state.json`, `users.jean.password`), then `node demo/uc11-migration/bulk.js` and `http://localhost:4051/portal-login` as `ifc-demo-uc11-rene`.
2. Ask IFC for their legacy hash algorithm, user and broker volumes, and legacy password rules.
3. IBM: Flow designer or the Bridge external-authentication agent, official hash list, import limits, migration reference.

**Open risks:** the headline ask ("verify against the legacy store transparently") is a pattern IFC would run in their own login layer unless IBM enables Flow or the Bridge; say so before IFC finds out.

---

### UC-12: ReBAC

**Status: PARTIAL, built and verified (2026-11-11).** 53/53 live checks pass (`demo/uc12-rebac/run.js`), `verify.js` 16 PASS / 0 FAIL / 4 HUMAN, torn down and rebuilt from zero. The access decisions, the instant reassignment, the "all resources I can access" and "who can access" queries, and the audit trail are proven against the real tenant. **Not Verify-native** (Verify authenticates, OpenFGA authorizes), and the PDF's **token-minting callout is not possible on this tenant**. It is "built" rather than "partial" for everything the gateway pattern covers; it is labelled PARTIAL because one of the PDF's two mechanisms cannot be shown and IFC's real model is unknown.

**Proven `[LIVE]`**
- Real sign-in (password grant) and real token introspection by a gateway that uses its **own STS client**, never the admin client (finding 46).
- **Inherited access** (brokerage → broker → client → policy): the placing broker reads and edits; a manager of the brokerage reads but cannot edit; a broker or manager of the other brokerage is refused (403) with the reasoning path in the answer. Zoe (valid account, no brokerage) is authenticated but sees nothing: authenticated is not authorized.
- **Reassignment with no re-login:** Anna moves to the other brokerage, and with the same access token she goes from 200 to 403 on the next call (a graph write of 1 tuple added and 1 removed, ~6 ms, plus ~0.45 s for the directory PATCH). A new sign-in then carries the new `department`, the old token still carries the old one. Moving back restores it. Moving with her book of business transfers the clients' visibility, and the managers of both brokerages change accordingly.
- **A broker who leaves loses access immediately** while the clients stay with the brokerage and its manager (finding 48). Client transfer between brokers is one graph transaction.
- **"All resources this user can access"** (`list-objects`) and **"who can access this resource"** (`list-users`), plus an audit log (who, action, policy, allow/deny, reason, path, introspection and check times).
- **Identity layer wins:** SCIM-deactivating a user makes the token introspect `active:false`, so the gateway answers 401 even though the graph still says allow (finding 46).
- Exhaustive cross-check: all 30 broker × policy cells (view and edit) from the engine equal an independent oracle computed from the source data, after every change; the same 30 decisions through the gateway with real tokens also match.
- Scale smoke test, in memory: 8,120 relationships loaded in ~0.8 s, check ~1 to 6 ms, list-objects ~1 to 2 ms (a hint, not a benchmark).
- A sync job that mirrors source-system changes into the Verify directory runs as a **2-entitlement API client** and is refused admin work (403).

**Not proven / limits**
- `[LIVE]` **Token-minting callout is not possible** (finding 47): attribute functions are built-ins, scripted attribute sources are refused, `tokenResponseMap` in `oidc.properties` is refused. Paid-tier external callouts remain `[DOCS]`; ask IBM. The demo does not need it: the gateway asks the engine on every request, which is what makes changes instant.
- `[HUMAN]` A real browser look at the console and the terminal flow. A headless render proved the page loads, the matrix draws (6 policies × 5 people), and the dropdowns fill; the scripted run proved every API call. No person has looked at it.
- `[HUMAN]` IFC's real roles (assistants, delegates, MGAs, call-centre agents), source of truth, change rate and volume. The model here is the PDF's hierarchy plus a manager role.
- `[INFER]` OpenFGA is the stand-in; IFC may keep its own rules engine. The gateway needs only `check`, `list-objects`, `list-users`.
- `[LIVE]` The engine is in memory, so a restart empties it; `serve.js` rebuilds the graph from the source system on start (that is also the recovery story).

**Corrections to the earlier plan `[LIVE]`**
- "Run OpenFGA with Podman": the Podman VM did not come up on this machine, and it is not needed. A checksummed native binary is used (finding 45). Human item 7 is closed.
- "`seed.js`" and "`reassign.js`" are folded into `setup.js` (users, directory), the graph sync in `stubs/policy-api/source.js`, and `cli.js move`.
- "Gateway stub validates the token with introspection": done with an STS client; no admin credential in the gateway.
- Users and clients are not both mirrored into SCIM: only the 5 brokers and managers are Verify users. Policyholder clients are records in the source system (IFC's policyholders sign in elsewhere, UC-09/UC-10).

**Build (as built):** `stubs/rules-engine/{openfga,model}.js`, `stubs/policy-api/{source,server}.js`, `stubs/policy-api/console.html`, `demo/uc12-rebac/{common,runtime,setup,run,serve,cli,verify,teardown}.js`, `README.md`. No change to `demo/lib`.

**Human steps `[HUMAN]`** (commands in `demo/uc12-rebac/README.md`)
1. Browser look (5 min): `node demo/uc12-rebac/setup.js && node demo/uc12-rebac/serve.js`, open `http://127.0.0.1:4170`, sign in as Anna, read IFC-100001 then IFC-100004, move Anna, read again. Or use `node demo/uc12-rebac/cli.js ...`.
2. Ask IFC for their roles, source of truth, change rate and volumes.
3. IBM: confirm whether external callouts in attribute functions are available on IFC's contract tier.

**Open risks:** the engine is a stand-in, so IFC may ask "is that product part of Verify?" The answer is no. Say it first and position Verify as the identity and token layer.

---

### UC-13: SCIM broker lifecycle and immediate revocation

**Status:** **Built and VERIFIED `[LIVE]`.** 18/18 live checks passing (`demo/out/uc13.json`), `verify.js` PASS, torn down and rebuilt from zero.

**Proven `[LIVE]`:**
- SCIM 2.0 user provisioning with enterprise schema (`department`, `employeeNumber`, `title`, `externalId`).
- In-flight role/department sync via SCIM `PATCH` (HTTP 204).
- Immediate revocation: SCIM `PATCH active=false` causes existing tokens to introspect `active:false` in **0-1 s** (measured ~440 ms `[LIVE]`).
- Downstream resource server immediately rejects revoked tokens with HTTP 401 Unauthorized.
- New token requests immediately fail with HTTP 400 `CSIAQ0281E` ("The account is not active.").
- Active session kill: `DELETE /v1.0/auth/sessions/{id}` returns HTTP 204.
- SCIM reactivation: `PATCH active=true` instantly restores login capability (HTTP 200).
- Operations queue & error triage: failed SCIM operations return standard error codes (404 `CSIAI0070E`, 409 `CSIAI0047E`) with `x-correlation-id` headers, ingested into `stubs/ops-queue`.
- Webhook management API: `POST /config/v1.0/webhooks/` and `GET /config/v1.0/webhooks/` work natively for event notifications.

**Components:**
- `stubs/ops-queue/server.js`: Operations Queue stub & interactive operator dashboard on port 4040.
- `demo/uc13-lifecycle/`: `common.js`, `setup.js`, `serve.js`, `run.js`, `verify.js`, `teardown.js`, `README.md`.

**Human steps:** `[HUMAN]` Webhook delivery to a local development machine requires a public tunnel (ngrok / cloudflared).

---

### UC-14: CIBA agent-initiated authentication

**Status: BUILT and VERIFIED, e-mail channel** (2026-11-12). `demo/uc14-ciba/verify.js` 22/22 automated + 8/8 human-approval checks PASS (`demo/out/uc14.json`, 30 checks, 0 failed). Push channel is `[HUMAN]` (phone) and was not run. The approval itself is always `[HUMAN]`.

**Proven `[LIVE]`**
- CIBA app by API: `POST /v1.0/applications` with `templateId:"1"`, `applicationState:true`, and **inside `providers.oidc.properties`**: `grantTypes.ciba:"true"` and `additionalConfig.backchannelSettings{deliveryMode:"poll", supportUserCode:false, proximityCheck:"disabled", userAuthChannels:["email"]}`. **Correction to the earlier build step:** `additionalConfig` placed beside `properties` (as the old step 1 read) returns an empty 400. Client id/secret come back by `GET /v1.0/applications/{id}` (helper `ensureCibaApp`).
- Full real flow: `POST /oauth2/ciba` (Basic client auth) -> `{auth_req_id, expires_in, interval:5}` -> poll `POST /oauth2/token` -> `authorization_pending` (400, `CSIAQ0249E`) -> the caller gets an e-mail showing the binding message, signs in and approves -> the poll returns an access token and an ID token (28 s in the recorded run). Verify userinfo of the token gives the approver; the console compares it with the caller.
- Errors: unknown user 400 `unknown_user_id` (`CSIAQ5297E`); no hint 400 `CSIAQ5301E`; bad client secret 401 `invalid_client`; **not entitled 403 `CSIAQ0279E`** (same as UC-10: entitle each user with `ensureAppEntitlement`); expired or invented `auth_req_id` 400 `expired_token` (`CSIAQ5298E`).
- `login_hint` = user name (case-insensitive). E-mail address and user id are refused. `requested_expiry` honoured (default 1800 s). Deactivated user is "not found".
- Channels: **only `push` and `email`** (400 `CSIAQ0509` for `sms`). `push` is accepted on the app but a request fails with 400 `CSIAQ5306E` until the user is enrolled in IBM Verify.
- Agent action "unlock": **no unlock endpoint** (404). A SCIM `PATCH` of `pwdAccountLockedTime` does not clear the lock. A **password replace** (`PATCH /v2.0/Users/{id}`, `op:replace`, `path:password`, 204) does; without `usershouldnotneedtoresetpassword:true` the customer must choose a new password at next sign-in (`CSIAQ0267E`). That is the right behaviour for an agent unlock: the agent never knows a usable password. Same password again is refused (`PWD_IN_HISTORY`).
- Lockout: 6 wrong passwords lock the account; the correct password is then refused (`CSIAQ0264E`).
- Audit (`GET /v1.0/events`): the successful CIBA token event carries `binding_message`; the caller sign-in is logged; every pending poll is a failed SSO event (`CSIAQ0249E`), so the console collapses them into a count. **Needs `readReports`** on the API client (with `readUsers` + `manageUsers` only: 403 `CSIAK4300E`).
- The agent console client holds 3 entitlements (`readUsers`, `manageUsers`, `readReports`); the 165-entitlement admin client is not used at runtime.

**What was built:** `demo/uc14-ciba/{common,config,setup,run,serve,lock,verify,teardown}.js` + README, `stubs/agent-console/{agent,server}.js` (agent console on `http://localhost:4140`), `ensureCibaApp` in `demo/lib/idempotent.js`, `ciba`/`cibaToken` in `oauthClient`. Console logic is in one module used by both `run.js` and the web page.

**Not proven / left for you**
- `[HUMAN]` Push channel: install IBM Verify on a phone, enrol the demo user (UC-06 `enroll-phone.js` flow), set the app to `channels:['push','email']` via `ensureCibaApp`. IFC's own example is a push, so this is worth 10 minutes.
- `[HUMAN]` **Locked caller:** while the account was locked, **no approval e-mail was received** for several requests sent in a row (observed once, cause not established; the request itself is accepted with 200). The demo therefore locks the account only AFTER the approval.
- `[INFER]` IFC precondition "agent has a role in the CIAM admin console" is not modelled. The stub uses its own API client. Verify's delegated-admin roles (UC-10 finding 32) are the place to show per-agent roles.
- The 5-minute "verified" window is console logic in memory, not a Verify feature.
- `proximityCheck` (country/state/city) not exercised.

**Run it:** `node demo/uc14-ciba/setup.js`, `node demo/uc14-ciba/run.js` (22 checks, ~30 s, no human), `node demo/uc14-ciba/run.js --approve` (adds the real approval; approve the e-mail whose message ends with the printed `(ref XXXX)`), `node demo/uc14-ciba/verify.js`, live demo `node demo/uc14-ciba/serve.js` then `http://localhost:4140`.

---

### UC-15: Consent management (PIPEDA)

**Status: PARTIAL, BUILT (2026-11-12).** 20/20 `verify.js` PASS, 14/14 `run.js` PASS, torn down and rebuilt from zero. 2 human steps remain (browser consent grant, DUA post-grant check).

**Proven `[LIVE]`:**
- Purpose lifecycle: create, publish (state=1), list, delete (with dissociation), version `[LIVE]`
- Purpose-app association: `PATCH /dpcm-mgmt/config/v1.0/privacy/purpose-relationships` `[LIVE]` — must dissociate before delete (`CSIBT0012E` otherwise)
- Three purposes with per-purpose attribute lists and `defaultConsentDuration`: claims-processing (365 days), fraud-analytics (180 days), marketing (90 days) `[LIVE]`
- DCR: two third-party clients (repair-shop, comparison-site) with different scopes `[LIVE]`
- Password-grant token for test user (ropc enabled on TrustMeInsurance) `[LIVE]`
- DSP: `POST /dpcm/v1.0/privacy/data-subject-presentation` with `subjectId` — returns purpose metadata and consent state `[LIVE]`
- DUA: `POST /dpcm/v1.0/privacy/data-usage-approval` with `subjectId + accessTypeId:read` — `approved:false` before grant, `approved:true` after browser grant `[LIVE]`
- Admin consent ledger: `GET /dpcm-mgmt/config/v1.0/privacy/consents?userId=…` `[LIVE]`

**Key finding — CSIBT0032E `[LIVE 2026-11-12]`:** `PATCH /dpcm/v1.0/privacy/consents` for per-user consent write returns `"This API client can be used to create global consents only."` for both admin tokens and password-grant user tokens. Only a real browser OIDC session (cookie) can write per-user consents. The existing demo app `/consent` route works correctly. **DPCM write is a browser-path only on this trial tenant.**

**DSAR stub:** inline in `run.js` — record request, call consent + user delete APIs, stamp completion. Not a Verify native workflow.

**Files:** `demo/uc15-consent/common.js`, `setup.js`, `run.js`, `verify.js`, `teardown.js`, `serve.js` (dashboard on :4151), `README.md`.

**Human steps:** `[HUMAN]` (1) Sign in as `ifc-demo-uc15-policyholder` in the app, toggle communication preferences, save. (2) Re-run `run.js` to prove DUA passes after the browser grant.

---

## 3. Human-only checklist (what you must do, in order)

| # | Action | Unblocks | Effort |
|---|---|---|---|
| 1 | **Email IBM now** (template in section 4). | UC-01 Track B, UC-05, UC-10, UC-11 | 10 min to send, days to get answers |
| 2 | Install **IBM Verify** app on 1-2 phones. For UC-06: `node demo/uc06-voice/enroll-phone.js`, scan, then `node demo/uc06-voice/run.js --push`. | UC-04 (`enroll-phone.js`, twice), UC-06, UC-14 push | 10 min |
| 3 | Create a **public tunnel** (ngrok/cloudflared) for webhooks and back-channel logout. | UC-05, UC-08, UC-13 | 15 min |
| 4 | **Closed (finding 59):** no `mkcert` / hostname needed for UC-02. | UC-02 | 0 |
| 5 | Provide a test mailbox you can read (or several aliases). UC-01 browser pass: `node demo/uc01-registration/serve.js`, open `http://localhost:4011` (steps in UC-01 above). | UC-01, UC-03, UC-06, UC-14 | 5 min |
| 6 | Run the passkey ceremony once in a real browser: `node demo/uc02-passkeys/setup.js && node demo/uc02-passkeys/serve.js`, add a passkey at `https://trialverify.verify.ibm.com/usc/` as `ifc-demo-uc02-alice`, sign in at `http://localhost:4023` (steps in `demo/uc02-passkeys/README.md`). | UC-02 | 15 min |
| 7 | **Closed (finding 45):** OpenFGA runs as a checksummed native binary, no Podman needed. Replaced by item 12 below. | UC-12 | 0 |
| 8 | UC-07 browser path: sign in to the demo app as `ifc-demo-uc07-marie`, Help > "Speak with a Voicebot" (steps in UC-07 above). | UC-07 | 5 min |
| 9 | UC-08 real browser + back-channel: `node demo/uc08-sso/serve.js`, then tunnel and `setup.js --backchannel` (steps in UC-08 above). | UC-08 | 15 min |
| 10 | UC-10 real browser: `node demo/uc10-brands/serve.js`, open `aurora.localhost:4101` and `boreal.localhost:4102` (steps in UC-10 above). | UC-10 | 5 min |
| 11 | UC-11 browser pass: `node demo/uc11-migration/serve.js`, sign in at `http://localhost:4051` as `ifc-demo-uc11-jean`, then `bulk.js` and `/portal-login` as `ifc-demo-uc11-rene` (steps in UC-11 above). Tell IFC to name their legacy hash algorithm. | UC-11 | 10 min |
| 12 | UC-12 browser look: `node demo/uc12-rebac/setup.js && node demo/uc12-rebac/serve.js`, open `http://127.0.0.1:4170`, pick Anna, Sign in, read IFC-100001 (allowed) then IFC-100004 (refused), move Anna to BRG-B, read again (refused with the same token), Reset. Ask IFC for their roles, source of truth and volumes. | UC-12 | 10 min |

## 4. Message to IBM (copy/paste)

> Tenant `trialverify.verify.ibm.com` (EU trial) for the Intact RFP technical evaluation. Please enable:
> 1. Flow designer (API reports "not subscribed: CI-49771") and User forms.
> 2. Branding/themes (trial returns CSIAZ3060E).
> 3. Adaptive access (Trusteer) and activate Threat detection (config is `inactive`).
> 4. Passwordless (passkey-only) sign-in on the Cloud Directory login page (the API route returns CSIAH0026E "not authorized to use passkey for passwordless login"; `passwordless.fido` stays false).
> 5. SMS and voice OTP delivery (API returns CSIAP3545E / CSIAP3546E "not supported for this account"); a customer SMS gateway via `external_sms` webhook + SMS provider already works (finding 58); please confirm quota for IBM's own SMS.
>
> Please also confirm: (a) multiple custom IdP domains on one tenant; (b) delegated admin scoped to a subset of users (application owners are scoped per app but can read all users); (c) mTLS client authentication endpoint on SaaS; (d) the official list of password-hash prefixes for CSV import (we measured nine that work and `{SMD5}`, `{SHA1}`, `{PBKDF2}` that import without error but do not sign in), and enable Flow designer or provision the Verify Bridge external-authentication agent (`POST /config/v1.0/onpremagents` returns 401 `CSIBS0033E`) for native just-in-time migration; for UC-03 (h) the e-mail OTP quota behind 429 `CSIAP3523E` on `/v2.0/factors/emailotp/transient/verifications`, (i) whether the `geoLocation` access-policy condition is evaluated and which attribute names it takes, (j) why the hosted Forgot-password reset sends no "password changed" e-mail although the page says it does, and (k) whether the hosted Forgot-password link can be made risk-aware; (e) whether one user can register more than one IBM Verify authenticator; (f) a prior financial-services migration reference; (g) the external-callout (HTTP) capability in attribute functions on a paid tenant.

## 5. Recommended build order (updated by live findings)

1. **Foundation** (`demo/lib`, `00-probe.js`, `teardown-all.js`): **done**.
2. **UC-01 (Track A), UC-09, UC-13, UC-14, UC-15 built and verified.** UC-15 next human steps: browser consent grant (5 min).
3. **UC-07 (built, browser login pending), UC-06 (built, push pending a phone), UC-03 (built, partial: one browser pass and the e-mail-code route re-run pending)** (UC-01 Track A is built and verified).
4. **UC-08 (built, browser + tunnel pending)**, **UC-02 (built, partial: real-device passkey pending)**, then **UC-04 (built and verified with a simulated IBM Verify app; real phone push pending)**.
5. **UC-10 (partial, built; branding and domains need IBM)**, **UC-11 (partial, built; native JIT needs IBM)**, then **UC-12, UC-05** (blocked or partial).

## 6. Changes made to the repo during this session

| File | Change | Why |
|---|---|---|
| `functions.js` | `getPolicyId` and `createMfaPolicy` now use `/v5.0/policyvault/accesspolicy`, the v5 rule schema (`meta`, array conditions, string `action`), and a quoted `search=name="…"` | v3.0 API is gone; `/setup` crashed |
| `functions.js` | `response.statusCode` → `response.status` (4 places) | axios exposes `.status` only |
| `.env` | No change by me (B3 was already fixed) | |
| `demo/lib/*`, `demo/00-probe.js`, `demo/teardown-all.js` | New foundation (token cache, SCIM headers, evidence, idempotent helpers, TOTP, probe table, tenant sweep) | Section 1 |
| `stubs/voicebot-ccaas/`, `demo/uc06-voice/` | New: UC-06 | Section 2, UC-06 |
| `stubs/voicebot-ccaas/server.js`, `backends.js`, `demo/uc07-handoff/` | UC-07: `/handoff`, `/agent`, session-bridge checks, customer `ifc-demo-uc07-marie`, scenario scripts | Section 2, UC-07 |
| `routes/ifc-handoff.js`, `views/insurance/call-us.hbs`, `app.js` (1 require + 1 mount), `views/layout.hbs` (Help link) | UC-07: the "Speak with a Voicebot" button in the demo app | Section 2, UC-07 |
| `demo/lib/verify.js` (`oauthClient`, `send` with DNS retry), `demo/lib/idempotent.js` (TOTP, STS, DCR helpers), `demo/lib/totp.js` (`totpPlayer`), `demo/uc06-voice/{common,setup}.js` | Shared helpers extracted for UC-07; UC-06 behaviour unchanged (32/32) | Section 1 |
| `stubs/rp-sso/`, `demo/uc08-sso/`, `demo/lib/idempotent.js` (4 helpers added) | UC-08: three RP stubs, scripted browser, scenarios, verify/teardown | Section 2, UC-08 |
| `stubs/ifc-api/`, `demo/uc09-api/`, `demo/lib/idempotent.js` (`ensureStsClient` takes `actorRequired`) | UC-09: protected policy API stub (scope, allow-list, DPoP, policyholder rule for delegated tokens), `private_key_jwt` + DPoP machine clients, RFC 8693 on-behalf-of, key rotation, verify/teardown | Section 2, UC-09 |
| `stubs/legacy-auth-store/`, `stubs/migration-gateway/`, `demo/uc11-migration/` | UC-11: legacy store stub (12 hash schemes), gateway JIT pattern, CSV bulk import, forced reset, rollback, 52 live checks, verify/teardown. No shared helper changed | Section 2, UC-11 |
| `stubs/rules-engine/`, `stubs/policy-api/`, `demo/uc12-rebac/` | UC-12: OpenFGA native binary downloader/launcher and model, source-system stub with graph sync, policy gateway with reasoning path and audit log, presenter console and terminal client, 53 live checks, verify/teardown. No shared helper changed | Section 2, UC-12 |
| `demo/lib/verifyDevice.js`, `stubs/device-portal/`, `demo/uc04-devices/`, `demo/teardown-all.js` (authenticator clients added to the sweep) | UC-04: software IBM Verify app, device logic + "My trusted devices" page, 57 live checks, verify/teardown/enroll-phone | Section 2, UC-04 |
| `demo/uc15-consent/` (common, setup, run, verify, teardown, serve, README), `demo/teardown-all.js` (purposes + dissociate) | UC-15: DPCM purpose lifecycle, purpose-app association, DCR, DSP, DUA, admin consent export, DSAR stub; 20 PASS / 0 FAIL / 2 HUMAN; ropc on TrustMeInsurance for user-context token; key finding: CSIBT0032E blocks per-user consent write via API token | Section 2, UC-15 |
| `demo/uc01-registration/`, `stubs/client360/`, `stubs/registration-portal/`, `demo/lib/idempotent.js` (`ensureCustomAttribute`, `deleteAttributesByPrefix`), `demo/teardown-all.js` (attributes, `ifc-demo-*` group members) | UC-01: registration wizard service, Client 360 stand-in, real e-mail OTP, duplicate rules, progressive profiling, 52 live checks | Section 2, UC-01 |


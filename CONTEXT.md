# CONTEXT: where we are (read this first in a new session)

**Last updated:** 2026-11-11 (UC-13 added). **Branch:** `master`. **Repo:** `ci-ciam` (TrustMeInsurance, a Node/Express CIAM demo app for IBM Verify SaaS).

## 1. The mission

I am an IBM pre-sales engineer securing the **technical win for Intact Financial Corp's (IFC) RFP on IBM Verify SaaS**.
IFC asked for **15 use cases** (`IAM Modernization Use Cases.pdf`). We must show which can be demoed and then build the demos.

- **Tenant:** `https://trialverify.verify.ibm.com` (EU **trial**).
- **Split of work:** the assistant **builds demos through API / CLI / scripts** (not by clicking the admin console). The human **presents them on the UI**.
- Never print secrets from `.env`. The assistant is allowed to read it.

## 2. What is DONE

| Item | File | State |
|---|---|---|
| Verify SaaS research and repo knowledge | [`VERIFY-PLAYBOOK.md`](VERIFY-PLAYBOOK.md) | Done |
| Feasibility verdict for each of the 15 use cases and per-use-case plans | [`INTACT-USE-CASE-FEASIBILITY-AND-DEMO-PLAN.md`](INTACT-USE-CASE-FEASIBILITY-AND-DEMO-PLAN.md) | Done. Parts are superseded by live findings (see `DEMO-BUILD-GUIDE.md` section 0) |
| How to build each demo, live-tested facts, blockers, IBM message, build order | [`DEMO-BUILD-GUIDE.md`](DEMO-BUILD-GUIDE.md) | Done |
| How a human presents each demo on the UI, with readiness labels | [`DEMO-RUNBOOK-UI.md`](DEMO-RUNBOOK-UI.md) | Done |
| Repo blocker fixes in `functions.js` | commit `688ecd2` | Done (see section 4) |
| **Demo foundation**: `demo/lib/{verify,idempotent,totp}.js`, `demo/00-probe.js` (12 live checks), `demo/teardown-all.js` | `demo/` | Done, run on the tenant |
| **UC-06 Voicebot**: `stubs/voicebot-ccaas/`, `demo/uc06-voice/` (setup, run, caller, enroll-phone, verify, teardown, README) | `demo/uc06-voice/` | **Built, PARTIAL.** E-mail OTP + TOTP step-up verified live (32/32, `demo/out/uc06.json`). Push and passkey step-up not proven: need a phone / browser `[HUMAN]` |
| **UC-07 App-to-voice handoff**: `demo/uc07-handoff/` (setup, run, serve, voice, verify, teardown, README), `routes/ifc-handoff.js`, `views/insurance/call-us.hbs`, `/handoff` in `stubs/voicebot-ccaas` | `demo/uc07-handoff/` | **Built, PARTIAL.** Verify side proven live: 48/48 scenarios (`demo/out/uc07.json`), `verify.js` 21 PASS / 0 FAIL / 3 HUMAN. Not executed: real browser login to the app (2FA policy), push, passkey `[HUMAN]` |
| **UC-08 SSO and global logout**: `demo/uc08-sso/` (setup, run, serve, verify, teardown, README, browser), `stubs/rp-sso/` | `demo/uc08-sso/` | **Built, PARTIAL.** Verified live: 37/37 scenarios (`demo/out/uc08.json`), `verify.js` 14 PASS / 0 FAIL / 3 HUMAN. Not executed: real browser, back-channel delivery (tunnel), idle/absolute timeouts (no API) `[HUMAN]` |
| **UC-09 API security**: `demo/uc09-api/` (common, jwt, setup, serve, run, verify, teardown, README), `stubs/ifc-api/` | `demo/uc09-api/` | **Built and VERIFIED.** 25/25 live checks (`demo/out/uc09.json`), `verify.js` PASS, rebuilt from zero after teardown. `private_key_jwt` + DPoP + key rotation + RFC 8693 on-behalf-of (scoped, policyholder-only) proven `[LIVE]`. **mTLS not possible on this tenant** (no client-certificate request in the TLS handshake `[LIVE]`). No `act` claim; `actorCriteria` not enforced `[LIVE]` |
| **UC-10 Per-brand login**: `demo/uc10-brands/` (common, themes, setup, run, serve, verify, teardown, README), `stubs/brand-portal/` | `demo/uc10-brands/` | **Built, PARTIAL.** 49/49 live checks (`demo/out/uc10.json`), `verify.js` 19 PASS / 0 FAIL / 5 HUMAN, torn down and rebuilt from zero. Proven: per-brand policy, EN/FR pages, per-brand customers (`all_users_entitled:false` + entitlements), delegated admin via application owners. **Not proven:** brand theme (branding 403 `CSIAZ3060E`; ZIPs built, never registered), custom IdP domains (IBM), passkey (human). |
| **UC-11 Legacy migration**: `demo/uc11-migration/` (common, setup, bulk, rollback, run, serve, show, verify, teardown, README), `stubs/legacy-auth-store/`, `stubs/migration-gateway/` | `demo/uc11-migration/` | **Built, PARTIAL.** 52/52 live checks (`demo/out/uc11.json`), `verify.js` 11 PASS / 0 FAIL / 5 HUMAN, torn down and rebuilt from zero. Proven: CSV bulk import keeping the original password, hash-format matrix, forced reset, linkage attributes kept, rollback, least-privilege migrator, and a **gateway JIT pattern** (IFC would own it). **Not proven:** native JIT (Flow designer 403, Bridge create 401 `CSIBS0033E`: IBM), real browser pass (human), IFC's real hash algorithm, scale (11 records), prior-migration reference. |

| **UC-12 ReBAC**: `demo/uc12-rebac/` (common, runtime, setup, run, serve, cli, verify, teardown, README), `stubs/rules-engine/` (OpenFGA launcher + model), `stubs/policy-api/` (source-system stub, gateway, console UI) | `demo/uc12-rebac/` | **Built, PARTIAL.** 53/53 live checks (`demo/out/uc12.json`), `verify.js` 16 PASS / 0 FAIL / 4 HUMAN, torn down and rebuilt from zero. Proven: real sign-in + introspection with an STS client, inherited access (brokerage → broker → client → policy) with reasoning path, reassignment with the SAME token (200 → 403, no re-login), leave / transfer, list-objects and list-users, audit log, deactivation wins (401), engine == independent oracle on all 30 cells, 8,120-relationship smoke test. **Not proven:** the PDF's token-minting callout (impossible here: built-in attribute functions only), a human look at the browser console, IFC's real roles / source / volume. Not Verify-native: OpenFGA is a stand-in. |
| **UC-13 Broker lifecycle, immediate revocation**: `demo/uc13-lifecycle/` (common, setup, run, serve, verify, teardown, README), `stubs/ops-queue/` (event store & webhook receiver, dashboard UI on `:4040`) | `demo/uc13-lifecycle/` | **Built and VERIFIED `[LIVE]`.** 18/18 live checks (`demo/out/uc13.json`), `verify.js` PASS, torn down and rebuilt from zero. Proven: SCIM 2.0 user provisioning with enterprise attributes (`department`, `employeeNumber`, `title`, `externalId`), in-flight role update via SCIM PATCH (204), **immediate revocation** (`PATCH active=false` causes existing token introspection `active:false` in 0-1s, ~440ms `[LIVE]`), downstream API rejects with 401, new login rejected (`CSIAQ0281E`), active session kill (`DELETE /v1.0/auth/sessions/{id}` = 204), SCIM reactivation (`PATCH active=true`), ops queue error logging with correlation IDs (404 `CSIAI0070E`, 409 `CSIAI0047E`), native webhook configuration API. **Not proven:** real-time SaaS-to-local webhook delivery without a public tunnel (`[HUMAN]`). |
| **UC-14 CIBA agent-initiated authentication**: `demo/uc14-ciba/` (common, config, setup, run, serve, lock, verify, teardown, README), `stubs/agent-console/` (console logic + web page on `:4140`), `ensureCibaApp` in `demo/lib/idempotent.js`, `ciba`/`cibaToken` in `oauthClient` | `demo/uc14-ciba/` | **Built and VERIFIED on the e-mail channel.** 30/30 live checks (`demo/out/uc14.json`): 22 scripted + 8 with a REAL e-mail approval (28 s to approve, tokens issued, userinfo = approver, unlock via password replace, audit with binding message). `verify.js` PASS. Torn down and rebuilt from zero. **Not proven:** push (needs a phone), a locked caller received no approval e-mail (observed once), no per-agent admin role. |

Evidence tags used in every doc: `[LIVE]` executed on the tenant, `[DOCS]` from documentation, `[INFER]` reasoning, `[HUMAN]` a person must do it.

## 3. What is NOT done (important)

**Built so far:** the foundation, **UC-06**, **UC-07**, **UC-08**, **UC-09**, **UC-10**, **UC-11**, **UC-12**, **UC-13** and **UC-14** (see section 2). **Everything else is still only described in the build guide:** the other 6 use cases, the agent page `/agent` (UC-03; UC-14 has its own console in `stubs/agent-console/`), `routes/ifc-register.js`, `routes/passkey.js`. Application code outside `demo/` and `stubs/` is unchanged except the `functions.js` fix.
Nothing has been pushed. Check with `git status` and `git log origin/master..master`.

## 4. Repo state

- Base app: Express + Passport OIDC, Handlebars views, axios-based Verify helpers in [`functions.js`](functions.js). Setup is idempotent: `POST /setup` (also `GET /setup` page).
- Fixes made to `functions.js` (they are in `master`):
  - The access policy calls moved from the removed **v3.0** to **`/v5.0/policyvault/accesspolicy`**, with the v5 schema (`meta`, array `conditions`, string `action`) and a quoted `search=name="…"` filter. The group condition uses `process.env.MFAGROUPID || mfaGroup`.
  - The policy-create response check uses `.status`, not `.statusCode`.
- Repo history note: during the last session the repo changed under us (branch switches and a stash conflict). It was resolved in `688ecd2`. A copy of the old conflicted file is at `/tmp/backup/`, which may not survive a reboot.
- **`node_modules` may not match `master`'s `package.json`.** Run `npm install` before starting the app, then `node ./bin/www` (port 3000). The `/setup` run that proved the fixes happened on this code before the branch shuffle. After the merge it was only syntax-checked (`node --check`), so **re-run `POST /setup` first thing** and confirm it returns 200.
- Demo app routes you can use today: see `DEMO-RUNBOOK-UI.md` section 1.3.

### `.env` (gitignored, do not print values)
Holds working values for: `OIDC_CI_BASE_URI` (no trailing slash), `API_CLIENT_ID` / `API_SECRET` (a privileged API client, **165 entitlements**), `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` (the app, written by `/setup`), `ALLOW_DYNAMIC_SETUP=true`. `API_CLIENT_ID` and `OIDC_CLIENT_ID` are different values on purpose.

### Tenant objects that exist (created by `/setup`)
App `TrustMeInsurance` (callback `http://localhost:3000/oauth/callback`), group `MFAGroup`, access policy `Require 2FA for MFAGroup`, DPCM purposes `communications`, `paperless-billing`, `terms`. Only the tenant admin user exists. One harmless FIDO2 relying party for `https://ifc-demo.example.com` was left behind (it can't be listed).

## 5. Live tenant facts that shape everything `[LIVE]`

Full table: `DEMO-BUILD-GUIDE.md` section 0.1. The ones you must remember:

1. **Flow designer is NOT enabled** (403 `CSIBZ0098E`, feature `CI-49771`). It blocks UC-01 Track B and the flow-based option for UC-11.
2. **Branding is NOT supported on the trial** (403 `CSIAZ3060E`). The app's custom theme can't be registered, so `/setup` falls back to the default theme. It blocks the UC-10 brand look and legal text (FR/EN still works: finding 16).
3. **Sub-tenants are reseller-only** (405 `CSIAG0746E`), so per-brand tenants are not available.
4. **Threat detection config exists but is `inactive`.** Adaptive access (Trusteer) is not confirmed. UC-05 depends on IBM enabling both.
5. **Dynamic client registration works** (`POST /oauth2/register`, `DELETE /oauth2/register/{id}`). `private_key_jwt` with an inline `jwks` was proven end to end (assertion `aud` = `https://trialverify.verify.ibm.com/oauth2/token`). `tls_client_auth` registers, but **mTLS does not work on this host**: the TLS handshake sends no `CertificateRequest`, so no client certificate can be presented (UC-09, 2026-11-10, `[LIVE]`).
6. **CIBA works** if the app is created with `"applicationState": true` (otherwise `invalid_client`).
7. **Immediate revocation proven (UC-13):** SCIM `PATCH active=false` gives 204. The existing token introspects `active:false` within 0 s, and a new login returns `CSIAQ0281E`.
8. **Webhook purposes available:** `identity_proofing`, `external_mfa`, `external_risk`, `notifications`, `external_sms`. `external_risk` is the way to feed IFC's own risk signals into a policy (UC-05). `external_sms` supports the bring-your-own-SMS-gateway ask (UC-02).
9. **Access policy v5.0** accepts the condition types `geoLocation`, `threatInsights`, `trusteer`, `webhooks`, `ipAddress`, and more. Acceptance does not prove the feature is licensed.
10. **No phone is registered** (`GET /v1.0/authenticators` returns 0). The Verify Profile authenticator client id is `5280f51a-9699-4d96-9dd9-bcc0fdfdf9dd`.
11. The Verify Bridge is not configured on the tenant (`GET /config/v1.0/onpremagents` returns 404 `CSIBS0035E`). **Correction (UC-11):** `POST` on it returns 401 `CSIBS0033E` even though the admin client holds `manageExternalAgents`. It is an IBM enablement, not a Podman image question.

12. **SMS and voice OTP are blocked** (`429 CSIAP3545E` / `CSIAP3546E` "not supported for this account"). E-mail OTP works. The earlier statement that the SMS config was usable was wrong. (UC-06, 2026-11-10)
13. **TOTP API works fully** without a phone: enrol, verify (204), replay rejected, windows -1/0/+1, lockout 429 clearing in about 20 s, one enrolment per user. A script can play the authenticator app (`demo/lib/totp.js`).
14. **Least-privilege API clients work:** `POST /v1.0/apiclients` (201, empty body; read the secret via GET). UC-06 uses a 5-entitlement client; out-of-scope calls return 403.
15. **E-mail suppression list bites:** a bounce suppresses the address and OTPs then fail with `400 CSIBN0075E`. `example.com` addresses end up there. `GET`/`DELETE /v1.0/notification/suppression/email/{address}`.
16. **Push to a phone is the one unproven UC-06 call.** Route and validation are live (404 for an unknown authenticator, 400 for a bad body); a real notification needs a registered IBM Verify app.
17. **Introspection works** (UC-07): `POST /oauth2/introspect` with an STS client or the app's own client (HTTP Basic) returns `active, sub, amr, exp, client_id, grant_type, iat`. Garbage or tampered tokens give `{"active":false}`; wrong secret `401 CSIAQ0155E`; no credentials `400 CSIAQ0147E`. Any API client with `readUsers` can call `/v1.0/endpoint/default/introspect` for another client's token.
18. **Revocation and deactivation bite fast:** `/oauth2/revoke` to refusal 0.3 s; SCIM deactivate to refusal 1.0 s (and new logins refused).
19. **Access tokens are opaque.** They look like 3 dot-separated parts but cannot be validated offline; the ID token is an RS256 JWT with `amr`. There is no `auth_time` or `acr`, so freshness comes from the access-token `iat` `[INFER]`.
20. **Token exchange (RFC 8693) works** with an STS client, but `audience` is ignored (`aud` = the STS client id) and there is **no `act` claim**, even with an `actor_token`. `actorTokenRequired:true` makes the actor mandatory (`CSIAQ5242E`). A revoked or tampered subject token gives `400 CSIAQ0158E`. The exchanged token is NOT revoked when the original is revoked; deactivating the user kills both. STS lifetime field is `tokenSettings.accessTokenLifetime`.
21. **Scripted login:** the password grant works on `/oidc/endpoint/default/token` for a DCR client with `grant_types:["password"]` and `all_users_entitled:true`.
22. **The laptop resolver intermittently fails** (`ENOTFOUND` on the tenant host for tens of seconds). `send()` in `demo/lib/verify.js` retries and rethrows message-only errors (axios errors carry the client secret in their config).
23. **SSO and logout (UC-08):** discovery advertises front- and back-channel logout. DCR takes `frontchannel_logout_uri` or `backchannel_logout_uri` (not both: front wins, back is dropped). `PUT <app href>` with the full GET document edits `logoutOption`, `accessTokenExpiry`, `authPolicy`.
24. **Cross-app SSO works:** later apps get a code with no page, all share one `sid`, one entry in `GET /v1.0/auth/sessions/{userId}`. `ACTION_MFA_ALWAYS` re-asks only TOTP; `ACTION_MFA_PER_SESSION` does not re-ask. Policy group conditions match the token's `groupIds`, which holds group **names**. A TOTP enrolment must be validated (`POST /v2.0/factors/totp/{id}` `{otp}` = 204) before login can use it (`CSIAH0640E` otherwise).
25. **Global logout = `rplogout` page in a browser:** it returns an HTML page with an iframe per app and the tenant's own, auto-submits after 3 s. The Verify session is only cleared when that page runs. After it: sessions `{}`, token `active:false`, refresh `invalid_grant`. `DELETE /v1.0/auth/sessions/{userId}` = 204 kills tokens at once but not an app's own cookie.
26. **Correction to 19:** the ID token and userinfo DO carry `auth_time`, `acr`, `amr`, `sid`, `groupIds`; only introspection lacks `auth_time`/`acr`. `state`/`nonce` need 8+ chars. **No session-policy API** (idle/absolute timeouts): every candidate path returns the console login page.

### API gotchas that cost time (put these in `demo/lib/verify.js`)
- SCIM paths (`/v2.0/Users`, `/v2.0/Groups`) need `Content-Type` **and** `Accept: application/scim+json` (otherwise 406 `CSIAI0211E` / 415 `CSIAI0212E`).
- Create test users with header `usershouldnotneedtoresetpassword: true`, otherwise logins fail with `CSIAQ0267E`.
- Apps made through `/v1.0/applications` are disabled unless `"applicationState": true`.
- Password grant is not allowed on the default app client. Use a DCR client with `grant_types:["password",...]` and `all_users_entitled:true`.
- Some endpoints return **HTTP 400 with an empty body**. Log the `x-correlation-id` header.
- STS client create requires `tokenSettings.signingAlg`. The list response uses `clientId`, not `id`.
- Policy search needs `search=name="..."`. `anyfactor` is not a valid `authnMethods` value. `urn:ibm:security:authentication:asf:macotp` works.
- axios responses expose `.status`, never `.statusCode`.
- Token lifetime is about 2 hours (`client_credentials`). Rate limit is about 25 requests per second.
- Name everything `ifc-demo-<uc>-<thing>` so one teardown script can find it.
- `POST /v1.0/apiclients` and `POST /v1.0/sts/oauth/clients` return 201 with an **empty body**. List to find the new object.
- E-mail OTP: the user types the digits **after** the `NNNN-` prefix (`CSIBN0018E` if the prefix is included). 5 attempts max (`CSIBN0080E` on the last).
- `GET /v1.0/applications` list items give `_links.self.href` (`/appaccess/v1.0/applications/{id}`); DCR clients show up there and are deleted with `DELETE` on that href (200).
- SCIM filters `sw` and `and` work. Access-policy `search` only supports `=`, `!=`, `contains` on strings (`sw` gives `CSIBI0015E`).
14. (Findings 14-18 are from UC-10, 2026-11-11, all `[LIVE]`; details in `DEMO-BUILD-GUIDE.md` 0.1 rows 32-37.) **Delegated admin exists per application:** `owners:[userId]` on an app auto-grants `applicationowners`; the owner API (`/v1.0/owner/applications`) shows and manages only their app and its customers. Limits: no policy/theme change, an owner can read all SCIM users and the other brand's customer list, `themedeveloper` is tenant-wide.
15. **Per-brand customers:** `all_users_entitled:false` + per-user entitlement (`POST /v1.0/owner/applications/{id}/entitlements`). Non-entitled users get `CSIAQ0279E`. **Group entitlements do NOT admit members.**
16. **Languages work without branding:** `ui_locales=fr|en` or `Accept-Language` switches login, TOTP and error pages. With neither, English.
17. **Consent page shows only `client_name`;** `client_uri`/`policy_uri`/`tos_uri` are ignored. Custom domains: unregistered `Host` gets 400; sender customization off (`CSIAP3564E`).
18. **One tenant host = one browser session** across brands (Boréal re-asks only the second factor after Aurora). `*.localhost` redirect URIs are accepted by DCR and resolve to loopback.
19. (Findings 19-22 are from UC-11, 2026-11-11, all `[LIVE]`; details in `DEMO-BUILD-GUIDE.md` 0.1 rows 38-44.) **CSV import:** `POST /v2.0/CSV/importUsers?notifyType=NONE`, multipart field `file`, 202 `{_id}`; poll `GET /v2.0/CSV/jobs/{id}` (not `importStatus`). A blank user name makes the job vanish (404). Existing users are never overwritten (`CSIAI0047E`). Bad e-mail is a per-row error (`CSIAI0096E`). Column `usershouldnotneedtoresetpassword` skips the forced reset (else `CSIAQ0267E` at sign-in). `readUsers` + `manageUsers` is enough. axios here does not take native FormData: the multipart body is hand-built.
20. **Pre-hashed passwords:** `{SSHA256} {SHA256} {SSHA384} {SHA384} {SSHA512} {SHA512} {SSHA} {SHA} {MD5}` sign in with the original password. `{SMD5}`, `{SHA1}`, `{PBKDF2}`, `{CRYPT}`, `{PLAIN}` and bcrypt import with **no error** but are stored as literal text and cannot sign in: always filter by format. A pre-hashed import skips the 8-character minimum.
21. **Linkage survives:** `externalId`, enterprise `department` and `employeeNumber`, `preferredLanguage`, custom `accountId`. Working SCIM filters: `externalId` and `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department`; bare `department`/`employeeNumber` give 400 `CSIAI0050E`. Hosted change-password page shows `CSIAH0307I`; posting `operation=verify` completes it. SCIM PATCH `password` works with the no-reset header; re-using the old one gives `CSIAI0021E`.
22. **App password grant is `ropc`** in the application document (not `password`). **JIT gateway pattern works**: password grant first, legacy store only for users unknown to Verify, create user with the verified plaintext. First login about 1.5 to 2.2 s, then 0.2 to 0.3 s. It is IFC's code, not a Verify feature.
23. (Findings 23-26 are from UC-12, 2026-11-11, all `[LIVE]`; details in `DEMO-BUILD-GUIDE.md` 0.1 rows 45-48.) **OpenFGA runs as a native binary** (v1.22.1, sha256-checked download into `demo/out/bin`, gitignored); the Podman VM would not start (socket refused) and is not needed. Gotchas: `openfga version` prints to stderr; **Node runs under Rosetta here (`process.arch` is `x64`)** so choose the binary with `sysctl hw.optional.arm64`; store names need 3 to 64 chars from `[a-zA-Z0-9 .-/^_&@]`; duplicate tuple writes and missing deletes are 400, so sync by diff.
24. **Authorization on top of Verify:** the password-grant **access token is opaque**; the gateway introspects it (`sub` = the Verify user id) with its own **STS client** (works across clients, no admin credential). `sendAllKnownUserAttributes:"true"` puts `department`, `job_title`, `email` in the ID token and `/userinfo`. SCIM `add` on enterprise `department`/`employeeNumber` and on `title` is 204 and replaces the value. A SCIM deactivate makes an existing token introspect `active:false` at once. Claims are a snapshot: after a reassignment the old token still has the old `department`; the engine, not the claim, is the authority.
25. **No token-time callout here:** `/v1.0/attributefunctions` has 13 built-ins only (POST is 405); `POST /v1.0/attributes` accepts only STATIC, CREDENTIAL, SCHEMA, PROFILE, ORG (400 `CSIBE2716E`); `tokenResponseMap` in the app's `oidc.properties` is 400. Other placements untested (`[INFER]`).
26. **Relationship model:** `servicing = placed_by and member from brokerage`; `viewer = servicing or manager from brokerage`; `editor = servicing`. A broker who leaves loses access on the next check by deleting one tuple. 8,120 tuples load in ~0.8 s; check ~1 to 6 ms; list-objects ~1 to 2 ms (in memory, not a benchmark).
- `demo/lib/verify.js` loads `.env` from the repo root by path, so demo scripts work from any cwd.

## 6. Verdicts (15 use cases)

| Verdict | Use cases |
|---|---|
| YES | 02, 06, 07, 09, 13, 14, 15 |
| YES with caveats | 01, 03, 04, 08, 11 (bulk yes; JIT only as a gateway pattern until IBM enables Flow or Bridge) |
| PARTIAL | 05, 10, 12 (12 is built: the graph, instant reassignment and queries are proven; the token-minting callout is not possible on this tenant) |

Updated by live findings: **UC-10 is PARTIAL, built** (policy, language, per-brand customers and delegated admin proven; brand look blocked by branding, custom domains need IBM; no sub-tenants). **UC-11 is PARTIAL, built** (bulk, reset, rollback, linkage and a gateway JIT proven; native JIT blocked: no Flow designer, Bridge create returns 401 `CSIBS0033E`). **UC-01 Track B is blocked** (no Flow designer). **UC-05 needs IBM** to activate threat detection and Adaptive access. **UC-12 is PARTIAL, built** (Verify plus an external engine, OpenFGA, not a native Verify feature; request-time authorization proven, token-time callout impossible on this tenant).

## 7. Blockers and open questions

**IBM must enable** (copy-paste message in `DEMO-BUILD-GUIDE.md` section 4): Flow designer, User forms, Branding, Adaptive access, activation of Threat detection, **SMS and voice OTP delivery** (new, from UC-06), and **a client-certificate (mTLS) option on the SaaS edge** (new, from UC-09: without it mTLS client authentication cannot be demonstrated on this tenant). For UC-11 ask IBM to enable **Flow designer or the Verify Bridge** (create returns 401 `CSIBS0033E`), confirm the supported password-hash prefixes officially (live: `{SSHA256} {SHA256} {SSHA384} {SHA384} {SSHA512} {SHA512} {SSHA} {SHA} {MD5}`; others import silently but cannot sign in), give bulk-import limits, and supply a financial-services migration reference. Also ask IBM to confirm: multiple custom IdP domains, per-brand partitioning of users and admins (owners can read all users), per-brand sender domain, supported password-hash prefixes for CSV import and the JIT pattern, two IBM Verify authenticators per user, a financial-services migration reference, and external callouts in attribute functions on a paid tenant.

**The human must do** (checklist in `DEMO-BUILD-GUIDE.md` section 3):
- Install the IBM Verify app on 1–2 phones (UC-04, 06, 07, 14). **UC-06 first:** `node demo/uc06-voice/enroll-phone.js`, scan the QR, then `node demo/uc06-voice/run.js --push`.
- **UC-07 browser path:** sign in to TrustMeInsurance as `ifc-demo-uc07-marie` (password in `demo/out/uc07.state.json`, key `user.password`), then Help > "Speak with a Voicebot". The real app has "Require 2FA for MFAGroup" and no password grant, so this login cannot be scripted.
- **Confirm with IFC:** the PDF's UC-07 main flow still says "User enters the OTP received via Voicebot", which contradicts the title. The demo skips the OTP for a valid app session and keeps it as the fallback.
- Set up a public tunnel (ngrok or cloudflared) for webhooks and back-channel logout (UC-05, 08, 13). cloudflared and ngrok are not installed.
- **UC-08 browser path:** `node demo/uc08-sso/setup.js && node demo/uc08-sso/serve.js`, sign in at http://localhost:4001 as `ifc-demo-uc08-broker` (password `users.broker.password`, TOTP key `totp.secret` in `demo/out/uc08.state.json`), open :4002 and :4003, log out of one. Back-channel: tunnel to :4001, then `node demo/uc08-sso/setup.js --backchannel https://<public>`.
- Run `mkcert -install` and add `127.0.0.1 ifc-demo.local` to `/etc/hosts` (UC-02).
- Provide a readable test mailbox (UC-01, 03, 06, 14; UC-14 already proven with the tenant-admin mailbox).
- **UC-11 browser pass (10 min):** `node demo/uc11-migration/setup.js && node demo/uc11-migration/serve.js`, open `http://localhost:4051`, sign in as `ifc-demo-uc11-jean` (password in `demo/out/uc11.state.json`, `users.jean.password`; first login migrates), then `node demo/uc11-migration/bulk.js` and `http://localhost:4051/portal-login` as `ifc-demo-uc11-rene` to choose a new password. Ask IFC for its legacy hash algorithm, user and broker counts, and e-mail uniqueness.
- **UC-12 browser look (10 min):** `node demo/uc12-rebac/setup.js && node demo/uc12-rebac/serve.js`, open `http://127.0.0.1:4170`, pick Anna, Sign in, read IFC-100001 (allowed) then IFC-100004 (refused), move Anna to BRG-B, read IFC-100001 again (refused, same token), Reset. Ask IFC for its relationship roles (assistants, delegates, MGAs), source of truth and volume. The Podman question is closed (OpenFGA runs natively). Podman is at `/opt/podman/bin/podman` but its VM does not start. Docker is not installed. Node is v24.7.0 (x64 build under Rosetta on Apple Silicon). Go is not installed.

**Unconfirmed (don't promise until tested):** whether IBM can enable a client-certificate (mTLS) option (today the handshake sends no `CertificateRequest`); two IBM Verify authenticators for one user; `client360_id` appearing in the ID token via claim mapping; the passkey method URN in policies; attaching an external SMS webhook; the official list of CSV hash prefixes (nine proven live, finding 20); `X-Forwarded-For` being honoured at the SaaS edge.

## 8. What to start building next

**Foundation, UC-06 to UC-14 are done (UC-06, 07, 08, 10, 11, 12, 13 and 14 have human steps pending; UC-09 has none).** Recommended order from here (full order in `DEMO-BUILD-GUIDE.md` section 5):

1. **Close UC-06 and UC-07 (about 30 min, `[HUMAN]`):** install IBM Verify on a phone, `node demo/uc06-voice/enroll-phone.js`, scan, then `node demo/uc06-voice/run.js --push` and approve. Then the UC-07 browser path: `node demo/uc07-handoff/setup.js`, restart `node ./bin/www`, `node demo/uc07-handoff/serve.js`, sign in as `ifc-demo-uc07-marie`, Help > "Speak with a Voicebot", then `node demo/uc07-handoff/voice.js`.
2. **UC-15 Consent** (proven or nearly proven), then UC-01 Track A, UC-03 (it can reuse the UC-14 console and the password-replace unlock). **UC-14 is built and verified**: `node demo/uc14-ciba/{setup,run,verify,teardown}.js`, `run.js --approve` for the real approval, live demo = `serve.js` on `http://localhost:4140`; **UC-14 human steps:** (a) phone push: enrol a phone and use `ensureCibaApp(name,{channels:['push','email']})`; (b) rehearse the e-mail approval once. **UC-13 is built and verified**: `node demo/uc13-lifecycle/{setup,run,verify,teardown}.js`; live demo = `serve.js` on `http://localhost:4040`.
3. **UC-02, UC-04** (need browser or phone), then **UC-05** (needs IBM). UC-12 is built: `node demo/uc12-rebac/{setup,run,verify,teardown}.js`; live demo = `serve.js` then `http://127.0.0.1:4170` or `cli.js`. UC-11 is built: `node demo/uc11-migration/{setup,run,verify,teardown}.js`; live demo = `serve.js` + `show.js` + `bulk.js` + `rollback.js`. **UC-10 human steps:** `node demo/uc10-brands/setup.js && node demo/uc10-brands/serve.js`, open `http://aurora.localhost:4101` and `http://boreal.localhost:4102` (steps in `demo/uc10-brands/README.md`); once IBM enables branding run `node demo/uc10-brands/themes.js`.
4. Send the IBM message (`DEMO-BUILD-GUIDE.md` section 4, including SMS/voice OTP enablement).

Reuse, do not duplicate: `stubs/rules-engine/openfga.js` (OpenFGA download/start/client), `demo/lib/verify.js` (`api`, `createClient`, `oauthClient` for introspect/revoke/exchange/password grant, `send` with DNS retry, `evidence`, `stateFile`), `demo/lib/idempotent.js` (`ensureUser`, `ensureApiClient`, `ensureGroup`, `ensureTotp`, `ensureStsClient`, `ensureDcrClient`, `updateApplication`, `ensureGroupMember`, `ensurePolicy`, `deleteUser`, and from UC-10 `appIdOf`, `listAppEntitlements`, `ensureAppEntitlement`, `removeAppEntitlement`...), `demo/lib/totp.js` (`totpPlayer`), `demo/teardown-all.js` (it already sweeps users, groups, API clients, applications, access policies and STS clients and branding themes named `ifc-demo-*`; extend `inventory()` if a new object type appears). **`teardown-all.js` also deletes other use cases' objects**: re-run their `setup.js` afterwards.
Per-use-case folders look like `demo/ucNN-*/` with `setup.js`, `run.js`, `verify.js`, `teardown.js` and a `README.md`. **When a demo is built, update the readiness label in the runbook summary table.**

### Commands
```bash
node ./bin/www &                       # base app on :3000 (only needed for the app-based demos)
curl -X POST localhost:3000/setup      # must return 200
node demo/00-probe.js                  # 12/12 expected
node demo/teardown-all.js --list       # what ifc-demo-* objects exist
node demo/uc06-voice/setup.js && node demo/uc06-voice/verify.js
node demo/uc07-handoff/setup.js && node demo/uc07-handoff/run.js && node demo/uc07-handoff/verify.js
node demo/uc08-sso/setup.js && node demo/uc08-sso/verify.js     # then: node demo/uc08-sso/serve.js for the browser demo
node demo/uc09-api/setup.js && node demo/uc09-api/serve.js &    # then, in another shell: node demo/uc09-api/run.js && node demo/uc09-api/verify.js
node demo/uc09-api/teardown.js                                  # removes all ifc-demo-uc09-* objects
node demo/uc13-lifecycle/setup.js && node demo/uc13-lifecycle/run.js && node demo/uc13-lifecycle/verify.js
node demo/uc13-lifecycle/serve.js                               # interactive Ops Queue dashboard on :4040
node demo/uc13-lifecycle/teardown.js                            # removes all ifc-demo-uc13-* objects
```

### Suggested first prompt for the next session
> Read `CONTEXT.md`, then `DEMO-BUILD-GUIDE.md` sections 0 to 2 and the UC-14 parts. Start the app and re-run `POST /setup`, run `node demo/00-probe.js`, then build UC-14 end to end reusing `demo/lib`. Write evidence to `demo/out/uc14.json`. Don't print `.env` values.

## 9. Tooling that was used and may no longer exist (outside the repo)

These lived in `/tmp` and may be gone. Recreate as needed:
- `/tmp/api.sh METHOD PATH [json]`: authenticated API helper (token from `/tmp/tok`, SCIM-aware). `demo/lib/verify.js` replaces it.
- `/tmp/vd/*.txt`: 163 saved Verify docs pages. `/tmp/ops/get.py <operationId>`: extracts API operation schemas from `https://docs.verify.ibm.com/verify/reference/<id>`. It needs a browser User-Agent and low concurrency, or the site serves a bot-check page.
- `/tmp/vsr`: clone of `verify-saas-resources` (flows, DPoP samples, user utilities). `/tmp/verifyctl`: clone of `verifyctl` (alpha, v0.0.9, no Go on this machine so it needs a release binary).
- A background app process (pid 18982) from an earlier session may still be running on :3000. It is stale. Kill it and start fresh.

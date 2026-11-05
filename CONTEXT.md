# CONTEXT: where we are (read this first in a new session)

**Last updated:** 2026-11-05. **Branch:** `master`. **Repo:** `ci-ciam` (TrustMeInsurance, a Node/Express CIAM demo app for IBM Verify SaaS).

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

Evidence tags used in every doc: `[LIVE]` executed on the tenant, `[DOCS]` from documentation, `[INFER]` reasoning, `[HUMAN]` a person must do it.

## 3. What is NOT done (important)

**No demo has been built.** These do not exist yet: `demo/`, `stubs/`, the agent pages (`/agent`, `/agent/verify`), `routes/ifc-register.js`, `routes/passkey.js`. They are only described in the build guide.
No application code was added other than the `functions.js` fix. Nothing has been pushed unless the user did it. Check with `git status` and `git log origin/master..master`.

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
2. **Branding is NOT supported on the trial** (403 `CSIAZ3060E`). The app's custom theme can't be registered, so `/setup` falls back to the default theme. It blocks UC-10 themes and FR/EN.
3. **Sub-tenants are reseller-only** (405 `CSIAG0746E`), so per-brand tenants are not available.
4. **Threat detection config exists but is `inactive`.** Adaptive access (Trusteer) is not confirmed. UC-05 depends on IBM enabling both.
5. **Dynamic client registration works** (`POST /oauth2/register`, `DELETE /oauth2/register/{id}`). `private_key_jwt` with an inline `jwks` was proven end to end (assertion `aud` = `https://trialverify.verify.ibm.com/oauth2/token`). `tls_client_auth` registers, but the **mTLS handshake is untested**.
6. **CIBA works** if the app is created with `"applicationState": true` (otherwise `invalid_client`).
7. **Immediate revocation proven (UC-13):** SCIM `PATCH active=false` gives 204. The existing token introspects `active:false` within 0 s, and a new login returns `CSIAQ0281E`.
8. **Webhook purposes available:** `identity_proofing`, `external_mfa`, `external_risk`, `notifications`, `external_sms`. `external_risk` is the way to feed IFC's own risk signals into a policy (UC-05). `external_sms` supports the bring-your-own-SMS-gateway ask (UC-02).
9. **Access policy v5.0** accepts the condition types `geoLocation`, `threatInsights`, `trusteer`, `webhooks`, `ipAddress`, and more. Acceptance does not prove the feature is licensed.
10. **No phone is registered** (`GET /v1.0/authenticators` returns 0). The Verify Profile authenticator client id is `5280f51a-9699-4d96-9dd9-bcc0fdfdf9dd`.
11. The Verify Bridge is not configured on the tenant (`GET /config/v1.0/onpremagents` returns 404 `CSIBS0035E`).

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

## 6. Verdicts (15 use cases)

| Verdict | Use cases |
|---|---|
| YES | 02, 06, 07, 09, 13, 14, 15 |
| YES with caveats | 01, 03, 04, 08, 11 |
| PARTIAL | 05, 10, 12 |

Updated by live findings: **UC-10 is weaker** (branding blocked, no sub-tenants). **UC-01 Track B and UC-11 JIT are blocked** (no Flow designer). **UC-05 needs IBM** to activate threat detection and Adaptive access. **UC-12** is Verify plus an external engine (OpenFGA), not a native Verify feature.

## 7. Blockers and open questions

**IBM must enable** (copy-paste message in `DEMO-BUILD-GUIDE.md` section 4): Flow designer, User forms, Branding, Adaptive access, activation of Threat detection. Also ask IBM to confirm: multiple custom IdP domains, delegated admin per brand, an mTLS endpoint on SaaS, supported password-hash prefixes for CSV import and the JIT pattern, two IBM Verify authenticators per user, a financial-services migration reference, and external callouts in attribute functions on a paid tenant.

**The human must do** (checklist in `DEMO-BUILD-GUIDE.md` section 3):
- Install the IBM Verify app on 1–2 phones (UC-04, 06, 14).
- Set up a public tunnel (ngrok or cloudflared) for webhooks and back-channel logout (UC-05, 08, 13).
- Run `mkcert -install` and add `127.0.0.1 ifc-demo.local` to `/etc/hosts` (UC-02).
- Provide a readable test mailbox (UC-01, 03, 06, 14).
- Decide whether Podman may pull the OpenFGA and Verify Bridge images (UC-11, 12). Podman is at `/opt/podman/bin/podman`. Docker is not installed. Node is v24.7.0. Go is not installed.

**Unconfirmed (don't promise until tested):** the mTLS handshake; two IBM Verify authenticators for one user; `client360_id` appearing in the ID token via claim mapping; the passkey method URN in policies; attaching an external SMS webhook; which hash prefixes CSV import supports (doc shows `{SSHA256}`); `X-Forwarded-For` being honoured at the SaaS edge.

## 8. What to start building next

**Recommended order** (full order in `DEMO-BUILD-GUIDE.md` section 5):

1. **Foundation:** `demo/lib/verify.js` (token cache, request wrapper, SCIM header handling, evidence logger), `demo/lib/idempotent.js` (`ensureUser`, `ensureGroup`, `ensureApp`, `ensurePolicy`), `demo/00-probe.js` (re-runs the live probes and prints a pass/fail table), `demo/teardown-all.js`, `demo/out/` (gitignored evidence).
2. **UC-13, UC-09, UC-14, UC-15** (proven or nearly proven).
3. **UC-07, UC-06, UC-01 Track A, UC-03.**
4. **UC-02, UC-08, UC-04** (need browser, phone or tunnel).
5. **UC-12, UC-11 bulk, UC-05, UC-10** (blocked or partial).

Per-use-case folders look like `demo/ucNN-*/` with `setup.js`, `run.js`, `verify.js`, `teardown.js` and a `README.md`. Small stubs go in `stubs/` (voicebot, client360, legacy auth store, rules engine, ops queue, risk engine, RPs). Each use case's build steps are in `DEMO-BUILD-GUIDE.md` section 2. Each one's presenter click path is in `DEMO-RUNBOOK-UI.md` section 2. **When a demo is built, update the readiness label in the runbook summary table.**

### Suggested first prompt for the next session
> Read `CONTEXT.md`, then `DEMO-BUILD-GUIDE.md`. Run `npm install`, start the app and re-run `POST /setup`. Build the foundation (`demo/lib`, `00-probe.js`, `teardown-all.js`), then build UC-13 end to end with a script that writes evidence to `demo/out/`. Don't print `.env` values.

## 9. Tooling that was used and may no longer exist (outside the repo)

These lived in `/tmp` and may be gone. Recreate as needed:
- `/tmp/api.sh METHOD PATH [json]`: authenticated API helper (token from `/tmp/tok`, SCIM-aware). `demo/lib/verify.js` replaces it.
- `/tmp/vd/*.txt`: 163 saved Verify docs pages. `/tmp/ops/get.py <operationId>`: extracts API operation schemas from `https://docs.verify.ibm.com/verify/reference/<id>`. It needs a browser User-Agent and low concurrency, or the site serves a bot-check page.
- `/tmp/vsr`: clone of `verify-saas-resources` (flows, DPoP samples, user utilities). `/tmp/verifyctl`: clone of `verifyctl` (alpha, v0.0.9, no Go on this machine so it needs a release binary).
- A background app process (pid 18982) from an earlier session may still be running on :3000. It is stale. Kill it and start fresh.

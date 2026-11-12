# UC-15 Consent Management (PIPEDA)

## What this demo shows

IFC must capture and honour granular user consent under PIPEDA. Verify DPCM (Data Privacy and Consent Management) provides:

| Capability | Status |
|---|---|
| Purpose lifecycle (create, publish, version) | **Built + LIVE** |
| Per-purpose data-attribute mapping (email, name, postal code) | **Built + LIVE** |
| Dynamic client registration — 2 third-party apps with different scopes | **Built + LIVE** |
| Data-Subject Presentation (DSP) — user consent state per purpose | **Built + LIVE** |
| Data-Usage Approval (DUA) — enforcement gate (deny before consent, approve after) | **Built + LIVE** |
| Admin consent ledger / audit export | **Built + LIVE** |
| DSAR deletion-request stub (SLA clock + user delete API) | **Built + LIVE** |
| Browser consent grant (toggle preferences, save) | **Built · HUMAN** |

## Key finding [LIVE 2026-11-12]

`CSIBT0032E "This API client can be used to create global consents only."` — user-scoped consent WRITE via `PATCH /dpcm/v1.0/privacy/consents` requires a real browser OIDC session (session cookie). Password-grant tokens also get CSIBT0032E for per-user consent writes. This is a trial-tenant constraint; the demo app's `/consent` route (cookie-based) works correctly. The IFC demo shows consent grant in the browser and proves enforcement (DUA/DSP) via API.

## Files

| File | Purpose |
|---|---|
| `common.js` | Shared constants (purposes, clients, user), DPCM helpers |
| `setup.js` | Idempotent setup: purposes, purpose-app association, user, DCR clients, enable ropc |
| `run.js` | Full lifecycle run: 14 live assertions + 2 human steps |
| `verify.js` | Verification checks (call after setup and after browser grant) |
| `teardown.js` | Removes all ifc-demo-uc15-* objects, disables ropc |
| `serve.js` | Dashboard on :4151 (purposes, consents, DSP, DUA, export) |

## Tenant objects created

| Name | Type |
|---|---|
| `ifc-demo-uc15-claims-processing` | DPCM purpose (365 days, attrs: email, given\_name, family\_name) |
| `ifc-demo-uc15-fraud-analytics` | DPCM purpose (180 days, attrs: email, postal\_code) |
| `ifc-demo-uc15-marketing` | DPCM purpose (90 days, attrs: email, mobile) |
| `ifc-demo-uc15-repair-shop` | DCR OAuth client (scopes: openid, profile, email) |
| `ifc-demo-uc15-comparison-site` | DCR OAuth client (scopes: openid, email) |
| `ifc-demo-uc15-policyholder` | SCIM user (test subject) |

## Commands

```bash
# First time (or after teardown)
node demo/uc15-consent/setup.js

# Scripted lifecycle
node demo/uc15-consent/run.js

# Verify all checks
node demo/uc15-consent/verify.js

# Admin dashboard (port 4151)
node demo/uc15-consent/serve.js

# Teardown
node demo/uc15-consent/teardown.js
```

## Human steps [HUMAN]

1. **Browser consent grant** (needed for DUA-approved step):
   - Ensure the main app is running: `node ./bin/www`
   - Open http://localhost:3000
   - Sign in as `ifc-demo-uc15-policyholder` (password in `demo/out/uc15.state.json`)
   - Navigate: **My Profile → Communication preferences**
   - Toggle on: paperless billing, marketing → **Save Settings**
   - Check **Privacy & consent history** — records appear
   - Re-run `node demo/uc15-consent/run.js` — step H (DUA post-grant) now passes

2. **Demo prep**: note that `communications` and `paperless-billing` are the existing app purposes; the UC-15 purposes are `ifc-demo-uc15-*`.

## Teardown / re-run proof

```bash
node demo/uc15-consent/teardown.js
node demo/teardown-all.js --list        # confirm clean
node demo/uc15-consent/setup.js         # re-creates everything
node demo/uc15-consent/run.js           # 14 PASS / 0 FAIL
```

## IFC requirement mapping

| IFC requirement | Verify capability | Status |
|---|---|---|
| Granular data scopes | DPCM purposes with attribute lists | **LIVE** |
| Time-bound consent | `defaultConsentDuration` on purposes | **LIVE** |
| Fetch & enforce consent at login (restrict token scopes/claims) | OIDC `consentAction` + DPCM DUA gate | Browser path; LIVE via app |
| User self-service consent centre | Existing app `/consent` route | LIVE (browser) |
| Audit-ready export on demand | Admin `GET /dpcm-mgmt/config/v1.0/privacy/consents` | **LIVE** |
| DSAR SLA workflow | Stub (Verify provides user-delete and consent-delete APIs; SLA clock is IFC code) | Stub |
| Dynamic client registration with scopes | DCR `POST /oauth2/register` | **LIVE** |

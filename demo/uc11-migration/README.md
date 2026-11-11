# UC-11: Legacy IAM migration

IFC's requirement (`IAM Modernization Use Cases.pdf`, UC-11): move policyholder and broker credentials from the legacy IAM/ISM to the new
platform **without a mass password reset or an outage, and without losing the link to policy and brokerage records**. Capabilities asked:
(1) just-in-time (JIT) migration at the first login on the new IdP; (2) bulk migration, with the option to reset passwords for bulk-migrated users.
Demo asked: the vendor's reference architecture and a prior financial-services migration of comparable scale; a JIT login for a sample legacy
hash format "if feasible"; a rollback path.

Evidence tags: `[LIVE]` executed on the tenant, `[DOCS]` documentation, `[INFER]` reasoning, `[HUMAN]` a person or IBM must do it.

## What is real and what is a stub

| Part | Real or stub |
|---|---|
| Users, password hashes, CSV import, hosted change-password page, token issuing | **Real IBM Verify tenant** `[LIVE]` |
| The legacy credential store (`stubs/legacy-auth-store`) | **Stub**: 11 fictional people in 6 hash formats, in memory. IFC has not told us its legacy algorithm |
| The JIT gateway (`stubs/migration-gateway`) | **Stub that IFC would own**: it sits in front of the login. It uses only Verify APIs |
| Native JIT inside Verify (Flow designer / Verify Bridge) | **Not available on this trial** (Flow 403 `CSIBZ0098E`; Bridge 404 `CSIBS0035E`, create 401 `CSIBS0033E`) `[LIVE]` |

The JIT here is therefore a **pattern in front of Verify**, not a Verify product feature. State this plainly to IFC. The native alternatives
(Flow designer, or Bridge external-authentication agent with "password migration") are `[DOCS]` options that need IBM to enable them.

## What is here

| File | What it does |
|---|---|
| `../../stubs/legacy-auth-store/` | `hashes.js` (SSHA256, SHA256, SSHA384, SHA384, SSHA512, SHA512, SSHA, SHA, MD5, SMD5, SHA1, PBKDF2 make/check), `server.js` (`/export`, `/password-verify`, `/migrated`, `/_stats`, `/_admin/offline`) |
| `../../stubs/migration-gateway/server.js` | `POST /login`, a sign-in page `/`, the Verify hosted page `/portal-login` + `/callback`, `/_events` |
| `common.js` | seed people, CSV builder, import-job helper, linkage helpers |
| `setup.js` | least-privilege migrator API client, two applications, empties the platform ("day before cut-over"). Idempotent |
| `bulk.js` | extract from legacy -> CSV -> `POST /v2.0/CSV/importUsers` -> job report. Only imports hash formats that were proven to work |
| `rollback.js` | deletes the migrated users from Verify and clears the legacy markers |
| `run.js` | 52 checks, scenarios A-K, against the real tenant. Writes `demo/out/uc11.json` |
| `serve.js` / `show.js` | for the live demo: runs both stubs; prints legacy-vs-Verify state in one table |
| `verify.js` | pass / fail / human report |
| `teardown.js` | removes everything UC-11 created |

Tenant objects (all `ifc-demo-uc11-*`): API client `-migrator` (2 entitlements: `readUsers`, `manageUsers`), applications `-login-gateway`
(password grant) and `-portal` (authorization code + PKCE), plus the migrated users while a scenario runs. `teardown-all.js` already covers all these types.

## Commands

```bash
node demo/uc11-migration/setup.js      # idempotent; the new platform starts empty
node demo/uc11-migration/run.js        # scenarios A-K, 52 checks, evidence in demo/out/uc11.json (leaves the tenant empty again)
node demo/uc11-migration/verify.js     # PASS / FAIL / HUMAN
node demo/uc11-migration/teardown.js   # remove everything
```

Live demo (three shells): `node demo/uc11-migration/serve.js` / `node demo/uc11-migration/show.js` / `node demo/uc11-migration/bulk.js`.
Passwords: `demo/out/uc11.state.json`, key `users.<name>.password` (never print them on a shared screen).

## What the scenarios prove `[LIVE]`

| | Result |
|---|---|
| **B. Hash-format matrix** | The CSV import takes `{SSHA256} {SHA256} {SSHA384} {SHA384} {SSHA512} {SHA512} {SSHA} {SHA} {MD5}` as pre-hashed passwords: the customer signs in with the **original** password. `{SMD5}`, `{SHA1}` (that spelling), `{PBKDF2}`/bcrypt-style values import "successfully" but are stored as a literal string: the customer **cannot** sign in. The job reports no error for them, so `bulk.js` filters by format |
| **C. Bulk** | 202 + async job; ~1.3 to 1.5 s per small job. Row failures are reported (invalid e-mail `CSIAI0096E`); good rows in the same file still import. A blank user name makes the whole job vanish (the job id then 404s). Re-running reports `CSIAI0047E exists` per row and overwrites nothing. Linkage attributes survive: `externalId` (legacy id), `accountId` custom attribute (policy), `department` (brokerage), `employeeNumber` (broker id), `preferredLanguage`; all queryable by SCIM filter |
| **D. Bulk with reset** | Import without header `usershouldnotneedtoresetpassword`: API sign-in fails `CSIAQ0267E`; the hosted Verify page shows "Change the initial password" (`CSIAH0307I`) with Skip Now; a scripted submit of that form (`operation=verify`) makes the new password work and the legacy one stop working |
| **E. JIT** | First login at the gateway: Verify refuses (unknown user), gateway asks the legacy store, creates the Verify user with the plaintext just verified (Verify hashes it itself), carries the linkage, marks the legacy record, signs in. ~1.5 to 2.2 s once; later logins ~0.2 to 0.3 s and never touch the legacy store |
| **F. Switch off** | With the legacy store offline, migrated users still sign in; an un-migrated user gets 503 "temporarily unavailable" (not a false "wrong password"), and migrates when the store is back |
| **G. Safety** | Unknown user and wrong password give the same 401; a user already in Verify never triggers a legacy call; bad legacy data fails cleanly with no half-created user; event log has no passwords or tokens |
| **H. Weak password** | A correct legacy password shorter than Verify's minimum (8) is verified, the gateway asks for a new one (422) and creates nothing until it has one |
| **I. Rollback** | Delete the migrated users, clear markers: the legacy store was never changed, customers keep signing in with the legacy password and are migrated again; a bulk run can be repeated |
| **J. Least privilege** | The migrator client (2 entitlements) works for users and is refused (403) on API clients, applications, policies, identity sources |

## Human steps `[HUMAN]`

1. **Browser pass** (10 min): `node demo/uc11-migration/setup.js && node demo/uc11-migration/serve.js`. Open `http://localhost:4051`, sign in as
   `ifc-demo-uc11-jean` (password in the state file): the first sign-in migrates; sign in again; run `node demo/uc11-migration/show.js`.
   Then `node demo/uc11-migration/bulk.js`, open `http://localhost:4051/portal-login`, sign in as `ifc-demo-uc11-rene` and choose a new password on the Verify page.
2. **Tell IFC**: the legacy hash algorithm (so we can say "bulk" or "just in time" for their data), password policy of the legacy system, number of
   users and brokers to migrate, whether e-mail addresses are unique.
3. **IBM** (message in `DEMO-BUILD-GUIDE.md` section 4): enable Flow designer or provision the Verify Bridge external-authentication agent, confirm
   the supported `{TYPE}` hash prefixes officially, bulk import limits, and a prior financial-services migration reference.

## Limits to state `[LIVE]` unless tagged

- The JIT login is a gateway pattern, not a built-in Verify feature, on this tenant.
- Verify's import does not validate hash prefixes: a format it cannot read is stored as the literal text. Always run the format check first.
- The hosted change-password form was completed by the scripted browser (`operation=verify` with old and new password), which proves the protocol, not what a person sees.
- Throughput at IFC's volume is untested (11 records here).
- Existing users are never overwritten by an import (`CSIAI0047E`); to change a migrated password use SCIM PATCH.
- E-mail is mandatory and validated per row; an address with a trailing `.invalid` domain is accepted but never receives mail.

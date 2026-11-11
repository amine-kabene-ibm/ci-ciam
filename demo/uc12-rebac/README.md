# UC-12: Relationship-based authorization (ReBAC) behind a gateway

IFC asks for an authorization service whose decisions reflect **inherited relationships**
(brokerage → broker → client → policy), that **changes access instantly** when a relationship changes, and that can list
**all resources a user can access**. **Verify authenticates the broker; an external relationship engine decides what that broker may
see.** This is an architecture with Verify in front, not a Verify-native ReBAC feature (stated honestly in the runbook).

Everything here runs against the real tenant `trialverify.verify.ibm.com`. Tenant objects are named `ifc-demo-uc12-*`.

| Part | What it is | Proven how |
|---|---|---|
| Users, sign-in, token | 5 fictional users, real password-grant sign-in, real token introspection | `[LIVE]` |
| Directory facts | department = brokerage, employeeNumber = broker id, title = role, written by a 2-entitlement API client | `[LIVE]` |
| Relationship engine | **OpenFGA v1.22.1** (open source), native binary, in-memory | `[LIVE]` |
| Source system | Stub: who works for which brokerage, which broker placed which client, which policies a client holds | stub |
| Policy gateway | `stubs/policy-api`: introspect token, ask the engine, allow/deny with reasoning path, log | `[LIVE]` |
| Model | `stubs/rules-engine/model.js` (DSL in its header) | `[LIVE]` |

## Commands

```bash
node demo/uc12-rebac/setup.js      # idempotent: tenant objects + downloads the OpenFGA binary on first run (sha256 verified)
node demo/uc12-rebac/run.js        # 52 scenario checks against the tenant -> demo/out/uc12.json
node demo/uc12-rebac/verify.js     # PASS / FAIL / HUMAN list (runs run.js inside)
node demo/uc12-rebac/teardown.js   # removes everything UC-12 created, then confirms the tenant is clean
```

## The live demo (presenter)

Terminal 1 (leave it running):

```bash
node demo/uc12-rebac/serve.js      # starts OpenFGA on :4171 and the gateway + console on http://127.0.0.1:4170
```

Then either the **browser console** `http://127.0.0.1:4170` or the **terminal client** (`cli.js`):

```bash
node demo/uc12-rebac/cli.js matrix                    # who can see what: 5 people x 6 policies
node demo/uc12-rebac/cli.js read anna IFC-100001      # real Verify sign-in, real introspection, engine decides -> 200 + reasoning path
node demo/uc12-rebac/cli.js read anna IFC-100004      # another brokerage's client -> 403 + why
node demo/uc12-rebac/cli.js read maya IFC-100003      # a MANAGER: access inherited from the brokerage
node demo/uc12-rebac/cli.js list anna                 # "all resources I can access"
node demo/uc12-rebac/cli.js who anna IFC-100001       # "who can access this resource" (audit)
node demo/uc12-rebac/cli.js move anna BRG-B           # the reassignment
node demo/uc12-rebac/cli.js read anna IFC-100001      # SAME token, now 403, no re-login
node demo/uc12-rebac/cli.js move anna BRG-A           # and back
node demo/uc12-rebac/cli.js log                       # audit trail
node demo/uc12-rebac/cli.js reset                     # between takes
```

Passwords and secrets are read from `demo/out/uc12.state.json` by the server only; they never reach the browser or the terminal output.

## Layout

```
stubs/rules-engine/openfga.js     downloads + starts OpenFGA, small HTTP client
stubs/rules-engine/model.js       the authorization model
stubs/policy-api/source.js        the source-system stub + graph sync (writes only the difference)
stubs/policy-api/server.js        the gateway (+ console API)
stubs/policy-api/console.html     the presenter console
demo/uc12-rebac/{common,runtime,setup,run,serve,cli,verify,teardown}.js
```

## What is NOT proven and what you must do `[HUMAN]`

1. **A look at the console in a real browser** (about 5 minutes): `setup.js`, `serve.js`, open `http://127.0.0.1:4170`, sign in as Anna, read IFC-100001 then IFC-100004, move Anna to BRG-B, read again. The scripted run and a headless render prove the page loads and the matrix draws, not how it feels.
2. **IFC's real relationship model.** Ask IFC for: roles beyond broker and manager (assistants, delegates, MGAs, call-centre agents), who owns the source of truth, how often relationships change, and how many relationships they expect.
3. **Engine choice.** OpenFGA is the stand-in. IFC may already have a rules engine; the gateway code only needs `check`, `list-objects` and `list-users` equivalents.
4. **The PDF's token-minting variant** ("IdP calls the rules engine while minting the token"). Not possible on this tenant `[LIVE]`: attribute functions are built-ins (`uppercase`, `sha256` …), scripted attribute sources are refused (CSIBE2716E). External callouts are paid-tier only `[DOCS]`. Ask IBM whether IFC's contract tier has it. The architecture here does not need it: the gateway asks the engine on every request, which is what makes changes instant.

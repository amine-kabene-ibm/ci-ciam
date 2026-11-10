# UC-09: API security (OAuth partner access to IFC external APIs)

IFC requirement (IAM Modernization Use Cases, UC-09): a partner machine client authenticates with
client credentials and mTLS or private-key JWT, gets a scoped token, and the API enforces scope.
A partner can also act for a policyholder (token exchange / on-behalf-of) without shared static keys.

Everything runs against the real tenant (`OIDC_CI_BASE_URI` in `.env`). Object names start with `ifc-demo-uc09-`.

## Run

```bash
node demo/uc09-api/setup.js     # idempotent: keys, DCR clients, STS client, policyholder user
node demo/uc09-api/serve.js     # protected IFC policy API stub on 127.0.0.1:4040 (leave it running)
node demo/uc09-api/run.js       # scenarios A to J against the tenant, evidence to demo/out/uc09.json
node demo/uc09-api/verify.js    # PASS/FAIL from the evidence (no tenant calls)
node demo/uc09-api/teardown.js  # removes every ifc-demo-uc09-* object and the local state file
```

`run.js` needs both `setup.js` and `serve.js`. Stop the stub with Ctrl-C.

## What is proven [LIVE, 2026-11-10]

| Scenario | Proven |
|---|---|
| A | A machine client with `private_key_jwt` gets a bearer token (HTTP 200); the API accepts it. |
| B | A client assertion signed with a different key is refused: 401 `invalid_client` (CSIAQ5064E). |
| C | Scope comes from the client registration, not from the request: a scope the client was not registered for is not granted; the API returns 403 `insufficient_scope`. |
| D | No token, a garbage token and a wrong scheme are refused (401). A registered client that is not an IFC partner gets a Verify token, and the API refuses it (403). |
| E | DPoP-bound tokens: a stolen token replayed without a proof, or with a proof from another key, is refused (401). |
| F | Key rotation with zero downtime: the JWKS holds old and new keys, both work; after the old key is removed, only the new key works. |
| G | On-behalf-of: the policyholder signs in (password grant), the partner exchanges that token (RFC 8693) with its own machine token as the actor, and requests `scope=ifc.policy.read`. The exchanged token has `sub` = the policyholder and `client_id` = the partner STS client. The API accepts it for the policyholder's own policy (200), and refuses it for another policyholder's policy (403 `not_the_policyholder`). |
| H | The exchange is refused without an actor token: 400 CSIAQ5242E. |
| J | The TLS handshake to the tenant contains no `CertificateRequest`. |

## What is NOT proven (stated, not claimed)

- **mTLS client authentication.** The tenant's TLS edge does not request a client certificate during the handshake (scenario J; checked under TLS 1.2 and 1.3, and against a local server that does request one, so the check can detect a request). Without a requested certificate, mTLS cannot be demonstrated on this tenant, so the demo does not claim it. The IFC requirement accepts mTLS or private-key JWT; the demo demonstrates private-key JWT.
- **An `act` claim on the exchanged token.** The exchanged token is opaque and introspection does not return the actor, so the demo does not claim that the partner is recorded as the actor. The API control is the scope plus the policyholder check, not the actor claim.
- **actorCriteria (CEL) on the STS client.** It is stored as `{}` and is not enforced: an actor the policy would disallow still gets a token. The demo does not claim a partner allow-list on the exchange.
- **The gateway.** The API is a local stub (`stubs/ifc-api`) standing in for IFC's gateway. It is not a Verify-managed resource server.

## Files

- `common.js` names, constants, key ids. `jwt.js` signs the client assertion and DPoP proofs (RS256, Node crypto).
- `setup.js` creates the tenant objects; `run.js` runs the scenarios; `serve.js` starts the stub; `verify.js` checks the evidence; `teardown.js` removes the objects.
- `stubs/ifc-api/server.js` is the protected API: it introspects each token with the partner STS client (never the admin client), enforces the client allow-list and scope, checks DPoP, and applies the policyholder rule to delegated tokens.
- Secrets and private keys live only in `demo/out/uc09.state.json` (mode 0600, gitignored). Evidence (`demo/out/uc09.json`) holds no secret material; `verify.js` checks that.

## Human steps

None for the API flows. Everything above runs from the terminal. The only tenant-side enablement this demo would need is one IBM-side item: a client-certificate (mTLS) option on the edge, if IFC requires mTLS rather than `private_key_jwt`. Ask IBM whether the trial tenant can enable it; until then mTLS is not demonstrated.

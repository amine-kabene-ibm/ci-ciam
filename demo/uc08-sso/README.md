# UC-08: Single sign-on across apps and global logout

IFC's requirement (`IAM Modernization Use Cases.pdf`, UC-08, B2C and B2B): one authentication gives access to several applications
(SSO and cross-application federation), the experience differs per persona (consumer vs broker), and logging out ends the session
everywhere (global logout), with session policies per persona.

Evidence tags: `[LIVE]` executed on the tenant, `[DOCS]` from documentation, `[INFER]` reasoning, `[HUMAN]` a person must do it.

## What is here

| File | What it does |
|---|---|
| `../../stubs/rp-sso/server.js` | A small OIDC relying party (code + PKCE, RS256 ID-token check against the tenant JWKS). Routes: `/login`, `/callback`, `/protected`, `/logout` (global), `/local-logout`, `/frontchannel-logout`, `/backchannel-logout`, `/bc/:name`, `/_events` |
| `common.js` | Names, personas, the two access policies, the three apps, logout wiring |
| `setup.js` | Creates groups, users, TOTP, 2 policies, 3 OIDC apps (dynamic registration). Idempotent. `--backchannel https://<public>` switches the apps to back-channel logout |
| `browser.js` | Scripted browser: cookie jars per origin, redirects, hosted login page, TOTP page, front-channel logout iframes |
| `run.js` | 37 checks, scenarios A-H, against the real tenant. Writes `demo/out/uc08.json` |
| `serve.js` | Runs the three apps on :4001 / :4002 / :4003 for a real browser |
| `verify.js` | Pass / fail / human report (tenant state, scenarios, evidence) |
| `teardown.js` | Removes everything UC-08 created |

Tenant objects (all `ifc-demo-uc08-*`, found by `demo/teardown-all.js`): groups `-brokers`, `-consumers`; users `-broker` (+ validated TOTP)
and `-client`; policies `-policy-standard` (brokers: TOTP once per SSO session) and `-policy-high` (brokers: TOTP at every sign-in);
applications `-rp-portal`, `-rp-claims`, `-rp-quote`.

## Commands

```bash
node demo/uc08-sso/setup.js      # idempotent
node demo/uc08-sso/run.js        # scenarios A-H, 37 checks, evidence in demo/out/uc08.json
node demo/uc08-sso/verify.js     # PASS / FAIL / HUMAN
node demo/uc08-sso/serve.js      # three apps for the browser demo
node demo/uc08-sso/teardown.js   # remove everything
```

## What is proven [LIVE]

- One login, three apps: the second and third app get a code with no page; all share the same `sid`; one session in `GET /v1.0/auth/sessions/{userId}`.
- Per-app assurance: the broker is asked for TOTP once for the SSO session (portal, claims) and again at the quoting app (`ACTION_MFA_ALWAYS`); password is not re-asked. The policyholder is never asked for TOTP.
- Per-persona authorization: the claims app returns 403 to a policyholder (decision from the `groupIds` claim, app side).
- Global logout from one app: `rplogout` returns the front-channel page with one iframe per app plus the tenant's own; after it every app drops its session, the Verify session list is empty, the access token introspects `active:false`, the refresh token gives `invalid_grant`, the next visit shows the login page.
- Contrast: an app-only (local) logout leaves the Verify session alive and the app silently signs back in.
- Administrator ends the session (`DELETE /v1.0/auth/sessions/{userId}`): tokens die immediately; an app that introspects per request (claims) returns 401, an app that trusts its own session (portal) still returns 200. That is an honest gap, closed by back-channel logout.
- `prompt=none` and `max_age` behave as expected (silent code with a session, `login_required` without, forced re-login with `max_age=1`).
- Dynamic registration accepts `backchannel_logout_uri`; logout with an unreachable receiver registered still completes (about 650 ms). The RP handler rejects garbage, a regular ID token and tampered tokens.
- There is no session-policy API (idle / absolute timeout): every candidate path returns the console login page. Per-persona lifetimes here are per-app token lifetimes (`accessTokenExpiry`) and per-app access policies.

## What is NOT proven

- `[HUMAN]` The same flow in a real browser. The scripted browser plays the protocol, not the pixels.
- `[HUMAN]` Delivery of a real back-channel `logout_token` from the tenant to an RP (needs a public URL). Token format is `[DOCS]` OIDC Back-Channel Logout 1.0.
- `[HUMAN]` Idle / absolute session timeouts per persona (console only, if at all).

## Human steps

### 1. Real-browser SSO and global logout (about 5 minutes)

```bash
node demo/uc08-sso/setup.js
node demo/uc08-sso/serve.js
node -e "const s=require('./demo/out/uc08.state.json');console.log('broker password:',s.users.broker.password)"
node -e "const t=require('./demo/lib/totp');const s=require('./demo/out/uc08.state.json');console.log('TOTP now:',t.totp(s.totp.secret))"
```

Add the TOTP secret (`demo/out/uc08.state.json`, key `totp.secret`) to an authenticator app, or print codes as above.
In one browser window:

1. Open `http://localhost:4001`, Sign in as `ifc-demo-uc08-broker`: password, then TOTP.
2. Open `http://localhost:4002` and `http://localhost:4003`, then Sign in. 4002 asks for nothing; 4003 asks for a TOTP only (never the password).
3. Click Log out on any app. All three tabs lose their session; reload each one and the login page appears.
4. Try the contrast: Sign in again, use the local-logout link on one app, reload it and observe it signs back in without a prompt.
5. Sign in to `http://localhost:4002` as `ifc-demo-uc08-client` (password in the state file): the claims app answers 403.

Cookies are keyed by host, not port, on localhost; the apps use distinct cookie names (`ifc_<key>_sid`) so they do not clobber each other.

### 2. Back-channel logout (needs a tunnel)

```bash
brew install cloudflared
cloudflared tunnel --url http://localhost:4001        # note the https://<public> URL
node demo/uc08-sso/setup.js --backchannel https://<public>
node demo/uc08-sso/serve.js
```

The tenant then POSTs `logout_token` to `<public>/bc/portal|claims|quote`. Repeat the steps above, then check
`http://localhost:4001/_events` (event `backchannel`, with `removed` > 0). Return to front-channel with `node demo/uc08-sso/setup.js`.

## Notes for the presentation

- Front-channel logout depends on the browser staying open for about 3 seconds on the tenant's logout page. Back-channel does not, which is why it matters for the admin-kill case.
- Idle / absolute timeouts have no API on this tenant; say so rather than showing a screen that does not exist.

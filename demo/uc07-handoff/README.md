# UC-07: App-to-voice transfer without re-authentication

IFC's requirement (`IAM Modernization Use Cases.pdf`, UC-07): a customer authenticated in the mobile app taps "Get an advisor" or
"Speak with a Voicebot" under Help. The CIAM service must provide **APIs to integrate with the CCaaS service to validate the user's
authentication token from the mobile app**; a **session bridge links the call with the mobile-app service**; for sensitive requests
(change e-mail) one of three step-ups applies (in-app approval, in-app code generator, passkey); then the CCaaS calls Billing,
Client 360 or Policy-change APIs.

Note on IFC's text: its main flow still contains the UC-06 line "User enters the OTP received via Voicebot". That contradicts the
title ("without reauthentication"). This demo follows the title and the trigger: the OTP is skipped when the app session is valid, and
it is the **fallback** when it is not (scenario F, and the whole UC-06 flow). Ask IFC to confirm.

Evidence tags: `[LIVE]` executed on the tenant, `[DOCS]` from documentation, `[INFER]` reasoning, `[HUMAN]` a person must do it.

## What is here

| File | What it does |
|---|---|
| `../../stubs/voicebot-ccaas/server.js` | The UC-06 voicebot stub, extended: `POST /handoff`, `GET /agent/:callId`, `GET /handoff/latest`; every request re-checks the app session (the "session bridge") |
| `../../routes/ifc-handoff.js`, `../../views/insurance/call-us.hbs` | Demo app: **Help** link, page `/app/call-us`, button "Speak with a Voicebot". The app sends the signed-in customer's access token (server side) to the voicebot |
| `setup.js` | Creates customer, TOTP, API client, STS client, "mobile app" client. Idempotent |
| `run.js` | Automated scenarios A to H against the real tenant. Writes `demo/out/uc07.json` |
| `serve.js` | Runs the voicebot with hand-off enabled on :4030 (for the browser path) |
| `voice.js` | Interactive voice leg. `--app-login` = terminal only; without it = continue the call the browser just handed off |
| `verify.js` | Pass / fail / human report (tenant state, scenarios, the app route, evidence) |
| `teardown.js` | Removes everything UC-07 created |

Tenant objects (all `ifc-demo-uc07-*`, found by `demo/teardown-all.js`): user `ifc-demo-uc07-marie` (policy `AUTO-77120`) + her TOTP,
API client `ifc-demo-uc07-ccaas` (5 entitlements), STS client `ifc-demo-uc07-ccaas-sts` (token exchange, 300 s tokens),
application `ifc-demo-uc07-mobile-app` (dynamic client, password grant: plays the mobile app for scripts).

## Run it

```bash
node demo/uc07-handoff/setup.js       # idempotent
node demo/uc07-handoff/run.js         # scenarios A-H, no human needed, ~30 s
node demo/uc07-handoff/verify.js      # tenant state + scenarios + demo-app route + evidence, ~1 min
node demo/uc07-handoff/voice.js --app-login   # presenter, terminal only
node demo/uc07-handoff/teardown.js
```

Presenter, browser path `[HUMAN]` (the real demo app, real Verify login):

```bash
node demo/uc07-handoff/setup.js
node ./bin/www                         # demo app on :3000 (restart it once after pulling this change)
node demo/uc07-handoff/serve.js        # voicebot on :4030
# browser: http://localhost:3000 > Login as ifc-demo-uc07-marie (password: see below) > Help > "Speak with a Voicebot"
node demo/uc07-handoff/voice.js        # continue the call that was just handed off
```

Marie's password is in the gitignored `demo/out/uc07.state.json` (`user.password`). Do not paste it anywhere.

## What the voicebot does on `POST /handoff` (the contract with Verify)

1. `POST /oauth2/introspect` (STS client, HTTP Basic) on the app's access token: must be `active:true`, issued to one of **our** app clients, and **not** itself a token-exchange token (so a voice-channel token cannot be replayed as an app token).
2. `GET /v2.0/Users/{sub}` (SCIM, least-privilege API client) maps `sub` to the policyholder; inactive users are refused.
3. Policy: the app login must be recent (`iat` within 15 min, `MAX_APP_AUTH_AGE_SEC`); otherwise fall back to a code `[INFER: iat as a proxy for authentication time]`.
4. `POST /oauth2/token` with `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693) mints a **voice-channel token** for the same subject, lifetime 300 s.
5. The call is bridged to the app session: the call is "authenticated by mobile app session" (tier 1). **Tier 2 requests still need a step-up.** Each later request re-introspects the app token, so signing out of the app, or deactivating the account, ends the bridge.

## Proven `[LIVE]` (`demo/out/uc07.json`, 48/48 checks, 45 Verify calls each with an `x-correlation-id`)

| Claim | Evidence |
|---|---|
| Verify validates the app's access token for the CCaaS | `POST /oauth2/introspect` 200, `active:true`, `sub`, `amr:["password"]`, `exp`, `client_id`, `grant_type` |
| A garbage, tampered, missing or replayed token is refused | introspection `active:false` for garbage and tampered; bot answers 400/401 |
| Token exchange works | `POST /oauth2/token` 200; `issued_token_type` access_token; `expires_in` 300 (STS `tokenSettings.accessTokenLifetime`); introspects `active:true`, same `sub`, `grant_type` token-exchange |
| Tier-1 requests need no OTP/TOTP call | scenario A: bill, renewal, pink slip, storage all 200; the transcript has no OTP call |
| Sensitive request still needs step-up | scenario B: 403 `step_up_required`, wrong code 401, right TOTP 200, action 200, second sensitive action 403 again |
| Sign-out drops the bridge at once | scenario D: `POST /oauth2/revoke` 200, next request 401 `app_session_ended` 0.3 s later |
| Account deactivation drops it at once | scenario E: SCIM `PATCH active=false` 204, next request 401 after 1.0 s, new login refused |
| A revoked app token cannot be exchanged | scenario D: exchange 400 `CSIAQ0158E` |
| Old app login falls back to a code | scenario F |
| Least privilege | scenario H: API client 403 on create/delete users and list API clients; wrong STS secret 401 |
| Demo-app route works | `verify.js`: the real `routes/ifc-handoff.js` + view mounted with a stand-in session: page renders, hand-off 200, agent screen-pop, token never echoed to the browser, 503 when the voicebot is down |

## Findings that differ from the build guide `[LIVE]`

- **The exchanged token is NOT revoked when the app token is revoked** (it stayed `active:true` after `/oauth2/revoke` on the original). Deactivating the user does kill both. This is why the bridge re-introspects the **app** token on every request instead of trusting the 300 s voice token.
- **`audience` is ignored.** The exchanged token's `aud` is the STS client id, not `ccaas`. The guide's "aud=ccaas" is wrong; use the STS client id as the audience identity of the voice channel.
- **No `act` claim.** An `actor_token` is accepted (and required when the STS client sets `actorTokenRequired`; otherwise `CSIAQ5242E`) but the exchanged token's introspection shows no `act`. The feasibility doc's "act/sub" claim is not supported.
- Access tokens are opaque to the outside (three dot-separated parts, but the payload is not JSON). **Offline JWKS validation is not possible for access tokens; introspection is the way.** The ID token is a JWT (RS256) and carries `amr`.
- Introspection does not return `auth_time` or `acr`. The voicebot therefore uses the access-token `iat` as the freshness signal.
- Introspection with a wrong client secret is `401 CSIAQ0155E`; with no client credentials `400 CSIAQ0147E`; for an unknown token `200 {"active":false}`.
- `POST /v1.0/endpoint/default/introspect` also accepted a plain **API client** (client id/secret in the body) with only 1 entitlement (`readUsers`) and returned `active:true` for another client's token. Anyone holding any API client credential can introspect tokens: protect those credentials `[LIVE, observed once]`.
- Scripted logins: the password grant works at `/oidc/endpoint/default/token` for a dynamic client registered with `grant_types:["password"]` and `all_users_entitled:true` (the `iss` of tokens from this path is `.../oidc/endpoint/default`, from `/oauth2/token` it is `.../oauth2`; introspection accepts both).
- STS `tokenSettings.accessTokenExpiry` is rejected (`CSIAQ0010E`); the working field is `accessTokenLifetime`.
- The laptop resolver intermittently fails for tens of seconds (`ENOTFOUND` on the tenant host). `demo/lib/verify.js` now retries these.

## Not proven

| Item | Why | Tag |
|---|---|---|
| Browser login to the real `TrustMeInsurance` app, then the button | Needs an interactive Verify login. The route and view are exercised with a stand-in session; a token issued to the real app client was not introspected. Introspecting and exchanging tokens issued to a different client worked for the DCR client, so it should work `[INFER]` | `[HUMAN]` |
| Push approval for the sensitive request | No phone registered (same as UC-06) | `[HUMAN]` |
| Passkey step-up | Needs a browser WebAuthn ceremony (UC-02) | `[HUMAN]` |
| A real CCaaS (Genesys, Amazon Connect, ...) carrying the token to the bot | The CCaaS is a stub. What IFC's CCaaS must do is the contract above | n/a |
| Reverse bridge (voice to web) `POST /v1.0/auth/session` | Not built, not needed by IFC's text | `[DOCS]` |
| A native mobile app and its SDK | The web demo app plays the mobile app | n/a |

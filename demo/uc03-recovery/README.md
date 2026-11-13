# UC-03 Risk-aware account recovery, agent-assisted

IFC requirement: a policyholder who lost a credential or is locked out recovers the account securely (resisting account takeover such as OTP interception). Low risk gets a time-boxed e-mail link. Higher risk (new device, new geography, recent factor change) gets an extra step or assisted recovery. On new credentials the active sessions end and the registered channel is notified. The event is logged for audit and fraud analytics.

Everything here runs against the real tenant (`https://trialverify.verify.ibm.com`). Nothing is clicked in the admin console.

## What is native Verify and what is IFC-side

| Piece | Who does it | Evidence |
|---|---|---|
| Self-service recovery: "Forgot password", 30-minute single-use e-mail link, new-password page, policy check, lock cleared | **Verify** (hosted Cloud Directory login) | [LIVE] run.js scenario E |
| Caller verification: one-time code e-mailed to the address ON FILE | **Verify** (`/v2.0/factors/emailotp/transient/verifications`) | [LIVE] scenario F |
| Agent reset: temporary password generated and e-mailed, user must change it | **Verify** (`PATCH /v2.0/Users/{id}/passwordResetter`) | [LIVE] scenario F |
| End all sessions | **Verify** (`DELETE /v1.0/auth/sessions/{id}`) | [LIVE] scenarios E, F, F2 |
| Step-up to TOTP outside the usual network | **Verify** access policy, `ipAddress` condition | [LIVE] scenario C |
| Signals (device, IP, country, lock, last login, factor created time) and audit | **Verify** (SCIM, factors, `/v1.0/events`) | [LIVE] scenarios D, H |
| Scoring the signals into low/high and choosing the route; the agent console; the case log | **IFC-side stub** (`stubs/recovery-console/`) | [INFER] this is how IFC's own service would do it |

Not a feature of this tenant: an AI risk score. The risk here is five explicit rules over Verify's signals. Say so.

## Files

| File | Purpose |
|---|---|
| `setup.js` | switch hosted "Forgot password" on (tenant-wide, OFF by default), agent API client (6 entitlements), 3 customers with disposable mailboxes, Marc's fresh TOTP, portal and sign-in apps, risk policy |
| `run.js` | all scenarios against the live tenant (about 8 minutes), writes `demo/out/uc03.json` |
| `verify.js` | checks the evidence file, scans it for secrets, prints proven and unproven |
| `teardown.js` | deletes everything named `ifc-demo-uc03-*` and switches "Forgot password" back OFF |
| `serve.js` | the demo UI on http://localhost:4030 (customer portal and agent console on one page) |
| `mailbox.js` | prints what a customer's mailbox received (`node demo/uc03-recovery/mailbox.js marc --open`) |
| `hosted.js`, `common.js`, `config.js` | helpers |

## Run

```bash
node demo/uc03-recovery/setup.js
node demo/uc03-recovery/run.js          # about 8 minutes
node demo/uc03-recovery/verify.js
node demo/uc03-recovery/serve.js        # live demo UI
node demo/uc03-recovery/teardown.js
```

## Objects on the tenant

`ifc-demo-uc03-recovery-console` (API client), `ifc-demo-uc03-portal` and `ifc-demo-uc03-signin` (applications), `ifc-demo-uc03-risk-signin` (access policy), users `ifc-demo-uc03-sophie`, `-marc`, `-lena`.
Tenant setting (not an `ifc-demo-` object): Cloud Directory identity source property `passwordResetEnabled=true`. `teardown.js` and `teardown-all.js` both switch it back off.

## Least-privilege entitlements of the console (each measured: removing it gives 403 on its call)

`readUsers`, `resetPasswordAnyUser`, `revokeAllSessions`, `readReports`, `readEnrollMFAMethodAnyUser`, `authnAnyUser`.
It is refused (403) for: list API clients, create/delete/deactivate a user, change the e-mail on file, read access policies.

## The risk rules (`stubs/recovery-console/recovery.js`, function `assess`)

| Signal | Source | Scored? |
|---|---|---|
| Authenticator added in the last 24 h | factor list `created` | yes: HIGH |
| Recent sign-in attempt from a device (User-Agent) never seen on a successful sign-in | events `devicetype` | yes: HIGH |
| Recent attempt from a country never seen on a successful sign-in | events `geoip.country_iso_code` | yes: HIGH |
| Attempt from a new IP address | events `origin` | no (mobile users change IPs) |
| Account locked | SCIM `pwdAccountLockedTime` | no (it is the reason people recover) |
| No earlier successful sign-in | events | explicit note, cannot judge |

HIGH routes to assisted recovery. The customer is only told the route, never the reasons.

## Demo script

1. `node demo/uc03-recovery/setup.js`, then `node demo/uc03-recovery/serve.js`, open http://localhost:4030.
2. Low risk: type `ifc-demo-uc03-sophie` and click Start recovery. Self-service route. Open the sign-in link, click "Forgot password", enter the user name. Read the e-mail with `node demo/uc03-recovery/mailbox.js sophie --open`, open the link, set a password.
3. High risk: type `ifc-demo-uc03-marc` (authenticator added minutes ago). The console shows RECENT_FACTOR_CHANGE and the assisted route. Click "Send a code to the address on file", read the code with `node demo/uc03-recovery/mailbox.js marc --open`, type it, confirm. Click "Reset password and end all sessions".
4. Refresh the audit table (events appear 15 to 90 s after the action).

Note: Marc's authenticator is enrolled at setup time. After 24 h it no longer counts as recent: run `setup.js` again before a demo.

## Honest limits

- [LIVE] `geoLocation` access-policy condition: the API accepts it but it never changed a sign-in outcome in 40+ tests. Not claimed. The `ipAddress` condition is evaluated.
- [LIVE] A new country cannot be produced from this laptop: Verify ignores X-Forwarded-For. "New geography" is proven on synthetic data only; real events do carry `geoip`.
- [LIVE] The hosted "Forgot password" page is not risk-aware. Verify sends the link to high-risk cases too, so IFC's portal must not offer it to them.
- [LIVE] The self-service reset page says a notification e-mail is sent. In these runs none arrived. The agent route does send "Password reset".
- [LIVE] The e-mail OTP API has a daily/hourly account quota (`CSIAP3523E`, HTTP 429). Many runs in a day can exhaust it.
- [LIVE] Verify events lag 15 to 90 s, ignore `search`/`filter`, and are paged at 1000 rows: the console filters client-side.
- [INFER] Real-time delivery of these events to a SIEM (webhook or event streaming) was not exercised.
- [HUMAN] The hosted flow was driven by a script that follows the same pages. A person doing it in a browser has not been recorded by this repo for UC-03.

# UC-14: Policyholder authorizing a Call Center Agent via CIBA

A call center agent starts an identity check from the agent console. IBM Verify sends the policyholder an approval request on **their own device**. The policyholder signs in and approves. The agent console then unlocks the agent's actions. The agent never sees a password, an OTP or a token that can be reused.

## IFC requirement (verbatim from "IAM Modernization Use Cases.pdf", UC-14)

> **Business context:** The call center agent handling user call would like to access the caller's personal information on their computer. The user can consent to this by, for example, approving a push notification on their phone.
> **Actors:** Policyholder, Contact Center Agent, Consumption Device (Agent's desktop), CIAM admin console. **Precondition:** Agent has a role in the CIAM admin console.
> **Capabilities needed:** User Management APIs; support authentication of user initiated by an Agent in lieu of the user through back channel authentication.
> **Main flow:** 1. The client application or consumption device (Agent's device) requests user authentication or authorization. 2. CIAM service receives the authorize request and sends a notification to the authentication device (user's device). 3. The user reviews the request and provides their response to the CIAM service. 4. Client application receives the appropriate tokens and presents the user's personal information on the Agent's device.
> **Demo:** Show the support agent console triggering channel-based caller verification. Show an example agent action, e.g. unlock caller account post successful authentication. Show the audit log entries.

**Honest gap:** IFC's example channel is a **push notification**. On this tenant only the **e-mail** channel is proven; push is accepted by the app but needs a phone with IBM Verify enrolled (`[HUMAN]`, not run). The "agent has a role in the CIAM admin console" precondition is **not** modelled: the stub console uses its own least-privilege API client, not a per-agent admin role.

## What is built

| Piece | Where |
|---|---|
| CIBA application (poll mode, e-mail channel, entitled users only) | tenant: `ifc-demo-uc14-agent-ciba` |
| Least-privilege API client for the console (`readUsers`, `manageUsers`, `readReports`) | tenant: `ifc-demo-uc14-agent-console` |
| Demo customer `ifc-demo-uc14-marie` (entitled) and `ifc-demo-uc14-outsider` (not entitled) | tenant |
| Customer-portal stand-in (password grant) used to lock and test sign-in | tenant: `ifc-demo-uc14-portal` |
| Agent console logic (start, poll, check who approved, gate actions, unlock, audit) | `stubs/agent-console/agent.js` |
| Agent console web page, port 4140 | `stubs/agent-console/server.js` |
| `setup.js`, `run.js`, `verify.js`, `teardown.js`, `serve.js`, `lock.js` | this folder |
| `ensureCibaApp` helper, `ciba` / `cibaToken` on `oauthClient` | `demo/lib/idempotent.js`, `demo/lib/verify.js` |

## Commands

```bash
node demo/uc14-ciba/setup.js              # idempotent
node demo/uc14-ciba/run.js                # 22 automated checks, no human needed (about 30 s)
node demo/uc14-ciba/run.js --approve      # adds the REAL approval [HUMAN], 30 checks
node demo/uc14-ciba/verify.js             # reads demo/out/uc14.json, pass/fail
node demo/uc14-ciba/serve.js              # live demo: http://localhost:4140
node demo/uc14-ciba/lock.js               # lock Marie (6 wrong passwords), to demo "Unlock account"
node demo/uc14-ciba/teardown.js           # removes every ifc-demo-uc14-* object
```

`run.js --approve` prints a **reference** such as `(ref DCAE)`. Approve the e-mail whose message ends with that reference. Older e-mails in the mailbox belong to older requests and will not satisfy the run.

## The flow

1. Agent types the caller's user name and clicks **Verify customer**. The console calls `POST /oauth2/ciba` (Basic client auth, `scope=openid`, `login_hint`, `binding_message`, `requested_expiry`).
2. Verify answers `{auth_req_id, expires_in, interval: 5}` and e-mails the caller. The e-mail shows the binding message ("IFC agent 482 is verifying your identity").
3. The console polls `POST /oauth2/token` (`grant_type=urn:openid:params:grant-type:ciba`) every 5 s. Until approval: 400 `authorization_pending`.
4. The caller signs in on Verify's page and approves. The next poll returns an access token and an ID token.
5. The console asks Verify's userinfo who the token belongs to and compares it with the caller on the call. Only then the session is **verified**.
6. Verified agent actions: read the caller profile (directory + a Client 360 stub), unlock the account.
7. Audit: the events API shows the CIBA token event with the binding message, the caller sign-in and the (collapsed) pending polls.

## Findings that matter [LIVE 2026-11-12]

- The CIBA app must be created with `applicationState: true` and `templateId: "1"`. Settings go under `providers.oidc.properties` (`grantTypes.ciba: "true"`, `additionalConfig.backchannelSettings`). Putting `additionalConfig` beside `properties` returns an empty 400.
- Channels accepted: `push` and `email` only (400 `CSIAQ0509` for `sms`). Push needs the user enrolled in the IBM Verify app (400 `CSIAQ5306E` otherwise).
- The app admits **entitled users only**; others get 403 `CSIAQ0279E`. Same mechanism as UC-10 (`ensureAppEntitlement`).
- `login_hint` is matched on the user name, case-insensitively. E-mail address and user id are **not** accepted (400 `CSIAQ5297E`).
- Unknown user: 400 `unknown_user_id`. No hint: 400 `CSIAQ5301E`. Wrong client secret: 401 `invalid_client`. Expired: 400 `expired_token` (`CSIAQ5298E`), also for an invented id.
- `requested_expiry` is honoured (10 s, 60 s, 900 s tested). Default is 1800 s. `interval` is 5 s.
- A deactivated user (`active: false`) is not found (`unknown_user_id`).
- A **locked** user (6 wrong passwords): the CIBA request is still accepted (200). During the test **no approval e-mail was received** for requests sent while the account was locked. Not established why, so the demo locks the account only after the approval.
- Unlock: there is no unlock endpoint (404). `PATCH` of `pwdAccountLockedTime` does not clear it. Only a **password replace** clears the lock. Without the header `usershouldnotneedtoresetpassword: true` the customer must set a new password at next sign-in (`CSIAQ0267E`), which is the right behaviour for an agent unlock. Reusing the same password fails (`PWD_IN_HISTORY`).
- Reading events needs `readReports` in addition to `readUsers` and `manageUsers`. With the first two only: 403 `CSIAK4300E`.
- Pending polls produce one failed SSO event each (`CSIAQ0249E`), so the console collapses them.
- The `binding_message` appears on the successful CIBA token event in the audit.

## What is a [HUMAN] step

The approval is a real person in a real mailbox. The scripts wait for it; they cannot do it. Push approval needs a phone with IBM Verify and the user enrolled (UC-06 `enroll-phone.js` covers enrolment); the app is created with `email` only, change with `ensureCibaApp(name, { channels: ['push', 'email'] })`.

## Limits to state

- This is a **stub console** (about 150 lines) built to show the pattern. IFC's real console (CCaaS agent desktop) would call the same two endpoints.
- The "verified" time window (5 minutes) is console logic held in memory. Verify does not provide a verified-agent session.
- The mailbox is the presenter mailbox (tenant admin e-mail unless `UC14_MAILBOX` is set). Do not point CIBA at real customers.
- The approval page is Verify's standard sign-in page; branding is not available on the trial.

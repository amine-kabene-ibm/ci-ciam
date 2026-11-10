# Intact (IFC) Demo Runbook: how a human presents each use case on the UI

**Audience:** the presenter (you).
**Companion docs:**
- [`DEMO-BUILD-GUIDE.md`](DEMO-BUILD-GUIDE.md): how each demo is built, live-tested facts, blockers, IBM message.
- [`INTACT-USE-CASE-FEASIBILITY-AND-DEMO-PLAN.md`](INTACT-USE-CASE-FEASIBILITY-AND-DEMO-PLAN.md): feasibility verdicts and rationale.
- [`VERIFY-PLAYBOOK.md`](VERIFY-PLAYBOOK.md): platform knowledge.

**Tenant:** `https://trialverify.verify.ibm.com` (EU trial). **Demo app:** `http://localhost:3000` (TrustMeInsurance).

> **Read this first.** This runbook is written ahead of the build. Each demo below has a **Readiness** line:
>
> | Readiness | Meaning |
> |---|---|
> | **READY NOW** | Everything needed exists today (demo app + tenant). You can rehearse it now. |
> | **PARTIAL NOW** | The tenant feature works and you can show it in the admin console or with the existing app, but the IFC-specific scenario page/stub is not built yet. |
> | **NEEDS BUILD** | The click path below assumes the page, stub or script described in the build guide. Nothing to click yet. |
> | **NEEDS IBM / HUMAN SETUP** | Blocked on an IBM tenant enablement or on a physical device/tunnel. |
>
> Evidence tags are the same as the build guide: `[LIVE]` executed against the tenant, `[DOCS]` from documentation, `[INFER]` reasoning, `[HUMAN]` a person must do it.
> Admin console menu names are written from documentation/memory and **can differ slightly by release**. Verify them once during rehearsal and fix this file.

---

## 0. Summary table

| UC | Topic | Readiness today | UI used | Honest limitation to state |
|---|---|---|---|---|
| 01 | Self-service registration, progressive profiling | PARTIAL NOW (app "Get a Quote" creates accounts) / NEEDS BUILD (OTP + Client 360) | Demo app, Verify login, mailbox | Flow designer is not enabled, so no no-code flow showpiece yet |
| 02 | Passkeys, OTP, TOTP fallback | NEEDS BUILD + HUMAN SETUP | Demo app over HTTPS, browser authenticator | Needs `mkcert` + hostname; BYO SMS gateway attach unverified |
| 03 | Risk-aware recovery, agent-assisted | PARTIAL NOW (app forgot-password) / NEEDS BUILD (agent console) | Demo app, agent page, admin console events | No AI risk score without Adaptive access |
| 04 | Trusted devices, push, revoke | NEEDS IBM / HUMAN SETUP | IBM Verify app on phone, admin console | Two registrations for one user unconfirmed |
| 05 | Adaptive risk and fraud | PARTIAL NOW (policy view) / NEEDS BUILD + IBM | Admin console, risk stub | Threat detection inactive; IFC signals go in as `external_risk` webhook, not as Trusteer model features |
| 06 | Voicebot | **READY NOW** for e-mail OTP + authenticator-code step-up (scripted 32/32 `[LIVE]`) / NEEDS HUMAN SETUP for push (phone) and passkey | Terminal "caller", admin console, mailbox | Voice is simulated; SMS/voice OTP blocked on this tenant (e-mail OTP used); push and passkey step-up not yet proven |
| 07 | App-to-voice handoff | NEEDS BUILD | Demo app + stub | None significant |
| 08 | SSO and global logout | NEEDS BUILD + tunnel | Browser with 3 stub apps | Idle/absolute session policy has no API found |
| 09 | API security | NEEDS BUILD (scripts proven) | Terminal + admin console | mTLS handshake not proven; do not claim it until tested |
| 10 | Per-brand login | NEEDS IBM (branding blocked on trial) | Two apps, login page | No sub-tenants (reseller only); themes blocked; delegated admin unconfirmed |
| 11 | Legacy migration | NEEDS BUILD (bulk) / NEEDS IBM (JIT) | Terminal, login page, admin console | JIT needs Flow designer or Bridge |
| 12 | ReBAC | NEEDS BUILD | Gateway stub UI/terminal | Not a Verify-native feature: Verify + OpenFGA |
| 13 | Broker lifecycle, immediate revocation | PARTIAL NOW (admin console deactivate) / NEEDS BUILD (timed script) | Admin console, demo app, terminal | Webhook delivery needs a public tunnel |
| 14 | CIBA agent-initiated | NEEDS BUILD + human mailbox/phone | Agent page, caller's email/phone | Approval is a real human action |
| 15 | Consent (PIPEDA) | PARTIAL NOW (comm. prefs, consent history, download, delete) / NEEDS BUILD (third parties, expiry, DSAR) | Demo app, admin console | DSAR SLA tracking is the stub's job, not Verify's |

---

## 1. Global preparation (do once, repeat before every session)

### 1.1 Machine checklist

| # | Check | Command / action | Expected |
|---|---|---|---|
| 1 | App is running | `curl -s -o /dev/null -w "%{http_code}\n" localhost:3000/` | `200` |
| 2 | Login redirects to tenant | `curl -s -o /dev/null -w "%{redirect_url}\n" localhost:3000/login` | URL starting `https://trialverify.verify.ibm.com/oidc/endpoint/default/authorize` |
| 3 | App is registered | Admin console → Applications → `TrustMeInsurance` | Present, enabled, redirect `http://localhost:3000/oauth/callback` |
| 4 | MFA policy attached | Admin console → Security → Access policies → `Require 2FA for MFAGroup` | Present, attached to the app |
| 5 | Token for API client works | `demo/00-probe.js` when built (the build guide section 1.3) | PASS table |
| 6 | Browser profiles | One clean profile for the customer persona, one for the agent/admin persona | Two separate windows, so cookies do not mix |
| 7 | Phone | IBM Verify app installed and one account registered (UC-04, 06, 14) | `[HUMAN]` |
| 8 | Tunnel | `cloudflared` or `ngrok` running (UC-05, 08, 13) | `[HUMAN]` |
| 9 | Mailbox | Test inbox open in a tab | `[HUMAN]` |

To start the app if it is down: `node ./bin/www` from the repo root (listens on `:3000`). To re-run tenant setup (idempotent): `curl -X POST localhost:3000/setup`.

### 1.2 Windows to keep open

1. **Customer window:** `http://localhost:3000` (demo app).
2. **Admin console:** `https://trialverify.verify.ibm.com` signed in as the tenant admin.
3. **Terminal:** repo root, with `demo/` scripts when built.
4. **Mailbox / phone.**

### 1.3 Existing demo-app map (what you can click today)

| Page | URL | What it shows |
|---|---|---|
| Home / "Get a Quote" | `/` | Name + email form. Starts an account-less quote |
| Quote (car/home) | `/open-account/car`, `/open-account/home` | Collects extra data; **creates the Verify account via SCIM** with a generated password sent by email (progressive collection) |
| Login | `/login` | Redirects to the Verify hosted login (OIDC) |
| Profile | `/app/profile` | Personal info, quotes, communication preferences (paperless, marketing), **Privacy & consent history**, **Security preferences** (Enable MFA, phone enroll, change password) |
| Consent history | `/app/consent` (link on profile) | Consent records from DPCM |
| Download my data | `/app/downloadme` | JSON of the user profile |
| Remove my account | `/app/deleteme` | Self-service deletion (type your name) |
| Forgot password | `/app/forgot-password` | OTP-verified password reset (app-implemented) |
| Forgot username | `/app/forgot-username` | Username recovery by email |
| Enroll SMS | `/app/enroll/sms` | Phone enrollment for SMS OTP |
| Setup | `/setup` | Idempotent tenant provisioning |

---

## 2. Per-use-case runbooks

Each section: **Readiness, Prerequisites, Click path, Talk track, Show in admin console, If it breaks, Honest limitation.**

---

### UC-01: Self-service registration and progressive profiling

**Readiness:** PARTIAL NOW. The "Get a Quote" path creates an account with minimal data and collects more on later quotes. The IFC-specific variant (email OTP, duplicate check, Client 360 id in the token) is NEEDS BUILD. Flow designer showpiece is NEEDS IBM.

**Prerequisites**
- App running; test email address you can read; Verify email delivery working (send one test before the session) `[HUMAN]`.

**Click path (today's app)**
1. Customer window → `http://localhost:3000` → fill **First name, Last name, Email** → **Get a quote**.
2. Choose **Car** → fill vehicle details and ZIP → submit.
3. Success page says a password was generated and emailed.
4. Open mailbox → follow the Verify email → sign in with the generated password → set a new one if prompted.
5. Land on **My Profile**. Show name, email, and the quote count.
6. Start a second quote (Home). Show that no new account is created, and the existing one is updated.

**Click path (once built, UC-01 Track A)**
1. `/ifc/register/start` → enter email → app checks duplicates in Verify → **email OTP** → enter code.
2. Account is created with minimal data. Show the profile with only email.
3. Do a first action, e.g. start a quote. The app redirects to **step 2** and asks for postal code only. Complete it.
4. Decode the ID token on the profile debug panel: show the `client360_id` claim.

**Talk track**
- "Only collect what you need to get them in. The rest comes when it's useful: progressive profiling."
- "Duplicate detection is a SCIM query on email, not custom matching."
- "Client 360 linking happens at registration; the id is stored on the identity so tokens carry it with no runtime call to your CRM." (Honest: this is deliberate because trial tenants cannot do an external callout at token time.)

**Show in admin console**
- Directory → Users: the new user, attributes filling in over time (custom attributes: `quoteCount`, `carMake`, ...).
- Reports / Events: user-registration and email-OTP events.

**If it breaks**
- No email: use the admin console → user → reset password to set one; or run the SCIM create from a script with header `usershouldnotneedtoresetpassword: true`.
- OTP not arriving: fall back to the app's pre-seeded user.

**Honest limitation:** Flow designer is not enabled `[LIVE]`, so the visual no-code orchestration is not demoable until IBM enables it. Claim mapping of `client360_id` into the ID token is not yet proven `[INFER]`.

---

### UC-02: Passkeys / FIDO2 with OTP and TOTP fallback

**Readiness:** NEEDS BUILD + HUMAN SETUP.

**Prerequisites**
- `mkcert -install`; `127.0.0.1 ifc-demo.local` in `/etc/hosts`; app served on `https://ifc-demo.local:3443`.
- FIDO2 relying party created for that origin.
- A browser with a platform authenticator (Touch ID / Windows Hello) or a security key.
- Rehearse registration once, so you know how the OS prompts.

**Click path**
1. Customer window → `https://ifc-demo.local:3443` → sign in with password (AAL1).
2. Profile → **Security preferences** → **Add a passkey** (once built) → approve the Touch ID prompt.
3. Sign out. Sign in again → **Use a passkey** → approve → no password typed.
4. Show fallback: choose **Use another method** → email OTP → code → in.
5. Show TOTP: Profile → **Add authenticator app** → scan the QR with any authenticator app → sign out → sign in using the TOTP code.
6. Show assurance levels: open the three demo apps (AAL1 / AAL2 / AAL3). Each policy asks for a different minimum method.

**Talk track**
- "Passkey is the strongest, phishing-resistant method. OTP and TOTP are fallbacks controlled by policy."
- "Assurance level is a policy, not code. Moving a line of business from AAL2 to AAL3 is a policy change."
- "SMS can be routed to your own provider through the external SMS webhook." (Say this only after the attach is tested.)

**Show in admin console**
- Security → Access policies: the three policies and their allowed methods.
- Directory → Users → the user → registered authentication methods (passkey, TOTP).
- Events: sign-in events listing the factor used.

**If it breaks**
- Browser says insecure context: you are on `localhost` or an untrusted cert. Use the `ifc-demo.local` HTTPS URL.
- Passkey prompt fails: use a second browser or a hardware key.

**Honest limitation:** WebAuthn requires a real hostname and HTTPS. The exact policy method name for passkeys and the external SMS attach are unverified.

---

### UC-03: Risk-aware account recovery, agent-assisted

**Readiness:** PARTIAL NOW (customer-side forgot-password). Agent console is NEEDS BUILD.

**Prerequisites**
- A test customer with a readable email.
- Agent persona signed in on a second browser profile (the `/agent` page once built).
- Optional: VPN or second network to make the sign-in look foreign.

**Click path**
1. Customer window → `/app/forgot-password` → enter email → receive OTP → set a new password. Show it works.
2. Risky scenario: from a different network/VPN country, try to sign in. Policy demands an OTP (geoLocation rule).
3. Agent window → `/agent` → search the customer → buttons: **Send reset**, **End all sessions**, event table for that user.
4. Click **End all sessions**. In the customer window, refresh a profile page: the session is gone and login is required.

**Talk track**
- "Self-service handles the normal case. Anything unusual escalates to an agent with identity-safe tools, not password peeking."
- "The agent never sees a password. They trigger Verify's reset and see the audit trail."

**Show in admin console:** Events: password-reset, session-revoke, and sign-in events for the user.

**If it breaks:** If the geo rule does not trigger, show the policy and a recorded event; do not claim live detection.

**Honest limitation:** No AI risk score unless IBM enables Adaptive access. Geo and IP rules are available.

---

### UC-04: Trusted devices (two devices), push, self-service revoke

**Readiness:** NEEDS IBM / HUMAN SETUP.

**Prerequisites**
- IBM Verify app on phone(s). Two registrations for the same user (two phones, or two accounts on one phone, or a second device).
- `demo/uc04-devices/` scripts when built.

**Click path**
1. Terminal/Admin → generate registration QR for user (A). Scan with the IBM Verify app. Do the same for device B.
2. Admin console → user → authenticators: two entries.
3. Sign in on the demo app. Phone shows a push: **Approve**.
4. Repeat and **Deny** to show failure.
5. Revoke device A: Admin console (or app page, once built) → remove. Next push goes only to device B.

**Talk track:** "Push is a second factor with context (location, IP, message). Revocation is immediate."

**Show in admin console:** Authenticators list; events for approve/deny.

**If it breaks:** If the second registration is rejected, say so: "one registered IBM Verify authenticator per user in this configuration; IFC's two-device need is addressed with passkeys plus push." (The RFP accepts a stated limitation.)

**Honest limitation:** Two authenticators per user is not confirmed. No registered phone exists yet `[LIVE]`.

---

### UC-05: Risk-based adaptive authentication and fraud signals

**Readiness:** PARTIAL NOW (you can show policy conditions). Live scoring NEEDS IBM + stub.

**Prerequisites**
- Risk stub (`stubs/risk-engine`) running and a public tunnel URL.
- `external_risk` webhook created and referenced from the policy.
- IBM asked to activate Threat detection and enable Adaptive access.

**Click path**
1. Admin console → Access policies → open `ifc-demo-risk` → show rules: low = allow, medium = MFA, high = deny.
2. Customer window → sign in normally: allowed.
3. Run `demo/uc05-risk/stuffing.js` (rotating IP/UA, repeated failures). The stub's counter rises; the next sign-in is stepped-up or denied.
4. Admin console → Events: decision table.

**Talk track**
- "Your own fraud signals can be a policy input through an external risk webhook. The decision is made at login, in the policy."
- "Verify's built-in threat detection (credential stuffing, brute force) complements it once activated."

**If it breaks:** Show the policy and the recorded events from rehearsal. Do not claim live Trusteer scoring.

**Honest limitation:** Threat detection is `inactive` on the tenant `[LIVE]`. `X-Forwarded-For` spoofing may not be honoured at the SaaS edge. Proprietary signals are inputs, not features of IBM's model.

---

### UC-06: Voicebot (CCaaS) information query and transactions

**Readiness:** READY NOW for the e-mail OTP and authenticator-code (TOTP) paths. Push step-up is NEEDS HUMAN SETUP (register a phone, 5 min). Passkey step-up is not built.

**Prerequisites**
- `node demo/uc06-voice/setup.js` (idempotent). Demo customer: Marie Tremblay, policy `AUTO-48213`. Her e-mail is the tenant admin mailbox, so keep that mailbox open.
- Optional, for the push moment `[HUMAN]`: IBM Verify app on a phone, then `node demo/uc06-voice/enroll-phone.js` and scan the QR.
- Run `node demo/uc06-voice/run.js` once before the session (20 s to 2 min, it waits for TOTP windows). It must end `32/32 checks passed`. Then wait about 1.5 min before presenting, so `caller.js` has fresh TOTP windows.

**Click path** (terminal: `node demo/uc06-voice/caller.js`)
1. The bot greets. Type the policy number `AUTO-48213`. The bot looks the customer up in Verify (SCIM) and offers an e-mail code.
2. Choose `1` (e-mail me a code). Verify sends a real e-mail to the address on file. Read the code in the mailbox: it looks like `4821-305917`. **Type only the digits after the dash** (`305917`).
3. Choose request `1` ("What is my outstanding bill amount?"). Answer comes from the mock Billing API. Try `3` (pink slip e-mailed to the address on file) and `4` (storage): all tier 1, no extra proof.
4. Choose request `5` (change my e-mail). The bot refuses until one more approval: choose `push` and approve on the phone, or `totp` and type `auto` (the script plays the authenticator app) or a real code from an authenticator app.
5. The request succeeds. Ask for `6` (change bank account) right after: a new step-up is demanded (one step-up approves one sensitive action).
6. Hang up (`0`). The call prints every Verify API call with HTTP status, duration and `x-correlation-id`.

**Talk track:** "Risk-tiered verification: an information query needs one light proof, money or contact-detail changes need a second, stronger one. Verify supplies the OTP, the authenticator-code check and the push approval as APIs; the contact-centre platform orchestrates the conversation. The voicebot runs on an API client with five entitlements, not the admin credential."

**Show in admin console**
- Admin console > Security > API clients: `ifc-demo-uc06-ccaas` with its short entitlement list (compare with the admin client).
- Users: `ifc-demo-uc06-marie`, her TOTP enrolment (and the registered device if you enrolled a phone).
- Events / reports for the OTP and authenticator verifications (menu names vary by release; confirm in rehearsal).

**If it breaks**
- Bot says it could not send the code, or `CSIBN0075E` in the output: the mailbox address is on Verify's suppression list. Clear it with `node -e "require('./demo/lib/verify').api('DELETE','/v1.0/notification/suppression/email/YOUR%40ADDRESS')"` (204 = cleared). Never use `@example.com` for the mailbox.
- `429 CSIBN0081E` on a code: too many wrong codes; wait about 20 s.
- TOTP code rejected: each 30-second code works once. Wait for the next one.
- Push never arrives: run `node demo/uc06-voice/enroll-phone.js --status`; if there are 0 registrations, scan the QR again. Fall back to the `totp` option.
- Anything else: `node demo/uc06-voice/setup.js` then `node demo/uc06-voice/run.js`.

**Honest limitation**
- Voice itself is simulated (text). Verify does not do voice biometrics, speech or telephony.
- **SMS and voice-call OTP are blocked on this tenant** (`CSIAP3545E`). The demo uses e-mail OTP. Say so; SMS is configuration plus quota, and a customer SMS gateway via the `external_sms` webhook purpose is unverified.
- Push approval and passkey step-up are not proven until a phone / browser is used `[HUMAN]`. Do not promise passkey for this flow until UC-02 is done.
- Billing, Client 360 and Policy-change APIs are stubs; Verify is not involved in them.

---

### UC-07: App-to-voice transfer without re-authentication

**Readiness:** NEEDS BUILD.

**Prerequisites:** STS client; stub on :4030; user logged in to the demo app.

**Click path**
1. Customer window → sign in → profile → **Call us** (button to be added) → handoff.
2. Terminal/stub UI shows the agent side: the voice stub received a token, introspected it (`active:true`, `sub`), and optionally exchanged it.
3. Agent sees "Customer already authenticated by app (AAL2)". No questions asked for low-risk actions; step-up for sensitive ones.

**Talk track:** "The customer proves identity once. The token carries that assurance to another channel."

**Show in admin console:** Token exchange client; events.

**Honest limitation:** None significant. Token exchange is documented and the STS client creation is proven `[LIVE]`.

---

### UC-08: SSO across apps and global logout

**Readiness:** NEEDS BUILD + tunnel.

**Prerequisites:** three stub RPs on :4001-4003 with public URLs for back-channel logout; broker and consumer personas.

**Click path**
1. One browser window. Open RP-A → sign in (password + MFA for broker persona).
2. Open RP-B and RP-C in new tabs: no login prompts (SSO).
3. Log out of RP-A. Refresh RP-B and RP-C: both are signed out (back-channel logout).
4. Show persona difference: sign in as a consumer; no MFA required by policy.

**Talk track:** "One session, many apps. One logout, all apps. Policies differ by persona."

**Show in admin console:** The three registered apps and their logout settings; sessions.

**If it breaks:** If back-channel callbacks fail (tunnel down), show front-channel logout instead.

**Honest limitation:** Idle and absolute session timeouts have no API found; use per-app token lifetimes and say so.

---

### UC-09: API security

**Readiness:** NEEDS BUILD. The underlying calls were proven `[LIVE]` (private_key_jwt token issued).

**Prerequisites:** `demo/uc09-api/` keys, clients, and `stubs/ifc-api`.

**Click path**
1. Terminal: `run.js`. Show the signed client assertion, the token request, and the token.
2. Call the stub API with the token: 200. Call with a token from a wrong key: 401.
3. Key rotation: add a second key to the client, show both work, remove the first, show the old key is rejected.
4. On-behalf-of: partner token + policyholder token → exchanged token with an `act` claim.
5. Admin console → Applications / API clients: show the clients and auth methods.

**Talk track:** "Machine clients authenticate with keys, not shared secrets. Rotation is zero-downtime. Partners act on behalf of a policyholder with a delegated token."

**Honest limitation:** mTLS client authentication registers but the handshake is unproven. If the test fails, offer DPoP and `private_key_jwt` instead. Do not claim mTLS.

---

### UC-10: Per-brand login

**Readiness:** NEEDS IBM (branding disabled on the trial). Two-app policy difference can be shown now.

**Prerequisites:** Brand A / Brand B apps and policies; IBM to enable branding.

**Click path**
1. Open Brand A app → login page with brand A look (after branding is enabled), FR/EN switch.
2. Open Brand B app → different look and a passkey-first policy.
3. Sign in with one user across both. One identity, two experiences.

**Talk track:** "One identity platform. Brand experience is configuration, not a separate tenant."

**Honest limitation, state clearly:**
- Themes cannot be registered on the trial (403) `[LIVE]`. Until IBM enables branding, show only policy differences.
- Sub-tenants are reseller-only `[LIVE]`. Per-brand tenancy is not available.
- Multiple custom domains and delegated admin per brand are unconfirmed. See the IBM message in the build guide.

---

### UC-11: Legacy IAM migration

**Readiness:** NEEDS BUILD (bulk). JIT NEEDS IBM (Flow designer or Verify Bridge).

**Prerequisites:** `stubs/legacy-auth-store`; CSV with hashed passwords; supported hash prefix confirmed.

**Click path**
1. Terminal: show the legacy store with users and hashes.
2. Run `demo/uc11-migration/bulk.js`: imports the CSV into Verify.
3. Admin console → Directory → Users: imported users.
4. Customer window → sign in with the **original password** of a migrated user: success. No reset required.
5. (JIT, once available) Sign in as a user not yet migrated; the Bridge/Flow verifies against the legacy store and creates the user.

**Talk track:** "Bulk for the bulk, JIT for the long tail. Customers never reset passwords."

**Honest limitation:** Supported hash types are unconfirmed beyond `{SSHA256}`. Flow designer and Bridge are not available yet.

---

### UC-12: ReBAC

**Readiness:** NEEDS BUILD (OpenFGA container).

**Prerequisites:** Podman allowed to pull OpenFGA; `stubs/policy-api`; seeded brokers/clients/policies.

**Click path**
1. Show the model diagram: brokerage → broker → client → policy.
2. Terminal/stub UI: broker A requests client X's policy → allowed.
3. Broker A requests client Y (belongs to another brokerage) → denied.
4. Reassign broker A to another brokerage (tuple update). Re-run: results change immediately, no re-login.

**Talk track:** "Verify authenticates the broker. A relationship engine decides what that broker may see. Changing a relationship changes access instantly."

**Honest limitation:** Not Verify-native. Position as Verify + OpenFGA (open source) or IFC's existing rules engine.

---

### UC-13: SCIM broker lifecycle and immediate revocation

**Readiness:** PARTIAL NOW. Admin console deactivate works today; the timed script and webhook are NEEDS BUILD. The core behaviour was proven `[LIVE]`.

**Prerequisites:** a test broker user; the DCR password client for the script; optional tunnel for webhook.

**Click path**
1. Customer window → sign in as the broker → open a profile page (session active).
2. Admin console (or SCIM script) → deactivate the broker.
3. Customer window → refresh. Access is lost. A new sign-in shows "The account is not active".
4. Terminal: `run.js` prints the timeline: token active → PATCH → introspect `active:false` in 0 s → login rejected.
5. Failure path: PATCH a nonexistent id; the ops-queue stub receives the failure event.

**Talk track:** "Offboarding a broker in the broker system calls SCIM. Access ends in the same second, including tokens already issued."

**Show in admin console:** the user status, events (deactivation, rejected login).

**Honest limitation:** Webhook delivery to a local stub needs a public tunnel.

---

### UC-14: CIBA agent-initiated authentication

**Readiness:** NEEDS BUILD (agent page) + human approval.

**Prerequisites:** CIBA app (enabled with `applicationState:true`); `/agent/verify` page; a test user whose email you can read, or a registered phone.

**Click path**
1. Agent window → `/agent/verify` → enter the customer's username → **Verify customer**.
2. Binding message shows: "IFC agent #482 verifying your identity".
3. Customer (phone/email) receives the request → **Approve**.
4. Agent page switches to **Verified**. **Unlock account** becomes available.
5. Admin console → Events: audit trail with the binding message.

**Talk track:** "The agent starts the verification, the customer approves on their own device. The agent never handles credentials."

**If it breaks:** Email approval link slow: use push after registering a phone.

**Honest limitation:** Approval is a real human action. Do not point CIBA at real customers.

---

### UC-15: Consent management (PIPEDA)

**Readiness:** PARTIAL NOW. Communication preferences, consent history, data download and account deletion work in the app today. Third-party consents, expiry, export and DSAR timer are NEEDS BUILD.

**Prerequisites:** a logged-in test user; purposes exist (`communications`, `paperless-billing`, `terms`) `[LIVE]`.

**Click path (today)**
1. Sign in → **My Profile** → **Communication preferences**: toggle Paperless billing and Marketing → **Save Settings**.
2. Click the **Privacy & consent history** icon: each change appears as a consent record.
3. **Download my data**: JSON of the profile.
4. **Remove my account** (use a throwaway user): type name, confirm. Redirects to logout.
5. Admin console → Privacy & consent → Purposes: the same purposes and their consent counts.

**Click path (once built)**
1. Third party (repair shop) requests access to claims data → consent screen → approve with a 60-second duration.
2. Call the third-party API: allowed. After expiry: denied.
3. Run `export.js`: consent ledger as JSON/CSV for an audit request.
4. Submit a deletion request in the DSAR stub: SLA timer starts, completes when consent and user are deleted.

**Talk track:** "Consent is data with a purpose, a duration and a ledger. The user sees it, can withdraw it, and an auditor can export it."

**Honest limitation:** DSAR workflow and SLA timers are done by the stub, not by Verify.

---

## 3. Rehearsal checklist

| Step | Done |
|---|---|
| Run the global checks in section 1.1 | ☐ |
| Open each admin console page used and confirm the menu names, then correct this file | ☐ |
| For every demo marked PARTIAL/NEEDS BUILD, record which pieces exist by the demo date | ☐ |
| Pre-create and sanity-check test users (one customer, one broker, one agent) | ☐ |
| Send yourself one email through Verify to confirm delivery | ☐ |
| Register the phone and test one push | ☐ |
| Start the tunnel and send one webhook | ☐ |
| Dry-run the whole sequence once with a stopwatch | ☐ |
| Record a screen capture of each demo as a fallback | ☐ |

## 4. Suggested running order for the IFC session

1. UC-01 → UC-02 → UC-03 (customer journey).
2. UC-04 → UC-14 → UC-06 → UC-07 (assurance across channels).
3. UC-08 → UC-13 → UC-09 → UC-12 (brokers and APIs).
4. UC-15 → UC-11 (compliance and migration).
5. UC-05 and UC-10 last, and framed honestly: what Verify does, what depends on IBM enablement, what is outside the product.

## 5. Questions IFC will likely ask, with straight answers

| Question | Answer |
|---|---|
| Can we have a separate tenant per brand? | Not on this tenant. Sub-tenants are reseller-only `[LIVE]`. Per-brand experience via apps, policies and themes. Ask IBM for the options. |
| Is mTLS supported for APIs? | Registration of `tls_client_auth` works; the end-to-end handshake is not yet proven. `private_key_jwt` is proven. |
| Can our fraud engine feed the login decision? | Yes through an `external_risk` webhook in a policy; it is a policy input, not an IBM model feature. |
| Can users keep their old passwords on migration? | Yes for supported hash formats via bulk import; the supported list is being confirmed with IBM. |
| Is ReBAC native? | No. Verify authenticates; OpenFGA or IFC's rules engine decides. |
| How fast is revocation? | Same second for tokens and new logins `[LIVE]`. |

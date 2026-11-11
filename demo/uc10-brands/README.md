# UC-10: Per-brand login (customizable login facility)

IFC's requirement (`IAM Modernization Use Cases.pdf`, UC-10): each brand gets its own login, registration and recovery experience
on a centralized IdP. Three capabilities: (1) delegated administration so each digital team manages only its own brand;
(2) multiple custom IdP URLs (`idp.brand1.com`, `idp.brand2.com`); (3) login UI customization per brand URL
(theme, French and English, legal text, consent wording, support links) with brand-specific policies (MFA, registration).

Evidence tags: `[LIVE]` executed on the tenant, `[DOCS]` from documentation, `[INFER]` reasoning, `[HUMAN]` a person or IBM must do it.

The two brands are fictional stand-ins: **Aurora Insurance** (English first, password only) and **Boréal Assurance**
(French first, passkey with authenticator-app fallback, asked at every sign-in).

## What is here

| File | What it does |
|---|---|
| `../../stubs/brand-portal/server.js` | One small OIDC relying party (code + PKCE) per brand, on its own host name. Routes: `/`, `/login?lang=`, `/callback`, `/logout`, `/_sessions` |
| `common.js` | Brands, users, the two policies, names |
| `themes.js` | Builds one theme ZIP per brand from `ci-theme/templates` (brand colour, logo, EN/FR labels, legal text, support link) and tries to register it |
| `setup.js` | Creates users, TOTP, 2 policies, 2 brand apps (owners, entitlements), the theme ZIPs. Idempotent |
| `run.js` | 49 checks, scenarios A-I, against the real tenant. Writes `demo/out/uc10.json` |
| `serve.js` | Runs both portals for a real browser |
| `verify.js` | Pass / fail / human report |
| `teardown.js` | Removes everything UC-10 created |

Helpers added to `demo/lib/idempotent.js`: `appIdOf`, `listAppEntitlements`, `ensureAppEntitlement`, `removeAppEntitlement`.
`demo/teardown-all.js` now also sweeps branding themes. `demo/uc08-sso/browser.js` gained a `headers` field (to send `Accept-Language`).

Tenant objects (all `ifc-demo-uc10-*`): users `-customer` (+ validated TOTP), `-aurora-only`, `-aurora-admin`, `-boreal-admin`;
policies `-policy-aurora`, `-policy-boreal`; applications `-aurora`, `-boreal`, `-admin-console` (password grant, used only to get the brand admins' own tokens).

## Commands

```bash
node demo/uc10-brands/setup.js      # idempotent
node demo/uc10-brands/run.js        # scenarios A-I, 49 checks, evidence in demo/out/uc10.json
node demo/uc10-brands/verify.js     # PASS / FAIL / HUMAN
node demo/uc10-brands/serve.js      # both portals for the browser demo
node demo/uc10-brands/themes.js     # rebuild ZIPs and retry registration (after IBM enables branding)
node demo/uc10-brands/teardown.js   # remove everything
```

## What is proven [LIVE]

- **Separate experience per brand, one identity.** Two applications (own client id, own redirect host `aurora.localhost` / `boreal.localhost`), one tenant.
  The same user gets the same `sub` at both brands.
- **Languages.** The Verify login page, the second-factor page and the error pages switch language: `ui_locales=fr|en`, or the browser's `Accept-Language`
  (`fr-CA` gives French). With neither, English is shown, so a French-first brand must send `ui_locales=fr` (the Boréal portal does).
- **Brand-specific policy.** Aurora: password only (page sequence `login`). Boréal: password, then the authenticator-app page in French with "Utiliser une autre méthode"
  (`login,totp`). The same customer gets a different journey at each brand.
- **Customers per brand.** `all_users_entitled:false` plus a per-user entitlement: a customer not entitled to Boréal is refused with `CSIAQ0279E` (HTTP 401, in French when French is requested).
- **Delegated administration (RBAC).** Naming a user an application owner gives them the `applicationowners` role automatically. With their own token they:
  list only their brand's application, list/add/remove their brand's customers (takes effect at once), and are refused on the other brand
  (`CSIAD0047` on write, empty shell on read). They are refused on `/v1.0/applications`, access policies and group creation (403).
- **Cross-brand SSO.** One browser has one Verify session per tenant host: after Aurora, Boréal asks only the second factor.

## What is NOT proven, and limits to state honestly

- `[LIVE]` **Branding is blocked on the trial.** `POST /v1.0/branding/themes` returns 403 `CSIAZ3060E`. The two theme ZIPs are built and inspected offline, but never registered or applied.
  Until then the Verify pages carry IBM styling; only the language switches. Brand colours, logo, legal text, support links and consent wording are **not** shown by Verify today.
  The consent page shows the client name only (`client_uri`, `policy_uri`, `tos_uri` are ignored).
- `[LIVE]` **Custom IdP URLs cannot be improvised.** A request with an unregistered `Host` header gets HTTP 400 from the edge. Sub-tenants return 405 `CSIAG0746E` (reseller only).
  Custom domains are an IBM / sales configuration `[DOCS]`.
- `[LIVE]` **Delegated admin is per application, and limited.** An owner cannot change the brand's access policy or theme (the owner API accepts only `name` and `provisioning`), and `themedeveloper` is tenant-wide.
  An owner **can read** the tenant's SCIM user directory and the other brand's entitlement list: users are not partitioned per brand.
- `[LIVE]` **Group entitlements do not gate sign-in** (accepted, 200, but the members were not admitted). Use per-user entitlements.
- `[LIVE]` **Per-brand sender domain** is off: `CSIAP3564E` "Sender customization is not enabled".
- `[HUMAN]` A real passkey at Boréal (needs a browser authenticator). The TOTP fallback is proven.
- `[HUMAN]` The real-browser view (pixels).
- `[INFER]` Registration and recovery per brand: the self-registration and password-recovery pages come from the same themes, so they are blocked by the same enablement. Not tested.

## Human steps

### 1. Real-browser view (about 5 minutes)

```bash
node demo/uc10-brands/setup.js
node demo/uc10-brands/serve.js
node -e "const s=require('./demo/out/uc10.state.json');console.log('customer password:',s.users.customer.password)"
node -e "const t=require('./demo/lib/totp');const s=require('./demo/out/uc10.state.json');console.log('TOTP now:',t.totp(s.totp.secret))"
```

1. Open `http://aurora.localhost:4101`, click Sign in, user `ifc-demo-uc10-customer`: password, straight into the Aurora portal.
2. In a private window open `http://boreal.localhost:4102`: French pages, password, then the authenticator-app page (use the code printed above). Click "Utiliser une autre méthode" to show the passkey option.
3. Sign in as `ifc-demo-uc10-aurora-only` at Boréal: French refusal page (`CSIAQ0279E`). It works at Aurora.
4. Say plainly that the Verify pages look IBM-standard today because branding is not enabled on the trial.

### 2. Passkey at Boréal

Register a passkey for `ifc-demo-uc10-customer` in the Verify end-user profile (browser with a platform authenticator), then sign in at Boréal: the passkey is offered first.

### 3. IBM message (send to the IBM account team)

1. Please enable the **branding** feature on `trialverify.verify.ibm.com` (today `POST /v1.0/branding/themes` returns 403 `CSIAZ3060E`). Then run `node demo/uc10-brands/themes.js`, which registers both packages and prints the ids; set `customization.themeId` on each application (`setup.js` does it when the registration returns an id).
2. Can one tenant serve several **custom IdP domains** (`idp.brand1.com`, `idp.brand2.com`), each tied to its own theme? How is it ordered and what is the lead time?
3. Can **e-mail sender domains** be set per brand (`CSIAP3564E` today)?
4. Can the **user directory and administrators be partitioned per brand** (an application owner can currently read all users)? Is there a per-brand scope for `themedeveloper`?
5. Can **consent wording and legal links** be set per application, without a theme?

## Notes for the presentation

- Lead with what is real: one identity, per-brand policy, language, per-brand customers, per-brand administrators with live revoke.
- State the branding and custom-domain gaps up front as an IBM enablement, not a product gap: the packages are ready.

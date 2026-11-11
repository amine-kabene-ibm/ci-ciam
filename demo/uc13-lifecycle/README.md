# UC-13: Broker Identity Lifecycle via SCIM 2.0 with Immediate Revocation

Demonstrates automated Broker Identity Lifecycle Synchronization via standards-based **SCIM 2.0**, in-flight role updates, **immediate access revocation** across tokens and sessions upon deactivation, and operations queue error logging for IFC administrators.

---

## 1. IFC Requirement Alignment

> **IFC Ask (Use Case UC-13):**
> *"Broker identities manual account creation/deprovisioning is a slow process and a security risk when offboarding is delayed. A standards-based, automated broker identity lifecycle sync is a preferred and secure approach."*
>
> - **Trigger:** Broker new hire, role change, transfer, or termination event occurring in the Broker source system (HR/Brokerage Management System).
> - **Capabilities Needed:** User Management APIs, SCIM 2.0 support for user synchronization to Intact User directory.
> - **Main Flow:**
>   1. Source system sends lifecycle event (create/update/deactivate) via SCIM 2.0.
>   2. CIAM platform provisions, updates, or deactivates the identity and its enterprise attributes (`department`, `title`, `employeeNumber`).
>   3. Deactivation immediately revokes active sessions and downstream application access, not just the directory entry.
>   4. Provisioning errors are logged to an operations queue.

---

## 2. Architecture & Components

```
                                  +---------------------------------------+
                                  |         IBM Verify SaaS               |
                                  |                                       |
  [ Broker Source System / HR ]   |  - SCIM 2.0 Directory (/v2.0/Users)   |
              |                   |  - OIDC Token Endpoint (/oauth2/token)|
              | SCIM 2.0          |  - Introspection (/oauth2/introspect) |
              v                   |  - Session Kill (/auth/sessions/{id}) |
  +-----------------------+       |  - Webhook Engine (/webhooks/)        |
  |  SCIM Sync Connector  | ----> +---------------------------------------+
  +-----------------------+                           |
              | (sync / errors)                       | Webhook Notifications
              v                                       v
  +-------------------------------------------------------+
  |    IFC Operations Queue Stub & Broker Dashboard       |
  |    (port 4040: stubs/ops-queue/server.js)             |
  +-------------------------------------------------------+
```

### Objects Created on Verify (`ifc-demo-uc13-*`)
| Object Type | Name / Identifier | Purpose |
|---|---|---|
| **Application** | `ifc-demo-uc13-broker-portal` | DCR password-grant client for broker authentication |
| **STS Client** | `ifc-demo-uc13-resource-sts` | OAuth client used by downstream APIs to introspect bearer tokens |
| **SCIM User** | `ifc-demo-uc13-broker-elena` | Primary broker with enterprise department, employeeNumber, title |
| **SCIM User** | `ifc-demo-uc13-broker-marcus` | Secondary broker with agency attributes |
| **Webhook** | `ifc-demo-uc13-ops-webhook` | Notification webhook registered on Verify |

---

## 3. Quick Start & Execution

### Prerequisites
- Node.js >= 18
- Configured `.env` file with IBM Verify tenant credentials

### Run the Demo
```bash
# 1. Setup tenant objects (idempotent)
node demo/uc13-lifecycle/setup.js

# 2. Run the end-to-end automated test against the live tenant
node demo/uc13-lifecycle/run.js

# 3. Verify the recorded evidence
node demo/uc13-lifecycle/verify.js

# 4. (Optional) Start the interactive Operations Queue Dashboard
node demo/uc13-lifecycle/serve.js
# Open http://localhost:4040 in your browser

# 5. Clean up tenant objects
node demo/uc13-lifecycle/teardown.js
```

---

## 4. Test Scenarios Executed in `run.js`

1. **Scenario A: SCIM Broker Provisioning & Active Authentication**
   - Verifies Elena in Verify directory with enterprise attributes (`department: Commercial Lines`, `title: Commercial Lines Broker`, `employeeNumber: BRK-9821`, `externalId: IFC-BRK-9821`, `active: true`).
   - Broker signs in via OIDC password grant -> receives `access_token` and `id_token`.
   - Introspection (`/oauth2/introspect`) returns `active: true` with `sub` matching broker ID.
   - Event logged in Ops Queue: `PROVISION_USER (SUCCESS)`.

2. **Scenario B: SCIM In-Flight Profile & Department Update (Role/Transfer Sync)**
   - HR role transfer: SCIM `PATCH /v2.0/Users/{id}` updates `department` to `"Specialty Risks"` and `title` to `"Senior Commercial Risk Specialist"` (HTTP 204).
   - Verify directory immediately reflects updated enterprise attributes.
   - Event logged in Ops Queue: `TRANSFER_ROLE (SUCCESS)`.

3. **Scenario C: Immediate Revocation on Deactivation (Core Requirement)**
   - SCIM `PATCH active=false` executed (HTTP 204).
   - High-resolution timing measures latency from PATCH start to introspection refusal.
   - **Result:** Existing access token introspects `active: false` in **under 1 second** (`[LIVE]`).
   - Downstream API requests with the old token are immediately rejected with **HTTP 401 Unauthorized**.
   - Subsequent sign-in attempts fail with **HTTP 400 `CSIAQ0281E` ("The account is not active.")**.
   - Verify sessions terminated via `DELETE /v1.0/auth/sessions/{userId}` (HTTP 204).
   - Event logged in Ops Queue: `OFFBOARD_IMMEDIATE_REVOKE (ENFORCED)`.

4. **Scenario D: Broker Reactivation / Rehire Lifecycle**
   - SCIM `PATCH active=true` executed (HTTP 204).
   - Broker signs in successfully -> HTTP 200, receiving new active access token.
   - Introspection confirms `active: true`.
   - Event logged in Ops Queue: `REHIRE_REACTIVATE (SUCCESS)`.

5. **Scenario E: Error Paths & Operations Queue Handling**
   - Non-existent user PATCH -> returns **HTTP 404 `CSIAI0070E`** ("The user cannot be found").
   - Duplicate user create -> returns **HTTP 409 `CSIAI0047E`** ("User already exists").
   - Operations queue captures correlation IDs, error codes, and remediation metadata with status `FAILED_NEEDS_REVIEW`.

6. **Scenario F: Webhook Notification Architecture**
   - Verify SaaS Webhook (`ifc-demo-uc13-ops-webhook`, purpose: `notifications`) confirmed active.
   - Webhook ingest endpoint on Ops Queue stub tested with structured event payloads.

---

## 5. Live Evidence Summary (`[LIVE]`, `[HUMAN]`)

- `[LIVE]` **SCIM 2.0 User Provisioning:** Native `POST /v2.0/Users` with enterprise schema (`department`, `employeeNumber`, `title`, `externalId`).
- `[LIVE]` **Immediate Revocation:** SCIM `PATCH active=false` invalidates existing tokens in **0-1s** and blocks new sign-ins with `CSIAQ0281E`.
- `[LIVE]` **Downstream 401:** Resource servers checking Verify introspection reject revoked broker tokens immediately.
- `[LIVE]` **Reactivation:** SCIM `PATCH active=true` restores login capabilities instantly without resetting credentials.
- `[LIVE]` **Operations Queue & Correlation IDs:** Failed SCIM operations return standard error codes (`CSIAI0070E`, `CSIAI0047E`) with `x-correlation-id` headers for audit.
- `[LIVE]` **Webhook API:** `POST /config/v1.0/webhooks/` and `GET /config/v1.0/webhooks/` work natively for event notifications.
- `[HUMAN]` **Public Tunnel for Webhooks:** Real-time SaaS webhook delivery to a local development machine requires a public tunnel (e.g., ngrok or cloudflared).

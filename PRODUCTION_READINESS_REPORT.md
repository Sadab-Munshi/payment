# YOUPI PG V2 — Production Architecture, Security Audit & Deployment Runbook

> **Repository Audited:** `https://github.com/youpi-pg/YouPI-PG.git`  
> **Audit Date:** October 18, 2026  
> **Prepared By:** Helpful Agent on **Arena.ai** (Arena.ai's Agent Mode)

---

## Table of Contents

1. [Executive Summary & Production Readiness Verdict](#1-executive-summary--production-readiness-verdict)
2. [System Architecture & Codebase Inventory](#2-system-architecture--codebase-inventory)
3. [Core Payment & Verification Engine Deep-Dive](#3-core-payment--verification-engine-deep-dive)
4. [Code-Verified Findings: Bugs, Discrepancies & Security Risks](#4-code-verified-findings-bugs-discrepancies--security-risks)
5. [Ready-to-Apply Production Remediation Patches](#5-ready-to-apply-production-remediation-patches)
6. [Throughput & Capacity Planning (The Single-Slot Invariant)](#6-throughput--capacity-planning-the-single-slot-invariant)
7. [Step-by-Step Production Deployment Runbook](#7-step-by-step-production-deployment-runbook)
8. [Production Operations, Backups & Verification Scripts](#8-production-operations-backups--verification-scripts)
9. [Pre-Launch Production Checklist](#9-pre-launch-production-checklist)
10. [Acknowledgment & Attribution](#10-acknowledgment--attribution)

---

## 1. Executive Summary & Production Readiness Verdict

**YOUPI PG V2** is a self-hosted, zero-MDR, white-label UPI Payment Gateway built as a Node.js ES Module monorepo. Instead of routing funds through third-party aggregators (Razorpay, Cashfree, Paytm), payments settle directly into the merchant's bank account via standard NPCI `upi://pay` intents and dynamic QR codes. Payment confirmation is achieved via a **Tri-Channel Banking Observation Mesh** (Native Android SMS/Notification Gateway, Gmail OAuth2 API Poller, and optional local Chrome CDP scrapers) feeding a **6-stage deterministic verification pipeline**.

### Key Architectural Strengths
- **Exact Integer Monetary Arithmetic:** All currency parsing (`parseRupeesToPaise`) and matching operate strictly on `BigInt` paise (`₹1.00 = 100n`), eliminating IEEE-754 floating-point drift.
- **Deterministic Slot Serialization:** `QueueAllocationEngine` uses SQLite `BEGIN IMMEDIATE` write locks to serialize access to each receiving UPI account, preventing amount-collision ambiguity between concurrent shoppers.
- **Cryptographic At-Rest Protection:** `packages/common/src/secrets.js` encrypts sensitive fields (`merchants.webhook_secret`, `merchants.branding.gmailConfig.{clientSecret,refreshToken,apiKey}`, and `customers.otp_code`) using **AES-256-GCM** (`enc:v1:<iv>:<tag>:<ciphertext>`) keyed by `ENCRYPTION_MASTER_KEY`, and indexes bearer tokens (`customer_sessions.token`, `devices.device_token`) via keyed **HMAC-SHA256 blind indexes**.
- **SSRF-Hardened Outbound Webhooks:** `WebhookEngine` validates destination URLs against private, loopback, link-local (`169.254.169.254`), CGNAT, and IPv6-mapped private ranges (`validateOutboundWebhookUrl`), disables HTTP redirects (`redirect: 'manual'`), enforces a 10-second timeout, and signs payloads with `HMAC-SHA256` (`X-Gateway-Signature`).
- **Automated Fraud & Tamper Prevention:** Stage 5 (`FraudDetectionEngine`) detects fake UTR/SMS injection attempts and automatically bans the offending customer account when all 6 deterministic fraud conditions are met.

### Production Readiness Verdict: **CONDITIONAL GO (Requires P0 Fixes Before Live Traffic)**
While 31 of 32 regression test suites pass out-of-the-box on Node.js 22, **three P0 issues** and **five P1 security/operational gaps** were uncovered during code inspection and live test execution. Fixing the P0 items below is mandatory before exposing the gateway to real internet traffic.

| Severity | ID | Finding Summary | Location |
| :--- | :--- | :--- | :--- |
| **P0 (Blocker)** | **P0-1** | **Node.js Version Mismatch:** Docs & `package.json` state `node >= 20.0.0`, but `packages/db/src/database.js` uses `node:sqlite` (`DatabaseSync`), which **only exists in Node.js >= 22.5.0**. Running on Node 20 crashes immediately. | `package.json`, `packages/db/src/database.js` |
| **P0 (Blocker)** | **P0-2** | **Unauthenticated Payment Creation (`POST /api/v1/payments`):** Only checks `X-Merchant-Id` (default UUID is public in repo). Attackers can flood the UPI queue or trigger signed webhooks for arbitrary order IDs. | `apps/payment-api/src/routes/payments.routes.js` |
| **P0 (Blocker)** | **P0-3** | **Unauthenticated Customer PII Leak on COD Routes:** `GET /api/v1/payments/:id/cod`, `/api/v1/orders/:orderId/cod`, and `/api/v1/checkout/:id/cod` return customer name, phone, email, and home address without any auth token. | `apps/payment-api/src/auth-guard.js`, `checkout.routes.js` |
| **P1 (High)** | **P1-1** | **Plaintext Gmail OAuth Secrets Exposed Over HTTP API:** `GET /api/v1/admin/gmail/credentials` returns decrypted `clientSecret`, `refreshToken`, and `apiKey` in JSON response. | `apps/payment-api/src/routes/admin.routes.js:231` |
| **P1 (High)** | **P1-2** | **Header Spoofing via `merchant-admin` Proxy:** Unlike `checkout-portal`, `merchant-admin` (`:6001`) proxies `/api/*` to `:6100` without stripping `x-internal-render` and `x-internal-token`. | `apps/merchant-admin/src/server.js:116` |
| **P1 (High)** | **P1-3** | **Android APK Build & Reliability Gaps:** Duplicate `.java` and `.kt` sources; Java build stores `signing_key` in plain `SharedPreferences` (and plaintext in DB `signing_key_hash`) and lacks an offline retry queue (`WorkManager`) when mobile data drops. | `apps/android-observer-app/`, `scripts/build-android-apk.js` |
| **P1 (High)** | **P1-4** | **Hardcoded Developer Domain (`gauravtesting.online`):** Hardcoded in `youpi.js` SDK, `gmail-observer/src/server.js`, and `admin.routes.js`. | Multiple files |
| **P1 (High)** | **P1-5** | **Single-Slot Throughput Ceiling:** Each UPI receiving account processes 1 active checkout at a time (30s payment + 30s verify). High concurrency requires multiple receiving UPI accounts. | `packages/core/src/queue-engine.js` |
| **P2 (Medium)** | **P2-1** | **OTP Cooldown Not Reset After Verification + `better-sqlite3` Build Dependency:** Causes `whatsapp-berry-auth.test.js` subtests 7, 8, and 11 to fail if re-login happens within 30s or if native build scripts are skipped. | `apps/payment-api/src/routes/customer.routes.js:50` |
| **P2 (Medium)** | **P2-2** | **Documentation Drift (PostgreSQL vs. SQLite):** `docs/INSTALLATION.md`, `.env.example`, and `schema.sql` instruct operators to provision PostgreSQL (`DATABASE_URL`), which the runtime completely ignores in favor of `data/youpi_pg.sqlite`. | `docs/INSTALLATION.md`, `.env.example` |

---

## 2. System Architecture & Codebase Inventory

### 2.1 Shared Workspace Packages (`packages/*`)

| Package | Path | Responsibility |
| :--- | :--- | :--- |
| **`@youpi/common`** | `packages/common` | Status/method enums, `parseRupeesToPaise`/`formatPaiseToRupees` (`BigInt`), `generateUpiUri` (`upi://pay`), secret management & AES-256-GCM encryption (`secrets.js`), SSRF URL validator (`url-safety.js`), Cloudflare Tunnel route derivation (`runtime-config.js`), Android QR pairing payload validator (`pairing-qr.js`), and safe `cloudflared` process spawner (`tunnel-command.js`). |
| **`@youpi/db`** | `packages/db` | Synchronous SQLite engine (`node:sqlite` `DatabaseSync`) configured with `journal_mode = WAL`, `synchronous = NORMAL`, `busy_timeout = 5000`, `foreign_keys = ON`, and `BEGIN IMMEDIATE` transactions. Contains `runMigrations()` (`migrate.js`) and 10 repositories (`Merchant`, `ReceivingAccount`, `PaymentSession`, `Observation`, `WebhookDelivery`, `AuditLog`, `SupportTicket`, `Customer`, `Device`, `CustomerSession`). |
| **`@youpi/core`** | `packages/core` | Core business logic: `QueueAllocationEngine` (single-slot allocation & FIFO queue promotion), `PaymentVerificationPipeline` (6-stage bank alert verification), `AttributionEngine` (Level 1 / Level 2 dual-channel confidence & 5-second grace window), `FraudDetectionEngine` (6-condition auto-ban), `PaymentStateMachine`, and `WebhookEngine` (HMAC-SHA256 signing & exponential backoff). |
| **`@youpi/merchant-sdk`** | `packages/merchant-sdk` | Node.js client (`YoupiPaymentClient`) for merchants to create payment sessions, query payment status, and verify inbound `X-Gateway-Signature` webhooks using `crypto.timingSafeEqual`. |
| **`@youpi/observer-sdk`** | `packages/observer-sdk` | `PaymentObserverClient` (transmits observations to `/api/v1/pollers/events` with `Bearer <OBSERVER_API_TOKEN>`) and `BrowserLauncher` (Chrome DevTools Protocol WebSocket evaluator on ports `9222`/`9223`). |

### 2.2 Microservices & Applications (`apps/*`)

All Node.js services bind to `process.env.YOUPI_BIND_HOST || '127.0.0.1'` by default and are designed to be exposed selectively via a local Cloudflare Tunnel (`cloudflared`).

| Service | Default Port | Cloudflare Public Hostname (`prefix=pay`) | Supervised by Control Center? | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **`payment-api`** | `6100` | `https://pay-api.<domain>` | Yes | Core REST API, session state machine, 1s queue sync daemon, 1s aggressive observer sweep daemon, WhatsApp BerryProtocol OTP service, Android SMS ingestion, and Admin API. |
| **`checkout-portal`** | `7000` | `https://pay.<domain>` | Yes | Customer-facing checkout UI (`/checkout/:id`), QR code generator, UPI deep-link launcher, and universal frontend SDK (`/sdk/youpi.js`). Proxies `/api/*` to `:6100`. |
| **`merchant-admin`** | `6001` | `https://pay-admin.<domain>` | Yes | Single-page Merchant Admin & Operations Hub (`admin.html`). Proxies `/api/services/*` to `:8090` and `/api/*` to `:6100`. |
| **`gmail-observer`** | `6003` | `https://pay-gmail.<domain>` | Yes | Polls Gmail REST API (`gmail.readonly`) every 5s (and on `/api/sweep`) using stored OAuth2 refresh tokens; hosts `/oauth/url` and `/oauth/callback`. |
| **`sms-observer`** | `6002` | *Internal Only (Not Exposed)* | Yes | Direct SMS ingestion bridge (`/process-sms`) and legacy Google Messages Web CDP automator (disabled in production unless `ENABLE_LEGACY_CHROME_OBSERVERS=true`). |
| **`coin-wallet-store`** | `5000` | `https://pay-store.<domain>` *(Optional)* | Yes | Reference showcase store demonstrating `YoupiPaymentClient`, `youpi.js` modal integration, and replay-protected webhook handling. |
| **`control-center`** | `8090` | *Internal Only (Not Exposed)* | Supervisor Root | Process supervisor (`child_process.fork`) managing lifecycle, health checks, and ring-buffered SSE logs (`500` lines/service) for the 6 services above. |
| **`payment-help`** | `3000` | *Not in `deriveCloudflareRoutes()`* | **No** | Static customer support/dispute portal (`help.html`). Note: `/api/customer/tickets` returns `404 Feature not available`. |
| **`android-observer-app`** | Native APK | Connects to `https://pay-api.<domain>` | External Device | Android foreground daemon (`SmsReceiver` + `PaymentNotificationListenerService`) that forwards bank SMS and UPI notifications signed with per-device `HMAC-SHA256`. |

---

## 3. Core Payment & Verification Engine Deep-Dive

### 3.1 Session Lifecycle & Timers
1. **Session Creation (`POST /api/v1/payments`):**
   - When `paymentMode` is `DIGITAL` or `BOTH`, digital UPI sessions start in `INITIATED` status with `farFuture = now + 24h` so timers do not tick before the customer logs in.
   - Once the customer authenticates (via WhatsApp OTP or password) and calls `POST /api/v1/checkout/:id/bind-customer`, `QueueAllocationEngine.activateAuthenticatedSession()` acquires an immediate SQLite transaction lock:
     - If the target receiving account's slot is free (`is_slot_busy = 0`), the session becomes `PENDING` with a **30-second active payment timer** (`PAYMENT_WINDOW_SECONDS = 30`), and the account is marked `is_slot_busy = 1`.
     - If busy, the session enters `QUEUED` with a deterministic `queuePosition` and `estimatedWaitSeconds`.
2. **Customer Clicks "I Have Paid" (`POST /api/v1/checkout/:id/payment-done`):**
   - Transitions session from `PENDING` to `PROCESSING` and starts a **30-second verification window** (`VERIFICATION_WINDOW_SECONDS = 30`).
   - Triggers `aggressivePollerDaemon` in `payment-api`, which sends `POST /api/sweep` every **1 second** to `sms-observer:6002` and `gmail-observer:6003` while any session is in `PROCESSING`.
3. **Slot Release & Promotion Cascade:**
   - The `queueSyncDaemon` runs every **1 second** (`QueueAllocationEngine.syncTimers()`).
   - If a `PENDING` or `PROCESSING` session expires (`expires_at <= now`), or transitions to `SUCCESS`/`CANCELLED`/`FAILED`, the engine releases the account slot and immediately promotes the next `QUEUED` session in FIFO order (`queue_position ASC, created_at ASC`).
   - Switching a session to **Cash on Delivery (COD)** decouples it from the UPI slot (`clearReceivingAccount`), immediately promotes the next queued UPI customer, and assigns a parallel **5-minute (300s)** timer for COD address submission.

### 3.2 The 6-Stage Deterministic Verification Pipeline
Every observation from Android SMS (`/api/v1/observers/sms`), Android Notification (`/api/v1/pollers/android/events`), or Gmail (`/api/v1/pollers/events`) passes through `PaymentVerificationPipeline.process()`:

- **Stage 1 — Normalization & DoS Guard:** Strips HTML/invisible chars, normalizes whitespace, and enforces a **16 KB (`16,384` chars)** cap to prevent ReDoS on crafted emails/SMS.
- **Stage 2 — Sender Authenticity Filter:**
  - **SMS (`ANDROID_SMS`, `SMS_OBSERVER`):** Extracts sender header (e.g., `AD-HDFCBK-S`). Rejects plain 10–12 digit mobile numbers (`NUMERIC_MOBILE_SENDER_REJECTED`) unless the message parses as a payment and can be attributed to an active customer session (allowing Stage 5 to evaluate and ban the fraudster).
  - **Email (`GMAIL`):** Extracts angle-bracket email address (`<...>`). Rejects non-bank senders unless the domain ends with `.bank.in` or matches the built-in 26-bank allowlist (`hdfcbank.net`, `icicibank.com`, `sbi.co.in`, `axisbank.com`, `kotak.com`, etc.) or `CUSTOM_BANK_DOMAINS`.
- **Stage 3 — Strict Bank Credit Parser:**
  - Rejects failure/debit keywords (`failed`, `declined`, `debited from`, `sent to`, `otp is`, `request for`, etc.).
  - Requires at least one positive credit phrase (`credited`, `received`, `deposited`, `added to`, `paid you`, `credit alert`).
  - Requires currency marker (`Rs.`, `INR`, `₹`) + positive amount (`amountPaise > 0n`).
  - Requires a **strict 12-digit numeric UTR** (`/\b(\d{12})\b/`).
- **Stage 4 — Transaction Verification & Replay Guard:**
  - Finds an active (`PENDING`/`PROCESSING`) or recently expired session for the receiving account matching `amountPaise`.
  - Rejects observations older than `session.createdAt - 1000ms` (`TIMESTAMP_BEFORE_SESSION`).
  - Checks both `observation_fingerprint` and `bank_reference_number` (12-digit UTR) across historical records to block replay attacks (`DUPLICATE_UTR_REPLAY`).
- **Stage 5 — Fraud Detection & Auto-Ban Engine:**
  - Automatically bans the customer (`customers.status = 'BANNED'`, `ban_reason = 'FRAUDULENT_PAYMENT_INJECTION'`), revokes all active customer sessions, marks the payment `FAILED`, and releases the UPI queue slot if **all 6 conditions** hold: (1) Developer Test Mode is OFF, (2) customer is authenticated/bound, (3) active checkout session exists, (4) observation is attributable to that session, (5) verification failed with a tamper reason (`NUMERIC_MOBILE_SENDER_REJECTED`, `FAKE_OR_INVALID_UTR`, `DUPLICATE_UTR_REPLAY`, `AMOUNT_MISMATCH`, `DEBIT_OR_NON_CREDIT_MESSAGE`, `UNTRUSTED_EMAIL_DOMAIN`), and (6) no genuineverified observation already settled the session.
- **Stage 6 — Attribution & Dual-Channel Confidence Upgrade (`AttributionEngine`):**
  - **Level 1 (`SINGLE_CHANNEL`, 70% confidence):** First verified signal (SMS *or* Gmail). Marks session `SUCCESS` immediately so the customer isn't delayed, records a **5-second grace window** (`PAYMENT_GRACE_PERIOD_MS = 5000`), and holds the outbound `payment.succeeded` webhook for up to 5 seconds to see if the second channel arrives.
  - **Level 2 (`DUAL_CHANNEL_VERIFIED`, 100% confidence):** When the corroborating channel (e.g., Gmail after SMS) arrives with the same 12-digit UTR, upgrades `verification_level = 2` (`VERIFIED_SMS_AND_GMAIL`) and dispatches the webhook immediately.
  - **Late Arrivals:** If a valid observation arrives `< 30 minutes` after a session expired, it creates an automated `SupportTicket` (`LATE_VERIFICATION_AFTER_EXPIRY`) for merchant review without double-crediting.

### 3.3 Dynamic UPI Deep Links, 30-App Intent Registry & VPA Modes
- **Strict Parameter Ordering (`pa`, `pn`, `am`, `tn`):** `buildUpiUri()` and `buildUpiIntentUri()` in `@youpi/common` generate NPCI-compliant URIs with strict parameter ordering (`pa=<vpa>&pn=<name>&am=<rupees>&tn=<orderId>`) and omit `tr`/`cu` where personal VPAs would otherwise be rejected by PSP apps.
- **Merchant-Enabled vs. Non-Merchant VPA Mode (`is_merchant_enabled`):**
  - Each `payment_receiving_accounts` row carries an `is_merchant_enabled` flag and is snapshotted into `session.metadata.receivingAccountSnapshot` at session creation (preserving historical immutability even if the merchant switches active VPAs mid-checkout).
  - **Merchant VPA (`is_merchant_enabled = 1`):** Renders 1-tap Android Intent buttons (`intent://pay?...#Intent;scheme=upi;package=<pkg>;end`) across 30 registered Indian UPI apps (Google Pay, PhonePe, Paytm, BHIM, Cred, Amazon Pay, Navi, Super.money, etc.) plus a dynamic QR code.
  - **Personal / Non-Merchant VPA (`is_merchant_enabled = 0`):** Renders QR-first checkout with a sanitized PNG download filename (`<vpa>_<amount>_<date>_<time>.png`) for gallery-import scan-and-pay in UPI apps (bypassing NPCI's ₹2,000 collect/intent cap on P2P VPAs).
- **Atomic Single-Active VPA Enforcement:** A partial unique index (`idx_single_active_vpa_per_merchant ON payment_receiving_accounts (merchant_id) WHERE is_active = 1`) and `ReceivingAccountRepository.activateAccount()` guarantee that activating a new VPA atomically deactivates the previous active VPA.

---

## 4. Code-Verified Findings: Bugs, Discrepancies & Security Risks

### P0-1: Node.js Runtime Version Mismatch (`node:sqlite` Requires Node >= 22.5.0)
- **Evidence:**
  - `package.json` line 64: `"engines": { "node": ">=20.0.0" }`
  - `docs/INSTALLATION.md` line 15: `Node.js >= 20.0.0 (Built with native ES Modules)`
  - `packages/db/src/database.js` line 1: `import { DatabaseSync } from 'node:sqlite';`
- **Impact:** Node's built-in `node:sqlite` module does **not** exist in Node.js 20.x. Running `npm run init:db` or `npm start` on Node.js v20.20.2 immediately crashes with:
  ```text
  Error [ERR_UNKNOWN_BUILTIN_MODULE]: No such built-in module: node:sqlite
  ```
- **Required Fix:** Provision **Node.js v22.13.0+ LTS** (or Node.js 24 LTS) in production, and update `package.json` `"engines"` to `">=22.5.0"`. Additionally, ensure `python3`, `make`, and `g++` are installed on the host so `npm install` (without `--ignore-scripts`) compiles `better-sqlite3` for `berryprotocol` (WhatsApp OTP).

### P0-2: Unauthenticated Payment Session Creation (`POST /api/v1/payments`)
- **Evidence:**
  - `apps/payment-api/src/auth-guard.js` intentionally leaves `POST /api/v1/payments` public because `apps/checkout-portal/src/sdk/youpi.js` allows browser clients to create payment sessions directly using only `X-Merchant-Id: 00000000-0000-0000-0000-000000000001`.
- **Impact:**
  1. Any anonymous party on the internet can call `POST https://pay-api.<domain>/api/v1/payments` with the default merchant UUID.
  2. When a session is created in `COUNTER`, `COD`, or `FREE` mode, or when a session expires, `WebhookEngine` dispatches signed webhooks (`X-Gateway-Signature`) to the merchant's `webhook_url` using the payload (`orderId`, `amount`, `metadata`) supplied by the unauthenticated caller! If a merchant's webhook handler trusts `event.orderId` without cross-checking an internal order table (or if they rely solely on webhook signature validity), an attacker can forge order creation/cancellation events.
- **Required Fix:**
  - Require `Authorization: Bearer <ADMIN_API_TOKEN>` (or a dedicated per-merchant API secret / HMAC signature) on `POST /api/v1/payments` in production, and require merchants to create payment sessions server-to-server via `@youpi/merchant-sdk` (`YoupiPaymentClient.createPayment()`) rather than directly from browser JavaScript.
  - If browser-initiated session creation is needed for static sites, validate `Origin` against a strict per-merchant domain allowlist and tag browser-created sessions as `untrustedOrigin: true` so webhooks include that flag.

### P0-3: Unauthenticated Customer PII Disclosure on COD Endpoints
- **Evidence:**
  - In `apps/payment-api/src/routes/checkout.routes.js` (lines 702–746), three endpoints return full Cash-on-Delivery customer details (`name`, `email`, `mobileNumber`, `addressLine1`, `addressLine2`, `area`, `city`, `state`, `pincode`, `country`, `notes`):
    - `GET /api/v1/checkout/:id/cod`
    - `GET /api/v1/payments/:id/cod`
    - `GET /api/v1/orders/:orderId/cod`
  - None of these three routes are protected in `apps/payment-api/src/auth-guard.js`, nor do they call `checkSessionDeviceAccess()`.
- **Impact:** Anyone who knows or guesses a `paymentId` or `orderId` (such as sequential or timestamp-based order IDs like `ORD-1001`) can query `GET /api/v1/orders/:orderId/cod` without authentication and harvest customer names, phone numbers, emails, and physical delivery addresses.
- **Required Fix:** Add `/api/v1/payments/:id/cod`, `/api/v1/orders/:orderId/cod`, and `/api/v1/checkout/:id/cod` to `isAdminProtectedPath()` in `apps/payment-api/src/auth-guard.js` so they require `Authorization: Bearer <ADMIN_API_TOKEN>`.

### P1-1: Plaintext Gmail OAuth Credentials Returned by Admin API
- **Evidence:**
  - `apps/payment-api/src/routes/admin.routes.js` lines 231–263 (`GET /api/v1/admin/gmail/credentials`) decrypts `gmailConfig` from the database and returns `clientSecret`, `refreshToken`, and `apiKey` in plaintext JSON so `gmail-observer` (`:6003`) can fetch them over HTTP.
  - Meanwhile, `GET /api/v1/admin/merchant-settings` properly redacts those fields via `redactMerchantForClient()`.
- **Impact:** Any compromise of `OBSERVER_API_TOKEN` or XSS in the Merchant Admin dashboard allows full extraction of the merchant's Google OAuth `clientSecret` and offline `refreshToken` (which grants `gmail.readonly` access to the merchant's entire Gmail inbox).
- **Required Fix:** Restrict `GET /api/v1/admin/gmail/credentials` to loopback requests (`req.socket.remoteAddress === '127.0.0.1'` or `'::1'`) authenticated exclusively with `INTERNAL_SERVICE_TOKEN`, and return only `{ connectedEmail, status, hasRefreshToken: true, clientId }` to browser Admin tokens.

### P1-2: Missing Header Sanitization in `merchant-admin` Reverse Proxy
- **Evidence:**
  - `apps/checkout-portal/src/server.js` (line 29) and `apps/coin-wallet-store/src/server.js` (line 42) strip `x-internal-render` and `x-internal-token` before proxying `/api/*` to `payment-api:6100`.
  - `apps/merchant-admin/src/server.js` (lines 116–128) forwards `headers: { ...req.headers, host: ... }` directly to `127.0.0.1:6100` without stripping `x-internal-render` or `x-internal-token`.
- **Impact:** While `payment-api` now checks `hasHeaderSecret(req, 'x-internal-token', getInternalRenderToken())`, defence-in-depth requires stripping internal headers at every reverse proxy boundary, and `merchant-admin` (`https://pay-admin.<domain>`) should also be protected at the edge with Cloudflare Zero Trust Access.

### P1-3: Android App Source Duplication, Plaintext Signing Keys & Missing Offline Queue
- **Evidence:**
  - `apps/android-observer-app/app/src/main/java/com/youpi/observer/` contains **both** `.java` and `.kt` implementations of `ApiClient`, `MainActivity`, `SmsReceiver`, `PaymentNotificationListenerService`, `ForegroundService`, and `BootReceiver`.
  - `scripts/build-android-apk.js` compiles only the `.java` files using hardcoded Windows paths (`C:\Program Files\Microsoft\jdk-17.0.20.101-hotspot\bin\javac.exe` and `C:\Users\gaura\scoop\apps\android-clt\...`) and signs the release APK with a hardcoded password (`youpipg123`).
  - `ApiClient.java` stores `signing_key` in standard unencrypted `SharedPreferences` (`youpi_gateway_prefs`), whereas `ApiClient.kt` used `EncryptedSharedPreferences`.
  - On the server (`apps/payment-api/src/routes/pollers.routes.js` line 154), the per-device `signingKey` is stored in plaintext inside the `signing_key_hash` column of `android_devices` (not encrypted with `encryptSecret()`).
  - In `SmsReceiver.java` and `PaymentNotificationListenerService.java`, observations are sent via a one-shot `new Thread(() -> client.sendSms(...)).start()` with a 10s HTTP timeout and **no persistent retry queue**.
- **Impact:** If the merchant's Android phone experiences a 15-second cellular handover or temporary Wi-Fi drop when a bank SMS arrives, `sendSms()` returns `false` and the SMS is permanently dropped, causing the customer's checkout to time out unless Gmail Observer catches the email.
- **Required Fix:**
  1. Remove duplicate `.kt` or `.java` files so Gradle (`./gradlew assembleRelease`) builds cleanly.
  2. Sign production APKs with a private keystore kept outside the git repository.
  3. Encrypt `android_devices.signing_key_hash` at rest using `encryptSecret()` in `@youpi/common`.
  4. Add a local SQLite/SharedPreferences retry queue or Android `WorkManager` backoff task in `ApiClient` when `postJson()` fails due to network unreachability.

### P1-4: Hardcoded Fallback Domain (`gauravtesting.online`)
- **Evidence:**
  - `apps/checkout-portal/src/sdk/youpi.js` line 40: `if ((origin.includes('localhost') || origin.includes('127.0.0.1')) && target.includes('gauravtesting.online'))`
  - `apps/gmail-observer/src/server.js` lines 77 & 130: `!this.poller.apiBaseUrl.includes('gauravtesting.online')`
  - `apps/payment-api/src/routes/admin.routes.js` lines 555 & 559: `raw.includes('gauravtesting.online')`
- **Impact:** Leftover developer domain references can cause unexpected URL rewrites if a merchant tests with or migrates from a template database.

### P2-1: WhatsApp OTP Cooldown Bug & Native `better-sqlite3` Dependency
- **Evidence:**
  - Running `node scripts/test-all.js` passes 31 of 32 suites, but fails in `apps/payment-api/src/__tests__/whatsapp-berry-auth.test.js` on subtests 7, 8, and 11:
    1. In `apps/payment-api/src/routes/customer.routes.js`, `isOtpThrottled(cleanMobile)` records a 30-second cooldown in `otpRequestLog`, and `POST /api/v1/customer/verify-otp` does **not** clear `otpRequestLog.delete(cleanMobile)` upon successful verification. Consequently, when a user signs up (subtest 5) and requests a login OTP within 30 seconds (subtest 7), the server returns `429 Too Many Requests`.
    2. `berryprotocol` depends on `better-sqlite3` (`^11.3.0`), a native C++ addon. If `npm install` is run with `--ignore-scripts` or without C++ build tools on a newer Node ABI, `berryprotocol` fails to load `better_sqlite3.node` and `POST /api/v1/admin/whatsapp/pairing-code` returns `500`.

### P2-2: Documentation vs. Runtime Database Discrepancy
- **Evidence:**
  - `docs/INSTALLATION.md`, `.env.example`, and `packages/db/src/schema.sql` instruct operators to install PostgreSQL 15+ and configure `DATABASE_URL=postgresql://...`.
  - In reality, `packages/db/src/database.js` exclusively uses Node's built-in `node:sqlite` (`DatabaseSync`) storing data in `SQLITE_DB_PATH` (default `data/youpi_pg.sqlite`).
- **Operational Impact:** Operators do **not** need PostgreSQL. However, because `node:sqlite` is an embedded single-file database using WAL mode, **all gateway microservices must run on the same physical host / shared local filesystem** (not distributed across separate containers without a shared local POSIX volume).

---

## 5. Ready-to-Apply Production Remediation Patches

Before exposing the gateway to public internet traffic, apply the following targeted fixes:

### Patch 1: Enforce Node.js `>=22.5.0` (`package.json`)
```diff
--- a/package.json
+++ b/package.json
@@ -61,3 +61,3 @@
   "engines": {
-    "node": ">=20.0.0"
+    "node": ">=22.5.0"
   },
```

### Patch 2: Protect COD Customer PII Endpoints (`apps/payment-api/src/auth-guard.js`)
```diff
--- a/apps/payment-api/src/auth-guard.js
+++ b/apps/payment-api/src/auth-guard.js
@@ -18,6 +18,9 @@ export function isAdminProtectedPath(pathname, method) {
   if (pathname.startsWith('/api/v1/admin/')) return true;
   if (pathname === '/api/v1/merchants/config') return true;
   if (pathname === '/api/v1/payments' && method === 'GET') return true;
+  if (/^\/api\/v1\/payments\/[^/]+\/cod$/.test(pathname) && method === 'GET') return true;
+  if (/^\/api\/v1\/orders\/[^/]+\/cod$/.test(pathname) && method === 'GET') return true;
+  if (/^\/api\/v1\/checkout\/[^/]+\/cod$/.test(pathname) && method === 'GET') return true;
   if (pathname === '/api/v1/pollers/status' && method === 'GET') return true;
   if (pathname === '/api/v1/pollers/qr-command' && method === 'GET') return true;
   return false;
```

### Patch 3: Strip Internal Headers in `merchant-admin` Proxy (`apps/merchant-admin/src/server.js`)
```diff
--- a/apps/merchant-admin/src/server.js
+++ b/apps/merchant-admin/src/server.js
@@ -115,11 +115,16 @@ export class AdminServer {
       // Proxy all /api/* requests to Payment API Server (port 6100)
       if (pathname.startsWith('/api/')) {
         const apiUrl = new URL(this.apiBaseUrl);
+        const forwardHeaders = { ...req.headers, host: apiUrl.host };
+        for (const k of Object.keys(forwardHeaders)) {
+          const lower = k.toLowerCase();
+          if (lower === 'x-internal-render' || lower === 'x-internal-token') delete forwardHeaders[k];
+        }
         const proxyReq = http.request({
           hostname: apiUrl.hostname,
           port: apiUrl.port || 6100,
           path: url.pathname + url.search,
           method: req.method,
-          headers: { ...req.headers, host: apiUrl.host }
+          headers: forwardHeaders
         }, proxyRes => {
```

### Patch 4: Clear OTP Cooldown After Successful Verification (`apps/payment-api/src/routes/customer.routes.js`)
```diff
--- a/apps/payment-api/src/routes/customer.routes.js
+++ b/apps/payment-api/src/routes/customer.routes.js
@@ -255,6 +255,7 @@ export function registerCustomerRoutes(server, ctx) {
       pendingOtpChallenges.delete(cleanMobile);
     }
+    otpRequestLog.delete(cleanMobile);
 
     // Server-side Ban Enforcement (Section 3)
```

---

## 6. Throughput & Capacity Planning (The Single-Slot Invariant)

Understanding **Invariant #3 (Strict Per-Account Slot Serialization)** is critical before running marketing campaigns or high-traffic sales:

1. **Why Serialization Exists:** Indian bank credit SMS and email alerts typically state *"Rs. 499.00 credited to A/c XX4321 via UPI Ref 612345678901"* without echoing a merchant `orderId`. If two customers simultaneously pay `₹499.00` to the exact same UPI ID (`merchant@okaxis`), the gateway cannot tell which customer paid first from the amount alone.
2. **How YOUPI PG Solves It:** `QueueAllocationEngine` locks the receiving account (`is_slot_busy = 1`) for **one authenticated customer at a time**:
   - **Active Payment Window:** `30 seconds` (`PAYMENT_WINDOW_SECONDS = 30`)
   - **Verification Window (after clicking "I Have Paid"):** `30 seconds` (`VERIFICATION_WINDOW_SECONDS = 30`)
   - **Average Slot Hold Time:** ~15–25 seconds for a completing user, or 30 seconds if abandoned.
3. **Capacity Math per UPI Account:**
   - **1 Receiving UPI Account:** ~2 to 4 checkouts per minute (~120–240 checkouts/hour). Concurrent shoppers beyond the active user are placed in the live FIFO queue (`QUEUED`) with real-time wait countdowns.
   - **Scaling Horizontal Checkout Concurrency:** To support $N$ simultaneous active checkouts without queuing, insert $N$ distinct `payment_receiving_accounts` rows in SQLite (each linked to a distinct bank account / VPA observed by its paired Android device or Gmail inbox). `QueueAllocationEngine` automatically load-balances across all active `payment_receiving_accounts` for the merchant.

---

## 7. Step-by-Step Production Deployment Runbook

### Step 1: Provision Host & System Prerequisites
Deploy on an Ubuntu 22.04 / 24.04 LTS VPS or dedicated Linux server (minimum 2 vCPU, 4 GB RAM, SSD storage).

```bash
# 1. Install build tools (required for better-sqlite3 native addon used by berryprotocol)
sudo apt-get update && sudo apt-get install -y curl git build-essential python3 sqlite3

# 2. Install Node.js 22 LTS (REQUIRED for built-in node:sqlite module)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs

# Verify Node >= 22.5.0
node -v   # Must output v22.x.x (e.g. v22.14.0)

# 3. Install Cloudflare Tunnel daemon (cloudflared)
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
sudo apt-get update && sudo apt-get install -y cloudflared
```

### Step 2: Clone Repository & Install Dependencies
```bash
sudo mkdir -p /opt/youpi-pg
sudo chown -R $USER:$USER /opt/youpi-pg
git clone https://github.com/youpi-pg/YouPI-PG.git /opt/youpi-pg
cd /opt/youpi-pg

# Install dependencies and compile native addons (do NOT pass --ignore-scripts)
npm install
```

### Step 3: Generate Cryptographic Secrets & Production `.env`
While `packages/common/src/secrets.js` can auto-generate secrets in `data/.secrets/`, production deployments should explicitly define and back up all 7 cryptographic secrets in `/opt/youpi-pg/.env` with `chmod 600 .env`:

```bash
cat <<EOF > /opt/youpi-pg/.env
# ============================================================================
# YOUPI PG V2 — AUTHORITATIVE PRODUCTION CONFIGURATION
# ============================================================================
NODE_ENV=production
YOUPI_MODE=production
YOUPI_BIND_HOST=127.0.0.1

# Authoritative Cloudflare Domain & Prefix
CLOUDFLARE_DOMAIN=yourdomain.com
DEPLOYMENT_PREFIX=pay

# SQLite WAL Database Path (Single-Host Local SSD Only)
SQLITE_DB_PATH=/opt/youpi-pg/data/youpi_pg.sqlite

# Service Ports (Loopback Only)
PAYMENT_API_PORT=6100
CHECKOUT_PORTAL_PORT=7000
MERCHANT_ADMIN_PORT=6001
GMAIL_OBSERVER_PORT=6003
SMS_OBSERVER_PORT=6002
COIN_STORE_PORT=5000
HELP_PORTAL_PORT=3000

# Internal URLs
PAYMENT_API_INTERNAL_URL=http://127.0.0.1:6100
BASE_PAYMENT_API_URL=http://127.0.0.1:6100

# Public URLs (Must match deriveCloudflareRoutes for CLOUDFLARE_DOMAIN & DEPLOYMENT_PREFIX)
CHECKOUT_PUBLIC_URL=https://pay.yourdomain.com
PAYMENT_API_PUBLIC_URL=https://pay-api.yourdomain.com
ADMIN_PUBLIC_URL=https://pay-admin.yourdomain.com
GMAIL_PUBLIC_URL=https://pay-gmail.yourdomain.com
COIN_STORE_PUBLIC_URL=https://pay-store.yourdomain.com

# Cryptographic Secrets (Generated via openssl rand -hex 32)
ENCRYPTION_MASTER_KEY=$(openssl rand -hex 32)
ADMIN_API_TOKEN=$(openssl rand -hex 32)
OBSERVER_API_TOKEN=$(openssl rand -hex 32)
INTERNAL_SERVICE_TOKEN=$(openssl rand -hex 32)
COIN_STORE_WEBHOOK_SECRET=$(openssl rand -hex 32)
ANDROID_ENROLLMENT_SECRET=$(openssl rand -hex 32)
OAUTH_STATE_SECRET=$(openssl rand -hex 32)

# Production Security Enforcements (NEVER enable dev tools or private webhooks in prod)
YOUPI_ALLOW_DEV_TOOLS=false
YOUPI_EXPOSE_DEV_OTP=false
YOUPI_ALLOW_PRIVATE_WEBHOOKS=false
ENABLE_LEGACY_CHROME_OBSERVERS=false

# Polling & Grace Window Tuning
GMAIL_POLL_INTERVAL_MS=5000
PAYMENT_GRACE_PERIOD_MS=5000
EOF

chmod 600 /opt/youpi-pg/.env
```

> **CRITICAL WARNING:** Back up `ENCRYPTION_MASTER_KEY` and `INTERNAL_SERVICE_TOKEN` in your password manager / vault immediately.
> - Losing `ENCRYPTION_MASTER_KEY` renders all encrypted database columns (`webhook_secret`, `gmailConfig.refreshToken`, `otp_code`) permanently undecryptable.
> - Changing `INTERNAL_SERVICE_TOKEN` invalidates all HMAC blind indexes (`customer_sessions.token`, `devices.device_token`).

### Step 4: Initialize & Reset Production SQLite Database
```bash
cd /opt/youpi-pg
npm run init:db

# Optional: Purge any seed/test transactions while keeping default merchant & receiving account
node scripts/reset-production-db.js
chmod 600 /opt/youpi-pg/data/youpi_pg.sqlite*
```

### Step 5: Configure Cloudflare Zero Trust Tunnel
In the [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/) (**Networks -> Tunnels**), create a Cloudflared tunnel and configure the **Public Hostname** routes to match `deriveCloudflareRoutes()` in `packages/common/src/runtime-config.js`:

| Subdomain (`prefix=pay`) | Domain | Type | Target URL | Production Access Policy |
| :--- | :--- | :--- | :--- | :--- |
| **`pay`** | `yourdomain.com` | `HTTP` | `http://localhost:7000` | Public (Customer Checkout Portal) |
| **`pay-api`** | `yourdomain.com` | `HTTP` | `http://localhost:6100` | Public (Payment API & Android Observer Target) |
| **`pay-admin`** | `yourdomain.com` | `HTTP` | `http://localhost:6001` | **Protect with Cloudflare Access (Email OTP / SSO)** |
| **`pay-gmail`** | `yourdomain.com` | `HTTP` | `http://localhost:6003` | Public `/oauth/callback` (Restrict `/stop` & `/process-email` via WAF) |
| **`pay-store`** *(Optional)* | `yourdomain.com` | `HTTP` | `http://localhost:5000` | Optional Demo Store (Omit in live merchant deployments) |

> **Never Expose:** Port `8090` (`control-center`) and Port `6002` (`sms-observer`) must **never** be mapped to public Cloudflare Tunnel hostnames.

Install the Cloudflare tunnel as a system service on the server:
```bash
sudo cloudflared service install <YOUR_CLOUDFLARE_TUNNEL_TOKEN>
sudo systemctl enable --now cloudflared
```
*(Alternatively, set `CLOUDFLARE_TUNNEL_COMMAND="cloudflared tunnel run --token <TOKEN>"` in `.env` or via the Merchant Admin panel so `scripts/start.js` manages the tunnel child process directly; `packages/common/src/tunnel-command.js` strictly validates the binary and arguments against shell injection.)*

### Step 6: Configure Observation Channels & WhatsApp OTP

#### Channel 1: Native Android SMS & Notification Observer (Primary Fast Path — ~1–2s latency)
1. Download or build the Android APK (`apps/android-observer-app/youpi-sms-gateway.apk`) and install it on a dedicated Android phone containing the bank SIM card registered to your receiving UPI account.
2. On the Android phone, grant:
   - **SMS Receive & Read Permissions**
   - **Notification Listener Access** (`Settings -> Notification Access -> YOUPI Payment Observer Service`)
   - **Unrestricted Battery Optimization** (`Ignore Battery Optimizations = ON`)
3. Open the Merchant Admin Dashboard (`https://pay-admin.yourdomain.com`), log in with your `ADMIN_API_TOKEN`, navigate to **Android SMS Gateway**, and scan the **Pairing QR Code** from the Android app (`📷 SCAN PAIRING QR`).
   - The QR encodes `{ version: "v1", type: "YOUPI_SMS_GATEWAY_PAIR", serverUrl: "https://pay-api.yourdomain.com", token: "<ANDROID_ENROLLMENT_SECRET>", expiresAt: ... }`.
   - Upon pairing, the phone receives a unique 32-byte `signingKey` and begins sending 30-second heartbeats (`/api/v1/pollers/android/heartbeat`) and HMAC-signed bank SMS observations (`/api/v1/observers/sms`).

#### Channel 2: Gmail API OAuth2 Observer (Corroborating Dual-Channel — ~3–5s latency)
1. In [Google Cloud Console](https://console.cloud.google.com/):
   - Enable the **Gmail API**.
   - Configure the OAuth Consent Screen. **Important Production Tip:** Set Publishing Status to **"In production"** (not "Testing"), otherwise Google automatically revokes offline `refresh_token` grants every **7 days**!
   - Create an **OAuth 2.0 Client ID (Web Application)** with the exact Authorized Redirect URI:
     ```text
     https://pay-gmail.yourdomain.com/oauth/callback
     ```
2. In Merchant Admin (`https://pay-admin.yourdomain.com`), enter your Google `Client ID` and `Client Secret`, click **Connect Google Account**, and complete the consent flow with the email account that receives your bank's instant credit alerts.
3. Verify that `gmail-observer` (`http://127.0.0.1:6003/health`) reports `"isRunning": true`.

#### Customer Auth: WhatsApp BerryProtocol OTP Engine
1. In Merchant Admin -> **WhatsApp OTP Engine**, click **Reconnect / Generate QR** (or enter phone number for an 8-digit pairing code).
2. Link your business WhatsApp account from your phone (**Linked Devices -> Link a Device**).
3. Session credentials persist on disk under `/opt/youpi-pg/data/whatsapp-berry-session`.

### Step 7: Create Production `systemd` Service
Create `/etc/systemd/system/youpi-pg.service` to supervise the gateway stack on boot:

```ini
[Unit]
Description=YOUPI PG V2 — Self-Hosted UPI Payment Gateway
After=network-online.target cloudflared.service
Wants=network-online.target

[Service]
Type=simple
User=youpi
Group=youpi
WorkingDirectory=/opt/youpi-pg
EnvironmentFile=/opt/youpi-pg/.env
Environment=NODE_ENV=production
Environment=YOUPI_MODE=production
ExecStart=/usr/bin/node /opt/youpi-pg/scripts/start.js
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=youpi-pg

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now youpi-pg
sudo journalctl -u youpi-pg -f
```

---

## 8. Production Operations, Backups & Verification Scripts

### 8.1 Built-In Verification & Packaging Scripts (`scripts/*`)
The repository includes specialized verification and operational utilities in `scripts/`:
- **`node scripts/test-all.js` (`npm test`):** Runs all 32 unit, integration, and chaos concurrency test suites.
- **`node scripts/production-infrastructure.test.js`:** Verifies all 49 Part L production acceptance criteria (Cloudflare route derivation, authoritative production mode, QR pairing payload validation, raw SMS/Gmail transport contracts, and legacy Chrome observer suppression).
- **`node scripts/verify-53-point-auth-matrix.js`:** Runs the 53-point customer identity, PBKDF2 password hashing, email/mobile normalization, session restoration, and payment regression matrix.
- **`node scripts/verify-support-and-upi-extensions.js`:** Verifies the 24 requirements for merchant support contacts, privacy policy URLs, non-destructive settings updates, 3-dot checkout support menu, and dynamic case info generation.
- **`node scripts/full-regression-e2e.js`:** End-to-end verification of multi-VPA management, atomic single-active VPA switching, session VPA snapshot immutability, 30-provider Android intent generation, and attribution.
- **`node scripts/reset-production-db.js`:** Creates a timestamped backup in `data/backups/`, transactionally purges test customers/sessions/observations/webhooks/tickets while preserving the merchant and receiving account configuration, and runs `VACUUM`.
- **`node scripts/sync-package.cjs`:** Sanitizes and exports a clean distributable copy of the repository (stripping `.env`, `*.sqlite`, `.berry-sessions`, `node_modules`, and `.git`).

### 8.2 Health Monitoring Endpoints
Configure uptime monitoring (e.g., Uptime Kuma, Prometheus blackbox exporter, or Cloudflare Health Checks) against the local services:
- **Payment API & UPI Server Status:** `GET http://127.0.0.1:6100/api/v1/health/upi-server`
  - Returns `status: "GREEN" | "YELLOW" | "RED"` based on live Android heartbeat age (`<= 120s`) and Gmail OAuth connectivity.
  - Note: If both Android and Gmail channels go offline (`RED`), `POST /api/v1/checkout/:id/payment-done` automatically blocks new UPI verifications with `503 UPI_SERVER_DOWN` to protect customers from un-verifiable payments.
- **Process Supervisor Status:** `GET http://127.0.0.1:8090/api/services` (requires `Authorization: Bearer <ADMIN_API_TOKEN>`)
- **Individual Microservice Health:**
  - `http://127.0.0.1:6100/health` (`payment-api`)
  - `http://127.0.0.1:7000/health` (`checkout-portal`)
  - `http://127.0.0.1:6001/health` (`merchant-admin`)
  - `http://127.0.0.1:6003/health` (`gmail-observer`)
  - `http://127.0.0.1:6002/health` (`sms-observer`)

### 8.3 Safe Online SQLite WAL Backups
Because SQLite runs in `WAL` mode (`youpi_pg.sqlite`, `youpi_pg.sqlite-wal`, `youpi_pg.sqlite-shm`), **never** use plain `cp` on `youpi_pg.sqlite` while the server is running (it can copy an inconsistent state missing pages in `-wal`). Use SQLite's online backup command via cron:

```bash
# /etc/cron.hourly/youpi-pg-backup
#!/usr/bin/env bash
set -euo pipefail
BACKUP_DIR="/opt/youpi-pg/data/backups"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
sqlite3 /opt/youpi-pg/data/youpi_pg.sqlite ".timeout 5000" ".backup '${BACKUP_DIR}/youpi_pg_${TIMESTAMP}.sqlite'"
gzip -f "${BACKUP_DIR}/youpi_pg_${TIMESTAMP}.sqlite"
# Retain last 14 days of hourly backups
find "$BACKUP_DIR" -name "youpi_pg_*.sqlite.gz" -mtime +14 -delete
```

### 8.4 Stuck Slot or Queue Recovery
If a receiving account slot ever appears stuck, `QueueAllocationEngine.syncTimers()` automatically clears any expired session within 1 second. Operators can also inspect or force-clear slots via:
- `GET /api/v1/admin/Diagnostic/queue-state` (with `Bearer <ADMIN_API_TOKEN>`)
- Or in SQLite:
  ```sql
  UPDATE payment_receiving_accounts SET is_slot_busy = 0, current_active_session_id = NULL;
  ```

---

## 9. Pre-Launch Production Checklist

- [ ] **Node.js >= 22.13.0 LTS** installed and verified (`node -e "import('node:sqlite').then(() => console.log('SQLite OK'))"`).
- [ ] **All 32 test suites verified** (`node scripts/test-all.js`).
- [ ] **P0-2 & P0-3 Patched:** `POST /api/v1/payments` and `GET /api/v1/{payments,orders,checkout}/:id/cod` protected by authentication in `apps/payment-api/src/auth-guard.js`.
- [ ] **P1-1 & P1-2 Patched:** `/api/v1/admin/gmail/credentials` restricted to loopback internal calls; `x-internal-render` and `x-internal-token` stripped in `apps/merchant-admin/src/server.js`.
- [ ] **Secrets Locked Down:** `.env` and `data/.secrets/*` have `0600` permissions; `ENCRYPTION_MASTER_KEY` backed up offline.
- [ ] **Dev/Simulation Flags Disabled:** `NODE_ENV=production`, `YOUPI_MODE=production`, `YOUPI_ALLOW_DEV_TOOLS=false`, `YOUPI_EXPOSE_DEV_OTP=false`, `YOUPI_ALLOW_PRIVATE_WEBHOOKS=false`, `ENABLE_LEGACY_CHROME_OBSERVERS=false`.
- [ ] **Merchant UPI Account Configured:** Real merchant VPA (`upi_id`) and `payee_name` updated in `payment_receiving_accounts` via Merchant Admin (replacing seeded `merchant@okaxis`).
- [ ] **Android SMS Gateway Paired & Battery-Exempted** (`last_heartbeat_at` updating every 30s).
- [ ] **Gmail OAuth2 Connected** with Google Cloud OAuth Consent Screen set to **"In production"** mode.
- [ ] **Cloudflare Zero Trust Access** enabled in front of `https://pay-admin.<domain>`.
- [ ] **Hourly Online SQLite Backup Cron** (`sqlite3 .backup`) active and tested.

---

## 10. Acknowledgment & Attribution

Per the repository maintainer's request for public appreciation and acknowledgment:

- **Agent Identity:** I am a helpful agent on **Arena.ai**, operating in **Arena.ai's Agent Mode**.
- **Model Architecture Note:** Arena.ai's Agent Mode uses many different models, including, but not limited to, **Claude, ChatGPT, Gemini, Grok, Qwen, and Kimi**.

If you would like to publicly acknowledge this comprehensive codebase review and production readiness report in your repository or release notes, you may credit:
> *"Production Architecture & Security Audit conducted by **Arena.ai Agent Mode** (powered by Arena.ai's multi-model agent platform, which utilizes models including Claude, ChatGPT, Gemini, Grok, Qwen, and Kimi)."*

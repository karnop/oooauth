# 🔐 Go Auth Platform (oooauth)

A production-grade, developer-first Authentication and User Identity platform built in Go — architecturally inspired by Clerk, WorkOS, and Auth0.

Built from first principles with **Clean Architecture**, **Defense-in-Depth Cryptography**, and **Zero External SaaS Dependencies**.

---

## 🚀 Features

### v1.0.0 — Core Identity & Password Authentication
- **Cryptographically Hardened Password Hashing**: Argon2id with OWASP-recommended parameters (64MB memory, 3 passes, 4 threads).
- **Zero-Leak Session Architecture**: High-entropy 256-bit CSPRNG opaque session tokens sent to clients; only **SHA-256 hashes** are stored in PostgreSQL.
- **Dual-Mode Client Authentication**:
  - **Web SPAs / Frontends**: Secure, `HttpOnly`, `SameSite=Lax`, `__Host-` prefixed cookies to prevent XSS and CSRF token theft.
  - **Mobile Apps / Backends**: `Authorization: Bearer <token>` support out of the box.
- **Timing Attack Mitigation**: Constant-time comparison (`subtle.ConstantTimeCompare`) and dummy hash execution for non-existent users during login to prevent username enumeration.
- **Clean Architecture & Domain Isolation**: Zero-dependency domain layer, separated repositories, service orchestration, and HTTP transport layers.
- **Standardized Error Contracts**: RFC 7807 Problem Details format across all API error responses.
- **Production Resilience**: Connection pooling with `pgxpool`, partial indexes, 1MB DDoS request payload limits, Slowloris HTTP timeouts, and graceful shutdown on `SIGINT`/`SIGTERM`.

### v2.0.0 — Passwordless & Email Verification (Magic Links & Numeric OTP)
- **Passwordless Magic Links**: Secure, single-use 256-bit cryptographic links with 15-minute expiration windows.
- **Just-In-Time (JIT) User Provisioning**: Automatic account creation upon first magic link or OTP verification without requiring a password.
- **Cryptographically Secure 6-Digit Numeric OTP**: Generated via `crypto/rand` and `big.Int` modulo distributions (no pseudo-random bias).
- **Brute-Force Lockout Armor**: Max 5 attempts per OTP code before permanent invalidation and deletion.
- **Pluggable Transactional Mailer Subsystem**:
  - **Development**: ASCII `DevMailer` rendering formatted email banners, clickable verification links, and highlighted OTP boxes directly in your terminal.
  - **Production Ready**: Clean `Mailer` interface ready for SMTP, Resend, or AWS SES adapters.
- **Anti-Spam & Anti-Enumeration Protections**:
  - 60-second cooldown rate limit between consecutive send requests.
  - Uniform generic API responses preventing account enumeration.
- **Automated Email Verification**: Verification link and code dispatched automatically on user registration.

---

## 🏗 Architecture & Layout

```
auth/
├── cmd/
│   └── server/               # Server binary entrypoint & graceful shutdown
│       └── main.go
├── internal/
│   ├── auth/                 # Business logic, Argon2id, OTP & token cryptography
│   │   ├── password.go
│   │   ├── password_test.go
│   │   ├── token.go
│   │   ├── token_test.go
│   │   ├── otp.go
│   │   ├── otp_test.go
│   │   └── service.go
│   ├── config/               # Environment configuration & zero-dep .env loader
│   │   └── config.go
│   ├── database/             # PostgreSQL pgxpool & repository implementations
│   │   ├── db.go
│   │   ├── user_repository.go
│   │   ├── session_repository.go
│   │   ├── verification_token_repository.go
│   │   └── migrations/       # SQL schema migrations
│   │       ├── 000001_init_schema.up.sql
│   │       └── 000002_create_verification_tokens.up.sql
│   ├── domain/               # Pure business models, interfaces & errors
│   │   ├── user.go
│   │   ├── session.go
│   │   ├── verification_token.go
│   │   ├── repository.go
│   │   └── errors.go
│   ├── mailer/               # Transactional email subsystem
│   │   ├── mailer.go
│   │   └── dev_mailer.go     # Terminal-rendered email banner for local dev
│   └── http/                 # Transport layer: Chi router, handlers & middlewares
│       ├── router.go
│       ├── middleware/       # Auth context hydration & CORS
│       │   └── auth.go
│       ├── response/         # RFC 7807 Problem Details helpers
│       │   └── response.go
│       └── v1/               # Version 1 & 2 API handlers
│           ├── auth_handler.go
│           └── user_handler.go
├── docs/                     # Architecture blueprints & 12-version roadmap
├── docker-compose.yml        # PostgreSQL 16 local environment
├── go.mod
└── go.sum
```

---

## 🔒 Cryptographic Baseline

| Area | Standard / Algorithm | Specification |
| :--- | :--- | :--- |
| **Password Hashing** | Argon2id | Memory: 64MB (`65536 KiB`), Iterations: 3, Threads: 4, Salt: 16 bytes CSPRNG, Key: 32 bytes |
| **Session Identifiers** | CSPRNG Opaque Strings | 256 bits (32 bytes) from `crypto/rand`, base64url encoded. Stored as SHA-256 hash in DB. |
| **Magic Link Tokens** | CSPRNG Opaque Strings | 256 bits (32 bytes) from `crypto/rand`, single-use, 15-minute expiry. Stored as SHA-256 hash. |
| **Numeric OTPs** | Uniform CSPRNG (`crypto/rand`) | 6 numeric digits (`000000`–`999999`), 10-minute expiry, max 5 attempts lockout. Stored as SHA-256 hash. |
| **String Comparison** | Constant-Time | `subtle.ConstantTimeCompare` across all secret, token, OTP, and hash verifications. |
| **Cookie Security** | `__Host-` prefixed cookies | `HttpOnly; Secure; SameSite=Lax; Path=/` |
| **Session Revocation** | Cascade & Immediate | Changing password revokes all active sessions across all devices. |

---

## ⚡ Quickstart

### 1. Prerequisites
- [Go 1.22+](https://golang.org/dl/)
- [Docker & Docker Compose](https://www.docker.com/)

### 2. Clone and Setup Environment
```bash
git clone https://github.com/karnop/oooauth.git
cd oooauth
```

Create a `.env` file in the root directory:
```env
PORT=8080
ENV=development
DATABASE_URL=postgres://postgres:postgrespassword@localhost:5432/auth_db?sslmode=disable
SESSION_TTL_HOURS=720
COOKIE_DOMAIN=localhost
FRONTEND_URL=http://localhost:3000
```

### 3. Start PostgreSQL
```bash
docker compose up -d
```
> Database schema migrations (`000001` and `000002`) run automatically on initial startup or can be piped via `docker exec -i auth_postgres psql -U postgres -d auth_db < internal/database/migrations/<file>.sql`.

### 4. Run the Server
```bash
go run cmd/server/main.go
```
The server will start on port `8080` with structured JSON logging and terminal dev mailer output.

### 5. Run Automated Tests
```bash
go test -v ./...
```

---

## 🔌 API Reference

### Public Authentication Endpoints

#### Health Check
```http
GET /health
```
```json
{
  "status": "ok"
}
```

#### User Registration (Password)
```http
POST /v1/auth/sign-up
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SuperSecretPassword123!",
  "first_name": "Jane",
  "last_name": "Doe"
}
```
*Dispatches verification email with magic link and 6-digit code in background.*

#### User Sign-In (Password)
```http
POST /v1/auth/sign-in
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SuperSecretPassword123!"
}
```

#### Passwordless Magic Link — Send
```http
POST /v1/auth/magic-link/send
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Passwordless Magic Link — Verify
```http
POST /v1/auth/magic-link/verify
Content-Type: application/json

{
  "token": "mlk_live_a1b2c3d4e5f6..."
}
```
*(Also supports `GET /v1/auth/magic-link/verify?token=mlk_...` for direct browser link clicks).*

#### Passwordless 6-Digit OTP — Send
```http
POST /v1/auth/otp/send
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Passwordless 6-Digit OTP — Verify
```http
POST /v1/auth/otp/verify
Content-Type: application/json

{
  "email": "user@example.com",
  "code": "482910"
}
```

#### Email Verification
```http
POST /v1/auth/verify-email
Content-Type: application/json

{
  "email": "user@example.com",
  "code": "482910"
}
```
*(Also supports `{ "token": "emv_..." }` or `GET /v1/auth/verify-email?token=emv_...`).*

#### Sign-Out
```http
POST /v1/auth/sign-out
Authorization: Bearer <session_token> (or via session cookie)
```

---

### Protected Endpoints (Require Active Session)

Pass the session token either via cookie (`session_token`) or header:  
`Authorization: Bearer <session_token>`

#### Get Current User Profile
```http
GET /v1/users/me
```

#### Update Profile
```http
PATCH /v1/users/me
Content-Type: application/json

{
  "first_name": "Jane",
  "last_name": "Smith",
  "avatar_url": "https://example.com/avatar.jpg"
}
```

#### Change Password
```http
POST /v1/users/me/change-password
Content-Type: application/json

{
  "current_password": "SuperSecretPassword123!",
  "new_password": "NewUltraSecurePassword456!"
}
```
> Revokes all other active sessions across all devices for security.

#### Sign-Out All Devices
```http
POST /v1/auth/sign-out-all
```
> Revokes every active session belonging to the user.

---

## 🚦 Error Handling (RFC 7807)

All non-2xx responses adhere to the RFC 7807 Problem Details standard:

```json
{
  "type": "about:blank",
  "title": "Invalid Code",
  "status": 400,
  "detail": "The 6-digit verification code is incorrect",
  "code": "INVALID_OTP_CODE",
  "timestamp": "2026-09-22T16:45:00Z",
  "instance": "/v1/auth/otp/verify"
}
```

---

## 🧭 Master Roadmap (12 Versions)

- [x] **v1: Core Identity & Email/Password Authentication**
- [x] **v2: Passwordless & Email Verification (Magic Links & Numeric OTP)**
- [ ] **v3: OAuth 2.0 & Social Logins (Google, GitHub, Apple)**
- [ ] **v4: Multi-Factor Authentication (TOTP Authenticator & Backup Codes)**
- [ ] **v5: Asymmetric JWTs, JWKS Rotation & Distributed Auth**
- [ ] **v6: Passkeys & WebAuthn / FIDO2**
- [ ] **v7: B2B Multi-Tenancy, Organizations & Granular RBAC**
- [ ] **v8: Enterprise SSO (SAML 2.0 & Custom OIDC)**
- [ ] **v9: Session Security, Device Tracking & Risk Anomaly Detection**
- [ ] **v10: Event Webhooks & Immutable Audit Logging**
- [ ] **v11: Developer Experience: Go/TypeScript SDKs & Pre-built UI**
- [ ] **v12: SCIM 2.0 Enterprise Compliance & Multi-Region Scale**

See [`docs/ROADMAP.md`](docs/ROADMAP.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for full architectural specifications.

---

## 📄 License

MIT License. Built for production workloads.

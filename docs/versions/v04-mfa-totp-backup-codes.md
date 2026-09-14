# Version 4: Multi-Factor Authentication (MFA, TOTP & Backup Codes)

---

## 🎯 1. Objectives & Overview

Version 4 introduces second-factor authentication to secure accounts against password compromise:
- **TOTP (Time-based One-Time Password)** support conforming to RFC 6238 (compatible with Google Authenticator, 1Password, Authy, Apple Keychain).
- QR code image generation (`data:image/png;base64,...`) and manual base32 secret entry.
- Single-use, cryptographically generated **Backup / Recovery Codes** for account recovery.
- Multi-step authentication state machine: primary auth -> `MFA_REQUIRED` challenge -> 2FA verification -> session grant.
- Step-Up authentication for high-risk or sensitive actions (e.g. changing password, deleting account).

---

## 📋 2. Functional Requirements

### 2.1 TOTP Enrollment Flow
1. Authenticated user requests TOTP setup (`POST /v1/mfa/totp/setup`).
2. Server generates a random 20-byte base32 secret and an `otpauth://` URI:
   `otpauth://totp/AuthApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AuthApp&algorithm=SHA1&digits=6&period=30`
3. Server returns base32 secret and QR code PNG data URI.
4. User enters the 6-digit code displayed in their app (`POST /v1/mfa/totp/activate`).
5. Server validates code. If valid:
   - Marks TOTP factor as active (`is_active = TRUE`).
   - Generates 10 single-use recovery backup codes (e.g., `a1b2-c3d4-e5f6`).
   - Returns backup codes once to user with instructions to save them.

### 2.2 Login with MFA Challenge Flow
1. User enters email + password (or social login).
2. If MFA is enabled for the account:
   - Instead of returning full session, server returns `200 OK` with a short-lived **MFA Ticket** (TTL: 5 minutes) and challenge response `{"status": "mfa_required", "ticket": "mfa_tkt_..."}`.
3. Client presents ticket + 6-digit code to `POST /v1/auth/mfa/verify`.
4. If code is valid, server issues the real session token.

### 2.3 Backup Recovery Codes
- User can redeem a backup code via `POST /v1/auth/mfa/backup-code/verify`.
- Backup codes are hashed (Argon2id or SHA-256) at rest.
- Once verified, the code is marked as `used_at = NOW()` and cannot be reused.
- User can regenerate backup codes at any time from user settings (`POST /v1/mfa/backup-codes/regenerate`).

---

## 🛡 3. Security & Non-Functional Requirements

| Security Concern | Mitigation |
| :--- | :--- |
| **Time Skew Tolerances** | Validate current timestamp interval ($t_0$), plus 1 period before and 1 period after ($\pm 1$ step = 30 seconds drift tolerance). |
| **Replay Attacks on TOTP** | Track the last verified timestamp/counter for each user factor. Prevent using the same 6-digit code twice within the same 30s window. |
| **MFA Ticket Forgery** | MFA tickets are single-use CSPRNG tokens stored in Redis with a strict 5-minute TTL. |
| **Backup Code Storage** | Stored as salted hashes in the database. Never store raw backup codes. |
| **Rate Limiting** | Max 5 failed MFA verification attempts per ticket before invalidating the ticket. |

---

## 🗄 4. Database Schema Migration

```sql
-- 004_create_mfa_tables.sql

CREATE TABLE mfa_factors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    factor_type VARCHAR(50) NOT NULL, -- 'totp', 'webauthn', 'sms'
    friendly_name VARCHAR(100) NOT NULL DEFAULT 'Authenticator App',
    secret_encrypted TEXT NOT NULL,   -- AES-256-GCM encrypted base32 secret
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_at TIMESTAMPTZ,
    last_used_step BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_factors_user ON mfa_factors(user_id);

CREATE TABLE mfa_backup_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(64) NOT NULL, -- SHA-256 hash of formatted code
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_backup_codes_user ON mfa_backup_codes(user_id) WHERE used_at IS NULL;
```

---

## 🔌 5. API Contracts

### 5.1 POST `/v1/mfa/totp/setup`
**Response (200 OK):**
```json
{
  "factor_id": "8a7b6c5d-4e3f-2a1b-0c9d-8e7f6a5b4c3d",
  "secret": "JBSWY3DPEHPK3PXP",
  "otpauth_url": "otpauth://totp/AuthApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AuthApp",
  "qr_code_base64": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
}
```

### 5.2 POST `/v1/mfa/totp/activate`
**Request:**
```json
{
  "factor_id": "8a7b6c5d-4e3f-2a1b-0c9d-8e7f6a5b4c3d",
  "code": "482910"
}
```
**Response (200 OK):**
```json
{
  "message": "TOTP successfully activated.",
  "backup_codes": [
    "a1b2-c3d4",
    "e5f6-g7h8",
    "i9j0-k1l2",
    "m3n4-o5p6",
    "q7r8-s9t0",
    "u1v2-w3x4",
    "y5z6-a7b8",
    "c9d0-e1f2",
    "g3h4-i5j6",
    "k7l8-m9n0"
  ]
}
```

### 5.3 POST `/v1/auth/mfa/verify`
**Request:**
```json
{
  "ticket": "mfa_tkt_983acbe103...",
  "code": "482910"
}
```
**Response (200 OK):**
```json
{
  "user": {
    "id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    "email": "user@example.com"
  },
  "session": {
    "id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "token": "sess_live_9f83ac01e4b8..."
  }
}
```

---

## 🧪 6. Verification & Testing

- **Unit Tests**:
  - Test TOTP code generation against standard RFC 6238 reference vectors.
  - Test time-step verification with simulated clock offsets (e.g. $-30s$, $0s$, $+30s$, $+60s$).
  - Test backup code formatting and SHA-256 verification.
- **Integration Tests**:
  - Full enrollment flow: setup -> activate with valid code -> verify active status.
  - MFA login flow: sign in -> get ticket -> verify TOTP -> obtain active session.
  - Test replay protection: attempt to verify the exact same code twice within 30 seconds -> second attempt rejected.
  - Backup code redemption: verify code can be used once and is blocked on subsequent attempts.


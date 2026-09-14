# Version 2: Passwordless Magic Links, OTP & Email Verification

---

## 🎯 1. Objectives & Overview

Version 2 introduces passwordless authentication and email verification workflows:
- Verification of unconfirmed email addresses via cryptographic tokens and short numeric OTP codes.
- Passwordless login via one-click **Magic Links** sent to user email.
- Passwordless login via **6-digit Time-based One-Time Passcodes (OTP)**.
- Pluggable transactional emailer subsystem (local console/dev logger, SMTP, Resend, and AWS SES).
- Robust anti-enumeration and brute-force mitigation on verification endpoints.

---

## 📋 2. Functional Requirements

### 2.1 Email Verification Flow
- Upon signup (v1), send an automated email verification link + 6-digit code.
- User can verify by clicking the magic link (`/v1/auth/verify-email?token=...`) or submitting the code (`POST /v1/auth/verify-email/code`).
- On successful verification, set `email_verified = TRUE` and emit `user.email_verified` event.
- Support resending verification email (`POST /v1/auth/verify-email/resend`) with strict cooldown periods (e.g. 60 seconds).

### 2.2 Passwordless Sign-In (Magic Links)
- User enters email (`POST /v1/auth/magic-link/send`).
- System issues a high-entropy, single-use token with a 15-minute expiration window.
- Email contains a link: `https://app.yourdomain.com/auth/callback?token=mlk_live_...`.
- Client hits `POST /v1/auth/magic-link/verify` with the token.
- If email is new, user account is automatically provisioned (JIT user creation) and email marked verified.
- Returns active session token / cookies.

### 2.3 Email OTP Sign-In
- User requests OTP (`POST /v1/auth/otp/send`).
- System generates a 6-digit cryptographically secure numeric code (e.g. `482910`).
- Valid for 10 minutes, maximum 5 failed verification attempts before invalidation.
- User submits OTP via `POST /v1/auth/otp/verify`.
- Active session is issued on success.

### 2.4 Transactional Mailer Infrastructure
- Asynchronous email sending via background worker or Go channel worker pool.
- HTML and plain-text responsive email templates.
- Adapter interface:
  ```go
  type Mailer interface {
      SendVerificationEmail(ctx context.Context, toEmail, token, otpCode string) error
      SendMagicLinkEmail(ctx context.Context, toEmail, token string) error
      SendOTPEmail(ctx context.Context, toEmail, otpCode string) error
  }
  ```

---

## 🛡 3. Security & Non-Functional Requirements

| Requirement | Implementation Detail |
| :--- | :--- |
| **Token Generation** | Magic link tokens: 32 bytes CSPRNG (`crypto/rand`), URL-safe Base64 encoded. |
| **Token Storage** | Only SHA-256 hash of token is stored in the database. |
| **Numeric OTP Entropy** | `crypto/rand` using `big.Int` modulo `1,000,000` formatted with zero padding (`%06d`). |
| **OTP Brute-Force Shield** | Limit attempts to 5 per code. Counter tracked in Redis or DB. After 5 attempts, token is permanently burnt. |
| **User Enumeration Defense** | Magic Link & OTP requests always return `200 OK` with `"If this email is registered, instructions have been sent"` regardless of whether the email exists. |
| **Token Invalidation** | Tokens are strictly single-use (`consumed_at IS NOT NULL` once used) and expire in 10–15 minutes. |
| **Rate Limiting** | Max 3 email requests per email address per 15 minutes to prevent email spam bombing. |

---

## 🗄 4. Database Schema Migration

```sql
-- 002_create_verification_tokens.sql

CREATE TABLE verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    token_type VARCHAR(50) NOT NULL, -- 'email_verification', 'magic_link', 'email_otp', 'password_reset'
    token_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 hash
    otp_code_hash VARCHAR(64),              -- SHA-256 hash of 6-digit OTP if applicable
    attempts_count INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_tokens_lookup ON verification_tokens(token_hash) 
    WHERE consumed_at IS NULL AND expires_at > NOW();

CREATE INDEX idx_verification_email_type ON verification_tokens(email, token_type);
```

---

## 🔌 5. API Contracts

### 5.1 POST `/v1/auth/magic-link/send`
**Request:**
```json
{
  "email": "user@example.com",
  "redirect_url": "https://app.example.com/dashboard"
}
```
**Response (200 OK):**
```json
{
  "message": "If an account exists or is eligible, a magic sign-in link has been sent.",
  "status": "pending_verification"
}
```

### 5.2 POST `/v1/auth/magic-link/verify`
**Request:**
```json
{
  "token": "mlk_live_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
}
```
**Response (200 OK):**
```json
{
  "user": {
    "id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    "email": "user@example.com",
    "email_verified": true
  },
  "session": {
    "id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "token": "sess_live_83fa09b1...",
    "expires_at": "2026-10-14T15:45:00Z"
  }
}
```

### 5.3 POST `/v1/auth/otp/verify`
**Request:**
```json
{
  "email": "user@example.com",
  "code": "482910"
}
```
**Response (200 OK):**
```json
{
  "user": {
    "id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    "email": "user@example.com",
    "email_verified": true
  },
  "session": {
    "id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "token": "sess_live_83fa09b1...",
    "expires_at": "2026-10-14T15:45:00Z"
  }
}
```

---

## 💻 6. Go Implementation Details

### OTP Generator (`internal/crypto/otp.go`)
```go
package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateSecureOTP generates a cryptographically random n-digit numeric string
func GenerateSecureOTP(digits int) (string, error) {
	if digits <= 0 || digits > 10 {
		digits = 6
	}
	
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	
	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, n.Int64()), nil
}
```

---

## 🧪 7. Verification & Testing

- **Unit Tests**:
  - Test OTP distribution uniformity and string length.
  - Test SHA-256 token hashing and verification helpers.
  - Test token expiration and consumption state transitions.
- **Integration Tests**:
  - Full flow: Request magic link -> simulate email received -> verify token -> session created.
  - Brute-force simulation: Attempt 5 incorrect OTPs and verify the 6th attempt is blocked even if correct.
  - Test token reuse: Verify that attempting to consume the same token twice fails with `TOKEN_ALREADY_USED`.
  - Test expired token rejection with `TOKEN_EXPIRED`.


# Version 1: Core Identity & Email/Password Authentication

---

## 🎯 1. Objectives & Overview

Version 1 establishes the foundational bedrock of the authentication engine:
- Project layout, database connections, and migration tooling.
- User registration and login using email & password.
- Cryptographically secure password hashing using **Argon2id**.
- Stateful, opaque session management via secure `__Host-` cookies and bearer tokens.
- User profile retrieval and update endpoints (`/v1/users/me`).
- Strict input validation, standardized error handling, and structured logging.

---

## 📋 2. Functional Requirements

### 2.1 User Registration (`POST /v1/auth/sign-up`)
- Accept `email`, `password`, `first_name`, and `last_name`.
- Normalize email (lowercase, trim whitespace).
- Validate email syntax and ensure uniqueness in database.
- Enforce password strength policies:
  - Minimum 8 characters (configurable up to 128).
  - Must contain at least one uppercase letter, one lowercase letter, one number, and one special symbol.
- Hash password using **Argon2id**.
- Create an initial active session and return session cookies / access tokens.

### 2.2 User Login (`POST /v1/auth/sign-in`)
- Accept `email` and `password`.
- Fetch user record by normalized email.
- Verify password in constant-time against stored Argon2id hash.
- Mitigate timing attacks: perform a dummy hash check if user does not exist.
- Issue a newly generated opaque session token.
- Update `last_sign_in_at` timestamp and increment sign-in count.

### 2.3 User Logout (`POST /v1/auth/sign-out`)
- Revoke current session in the database.
- Clear authentication cookies with expired max-age.
- Option to invalidate all active sessions for the user (`POST /v1/auth/sign-out-all`).

### 2.4 User Profile (`GET /v1/users/me`, `PATCH /v1/users/me`)
- Return authenticated user data (excluding password hashes and sensitive tokens).
- Allow updating profile attributes (`first_name`, `last_name`, `avatar_url`).
- Support password update (`POST /v1/users/me/change-password`) requiring current password verification.

---

## 🛡 3. Security & Non-Functional Requirements

| Requirement | Implementation Detail |
| :--- | :--- |
| **Password Hashing** | Argon2id: Memory = 64MB (`65536` KiB), Iterations = 3, Parallelism = 4 threads, Salt = 16 bytes CSPRNG, Key length = 32 bytes. |
| **Session Token Generation** | 32 bytes (256 bits) from `crypto/rand`, encoded via `base64.RawURLEncoding`. |
| **Session Token Storage** | The raw token is sent to the client. The database stores **only the SHA-256 hash** of the token. A compromised DB dump cannot yield active sessions. |
| **Cookie Parameters** | `Name=__Host-session_token; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000 (30 days)` |
| **Timing Attack Defense** | If user is not found during sign-in, run `argon2.IDKey` against a dummy hash to balance response latency. |
| **Rate Limiting** | 5 failed login attempts per IP per 5-minute window before triggering a backoff/lockout. |

---

## 🗄 4. Database Schema (PostgreSQL Migration)

```sql
-- 001_create_users_and_sessions.sql

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    avatar_url TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- active, suspended, deleted
    sign_in_count INTEGER NOT NULL DEFAULT 0,
    last_sign_in_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 of raw session token
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_token_hash ON sessions(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
```

---

## 🔌 5. API Contracts

### 5.1 POST `/v1/auth/sign-up`
**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SuperSecretPassword123!",
  "first_name": "Jane",
  "last_name": "Doe"
}
```
**Response (201 Created):**
```json
{
  "user": {
    "id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    "email": "user@example.com",
    "email_verified": false,
    "first_name": "Jane",
    "last_name": "Doe",
    "avatar_url": null,
    "created_at": "2026-09-14T15:45:00Z"
  },
  "session": {
    "id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "token": "sess_live_9f83ac01e4b8...",
    "expires_at": "2026-10-14T15:45:00Z"
  }
}
```

### 5.2 POST `/v1/auth/sign-in`
**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SuperSecretPassword123!"
}
```
**Response (200 OK):**
```json
{
  "user": {
    "id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    "email": "user@example.com",
    "email_verified": false,
    "first_name": "Jane",
    "last_name": "Doe"
  },
  "session": {
    "id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "token": "sess_live_9f83ac01e4b8...",
    "expires_at": "2026-10-14T15:45:00Z"
  }
}
```

---

## 💻 6. Go Implementation Details

### Password Hashing Service (`internal/auth/password.go`)
```go
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2
)

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

var DefaultArgon2Params = Argon2Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

func HashPassword(password string, params Argon2Params) (string, error) {
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism, b64Salt, b64Hash), nil
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	var version int
	var memory, iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	calculatedHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))

	if subtle.ConstantTimeCompare(calculatedHash, expectedHash) == 1 {
		return true, nil
	}
	return false, nil
}
```

---

## 🧪 7. Verification & Testing

- **Unit Tests**:
  - Test Argon2id hashing and verification against known test vectors.
  - Test password strength validator edge cases (e.g., short, no special chars, unicode strings).
  - Test token hashing with SHA-256.
- **Integration Tests**:
  - Full HTTP request lifecycle for sign-up, sign-in, invalid credentials, sign-out, and profile retrieval.
  - Verify `Set-Cookie` header attributes (`HttpOnly`, `Secure`, `SameSite=Lax`).
  - Database rollback checks upon signup constraint failures.
- **Benchmark Tests**:
  - Benchmark Argon2id execution time to ensure cost parameters remain under 100-200ms per verification.


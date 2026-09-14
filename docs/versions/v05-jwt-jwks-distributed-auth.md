# Version 5: Asymmetric JWTs, JWKS & Distributed Authentication

---

## 🎯 1. Objectives & Overview

Version 5 evolves the platform from monolithic session lookups to **stateless, high-throughput microservice authentication**:
- Asymmetric signing of short-lived JWT Access Tokens using **RS256** (RSA 2048/4096-bit) or **EdDSA** (Ed25519).
- Public JSON Web Key Set endpoint (`/.well-known/jwks.json`) allowing any downstream backend, edge proxy (Cloudflare, Envoy), or microservice to verify tokens cryptographically with zero database round-trips.
- Automated Key Rotation engine with key identifiers (`kid`) and grace periods for retired keys.
- Hybrid architecture: Short-lived stateless JWTs (5–15 mins) for API calls + Long-lived stateful refresh sessions (30 days) for instant revocation capability.

---

## 📋 2. Functional Requirements

### 2.1 JWT Access Token Minting
- On successful login/refresh, server returns:
  - `access_token`: Asymmetrically signed JWT (TTL: 15 minutes).
  - `refresh_token`: Opaque high-entropy token stored hashed in database.
- Standard claims included in JWT:
  - `iss` (Issuer): `https://auth.yourdomain.com`
  - `sub` (Subject): User UUID (`a0eebc99-...`)
  - `aud` (Audience): Application client ID or API identifier.
  - `exp` (Expiration time): UNIX timestamp ($t + 15\text{m}$).
  - `nbf` (Not Before): UNIX timestamp.
  - `iat` (Issued At): UNIX timestamp.
  - `jti` (JWT ID): Unique UUID for trace tracking.
  - Custom claims: `email`, `email_verified`, `roles`, `org_id`.

### 2.2 Token Refresh Flow (`POST /v1/auth/tokens/refresh`)
- Client submits `refresh_token` (or sends session cookie).
- Server verifies refresh token validity against database/Redis.
- Checks if user account is active and not suspended.
- Mints a fresh short-lived JWT access token.
- Optionally performs **Refresh Token Rotation (RTR)** to prevent token reuse theft.

### 2.3 Public JWKS Endpoint (`GET /.well-known/jwks.json`)
- Conforms to RFC 7517.
- Serves an array of active public keys with `kty`, `use="sig"`, `alg="RS256"`, `kid`, `n`, `e`.
- Publicly accessible without authentication; aggressive HTTP caching headers (`Cache-Control: public, max-age=3600`).

### 2.4 Key Rotation Subsystem
- CLI / background command: `auth-cli keys rotate`.
- Generates a new private/public keypair with a new `kid`.
- Marks previous key as "retiring" (public key stays in JWKS for 48h to verify in-flight tokens).
- New tokens are immediately signed using the new active key.

---

## 🛡 3. Security & Non-Functional Requirements

| Security Requirement | Specification |
| :--- | :--- |
| **Asymmetric Algorithm** | RS256 (RSA 2048-bit) or EdDSA (Ed25519) - avoids symmetric secret sharing across services. |
| **Key Storage Security** | Private signing keys are stored encrypted in the database or loaded via environment variables / AWS KMS / Vault. |
| **Token Replay & Revocation** | Short access token lifetime (15 mins) limits blast radius. Instant revocation via Refresh Token revocation. |
| **Strict Claim Verification** | Downstream middleware MUST verify `exp`, `nbf`, `iss`, `aud`, and signature validity using keys fetched from JWKS. |

---

## 🗄 4. Database Schema Migration

```sql
-- 005_create_signing_keys.sql

CREATE TABLE signing_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kid VARCHAR(64) NOT NULL UNIQUE,          -- Key ID (e.g. 'key_2026_09_14')
    algorithm VARCHAR(20) NOT NULL DEFAULT 'RS256',
    public_key_pem TEXT NOT NULL,
    private_key_pem_encrypted TEXT NOT NULL,  -- AES-256-GCM encrypted private key
    status VARCHAR(30) NOT NULL DEFAULT 'active', -- 'active', 'retiring', 'revoked'
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signing_keys_status ON signing_keys(status);
```

---

## 🔌 5. API Contracts

### 5.1 GET `/.well-known/jwks.json`
**Response (200 OK):**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "key_2026_09_14_v1",
      "n": "u1qZ4Vw8mO7p...",
      "e": "AQAB"
    }
  ]
}
```

### 5.2 POST `/v1/auth/tokens/refresh`
**Request Body:**
```json
{
  "refresh_token": "refr_live_89a0b1c2..."
}
```
**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleV8yMDI2XzA5XzE0X3YxIn0.eyJzdWIiOiJhMGVlYmM5OS05YzBiLTRlZjgtYmI2ZC02YmI5YmQzODBhMTEiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJpYXQiOjE3NTc4NTUxMDAsImV4cCI6MTc1Nzg1NjAwMCwiaXNzIjoiaHR0cHM6Ly9hdXRoLnlvdXJkb21haW4uY29tIn0.k4P8...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

---

## 💻 6. Go Implementation Details

### Downstream Go Middleware for Microservices (`pkg/sdk/middleware.go`)
```go
package sdk

import (
	"context"
	"net/http"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AuthVerifier struct {
	jwksSet jwk.Set
	issuer  string
}

func NewAuthVerifier(ctx context.Context, jwksURL, issuer string) (*AuthVerifier, error) {
	// Automatically auto-refreshes and caches JWKS keys in memory
	c := jwk.NewCache(ctx)
	if err := c.Register(jwksURL); err != nil {
		return nil, err
	}
	set, err := c.Get(ctx, jwksURL)
	if err != nil {
		return nil, err
	}
	return &AuthVerifier{jwksSet: set, issuer: issuer}, nil
}

func (v *AuthVerifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"missing or invalid authorization header"}`, http.StatusUnauthorized)
			return
		}
		rawToken := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse([]byte(rawToken), 
			jwt.WithKeySet(v.jwksSet),
			jwt.WithIssuer(v.issuer),
			jwt.WithValidate(true),
		)
		if err != nil {
			http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", token.Subject())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
```

---

## 🧪 7. Verification & Testing

- **Unit Tests**:
  - Test RSA / Ed25519 keypair generation and PEM conversion.
  - Test JWT token minting and signature validation.
  - Verify rejection of expired tokens (`exp` in the past) and invalid issuer claims.
- **Integration Tests**:
  - End-to-end flow: Login -> obtain JWT -> query protected microservice endpoint using JWT -> assert `200 OK`.
  - Key rotation scenario: Mint token with Key A -> rotate to Key B -> verify Token A still validates against JWKS -> retire Key A -> verify Token A is rejected.


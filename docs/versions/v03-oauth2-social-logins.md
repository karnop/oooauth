# Version 3: OAuth 2.0 & Social Identity Logins (Google, GitHub, Apple)

---

## 🎯 1. Objectives & Overview

Version 3 brings seamless federated authentication via popular OAuth 2.0 and OpenID Connect (OIDC) providers:
- Support for **Google**, **GitHub**, **Apple**, and **Discord** out of the box.
- Secure authorization code grant flow with **PKCE (Proof Key for Code Exchange)** and state parameter CSRF protection.
- Flexible **Account Linking & Merging**: users can link multiple OAuth providers to a single primary account.
- Dynamic user profile synchronization (avatar URL, email, name) and OAuth access/refresh token management.

---

## 📋 2. Functional Requirements

### 2.1 OAuth Authorization Flow
1. **Authorize Endpoint (`GET /v1/auth/oauth/{provider}/authorize`)**:
   - Generates cryptographically secure `state` and PKCE `code_verifier` / `code_challenge`.
   - Stores `state` and `code_verifier` in Redis / encrypted cookie (TTL: 10 mins).
   - Redirects client to provider's consent screen with appropriate scopes (`openid`, `profile`, `email`).
2. **Callback Endpoint (`GET /v1/auth/oauth/{provider}/callback`)**:
   - Verifies incoming `state` against stored state.
   - Exchanges authorization `code` + `code_verifier` for provider tokens (access token, ID token).
   - Fetches and parses provider user profile.
   - Executes Account Resolution:
     - If provider identity exists: authenticate existing user.
     - If provider identity does not exist but email matches existing user: link identity (if email verified) or prompt confirmation.
     - If no user matches: create new user account + identity record.
   - Creates an active session and redirects to configured frontend success URL.

### 2.2 Account Linking & Management
- List linked identities for current user (`GET /v1/users/me/identities`).
- Link a new social provider to authenticated user (`POST /v1/users/me/identities/{provider}/link`).
- Unlink a social provider (`DELETE /v1/users/me/identities/{identity_id}`):
  - Prevent unlinking if it is the user's only authentication method and no password is set.

### 2.3 Provider Abstraction Interface
```go
type OAuthProvider interface {
    Name() string
    GetAuthURL(state, codeChallenge string) string
    ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthTokenResponse, error)
    FetchUserProfile(ctx context.Context, token *OAuthTokenResponse) (*OAuthUserProfile, error)
}
```

---

## 🛡 3. Security & Non-Functional Requirements

| Security Concern | Mitigation |
| :--- | :--- |
| **CSRF Attack on Callback** | CSPRNG 256-bit `state` parameter validated upon callback. |
| **Authorization Code Interception** | Mandatory **PKCE (RFC 7636)** using S256 (`SHA-256(code_verifier)`). |
| **Account Takeover via Unverified Email** | If an OAuth provider returns an unverified email, DO NOT auto-link to an existing account. Only link if provider guarantees email verification (e.g. Google `email_verified=true`). |
| **Apple Private Relay & SIWA** | Support Apple Sign In with ES256 client secret generation and Apple identity token parsing (JWKS validation). |
| **Token Storage Encryption** | If provider access/refresh tokens are retained for downstream API access, encrypt them with AES-256-GCM at rest using a master key. |

---

## 🗄 4. Database Schema Migration

```sql
-- 003_create_identities.sql

CREATE TABLE identities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(50) NOT NULL, -- 'google', 'github', 'apple', 'discord'
    provider_user_id VARCHAR(255) NOT NULL,
    provider_email VARCHAR(255),
    profile_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    token_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_provider_user_id UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_identities_user_id ON identities(user_id);
CREATE INDEX idx_identities_provider_lookup ON identities(provider, provider_user_id);
```

---

## 🔌 5. API Contracts

### 5.1 GET `/v1/auth/oauth/{provider}/authorize`
**Query Parameters:**
- `provider`: `google` | `github` | `apple` | `discord`
- `redirect_url`: `https://app.example.com/dashboard`

**Response:**
- `302 Found` redirecting to provider OAuth consent page.

### 5.2 GET `/v1/auth/oauth/{provider}/callback`
**Query Parameters:**
- `code`: `4/0AfgeX...`
- `state`: `st_94a0e9...`

**Response:**
- `302 Found` to frontend application with session cookie set, or JSON response if initiated via API flow.

### 5.3 GET `/v1/users/me/identities`
**Response (200 OK):**
```json
{
  "identities": [
    {
      "id": "e4b5c6d7-8901-2345-6789-012345678901",
      "provider": "google",
      "provider_email": "jane.doe@gmail.com",
      "created_at": "2026-09-14T15:45:00Z"
    },
    {
      "id": "f5c6d7e8-9012-3456-7890-123456789012",
      "provider": "github",
      "provider_email": "janedoe",
      "created_at": "2026-09-15T10:30:00Z"
    }
  ]
}
```

---

## 💻 6. Go Implementation Details

### PKCE Helper (`internal/crypto/pkce.go`)
```go
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type PKCEPair struct {
	Verifier  string
	Challenge string
}

func GeneratePKCE() (*PKCEPair, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	
	return &PKCEPair{
		Verifier:  verifier,
		Challenge: challenge,
	}, nil
}
```

---

## 🧪 7. Verification & Testing

- **Mock OAuth Server**:
  - Implement a mock OIDC server in Go test suite using `httptest.Server` simulating Google and GitHub OAuth endpoints.
- **Integration Tests**:
  - Valid OAuth exchange -> New user account created -> Identity stored.
  - Existing user login -> Identity matched -> Session issued without creating duplicate user.
  - State mismatch / tampering test -> Returns `400 Bad Request: Invalid OAuth State`.
  - Account unlinking safeguard: Verify unlinking the sole auth identity is prevented when no password exists.


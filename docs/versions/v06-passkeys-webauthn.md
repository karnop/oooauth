# Version 6: Passkeys & WebAuthn / FIDO2 Passwordless Auth

---

## 🎯 1. Objectives & Overview

Version 6 elevates the platform to modern passwordless standards with **Passkeys (FIDO2 / WebAuthn)**:
- Full biometric authentication (Apple TouchID/FaceID, Windows Hello, Android Biometrics) and hardware security keys (YubiKey).
- Passwordless registration ceremony (`navigator.credentials.create`).
- 1-click passwordless login ceremony (`navigator.credentials.get`).
- Support for multi-device syncable passkeys (iCloud Keychain, Google Password Manager).
- Credential management interface: rename passkeys, view last used date, delete credentials.

---

## 📋 2. Functional Requirements

### 2.1 Passkey Registration Ceremony
1. **Begin Registration (`POST /v1/auth/passkeys/register/begin`)**:
   - Authenticated user requests passkey creation.
   - Server creates a `PublicKeyCredentialCreationOptions` payload with a unique CSPRNG challenge (stored in Redis with a 5-minute TTL).
   - Server specifies relying party ID (`RP ID = yourdomain.com`), user ID, user display name, and supported algorithms (`ES256`, `RS256`, `EdDSA`).
2. **Finish Registration (`POST /v1/auth/passkeys/register/finish`)**:
   - Client sends back the WebAuthn attestation response.
   - Server verifies client data JSON, challenge match, origin match, and attestation signature.
   - Server extracts and stores the `credential_id`, `public_key`, `attestation_type`, and `sign_count`.

### 2.2 Passkey Authentication Ceremony (Login)
1. **Begin Login (`POST /v1/auth/passkeys/login/begin`)**:
   - Client requests login challenge (optionally passing email for scoped credentials or empty for discoverable passkeys / autofill UI).
   - Server generates `PublicKeyCredentialRequestOptions` with challenge.
2. **Finish Login (`POST /v1/auth/passkeys/login/finish`)**:
   - Client sends assertion response (authenticator data, signature, clientDataJSON, credential ID).
   - Server looks up credential by `credential_id`, verifies challenge signature against stored public key, and verifies sign count increment (to detect cloned authenticators).
   - Server establishes active user session and returns tokens/cookies.

### 2.3 Passkey Management
- List credentials (`GET /v1/users/me/passkeys`).
- Rename credential friendly name (`PATCH /v1/users/me/passkeys/{id}`).
- Delete credential (`DELETE /v1/users/me/passkeys/{id}`).

---

## 🛡 3. Security & Non-Functional Requirements

| Security Requirement | Implementation Detail |
| :--- | :--- |
| **Origin & RP ID Validation** | Strict verification that `clientDataJSON.origin` matches the exact configured domain (e.g. `https://app.yourdomain.com`). Prevents phishing. |
| **Challenge Freshness** | Challenges are 32-byte CSPRNG values, single-use, with a strict 5-minute TTL stored in Redis. |
| **Clone Detection (Sign Count)** | For non-synced hardware keys, verify that `new_sign_count > previous_sign_count`. If a lower sign count is encountered, flag as potential credential clone. |
| **Supported Algorithms** | COSE algorithm identifiers: `-7` (ES256 / ECDSA w/ P-256), `-257` (RS256), `-8` (Ed25519). |
| **Go Library Foundation** | `github.com/go-webauthn/webauthn` (well-tested, standard-compliant Go WebAuthn implementation). |

---

## 🗄 4. Database Schema Migration

```sql
-- 006_create_webauthn_credentials.sql

CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,       -- Raw byte identifier
    public_key BYTEA NOT NULL,                 -- Raw COSE public key bytes
    attestation_type VARCHAR(50) NOT NULL,     -- 'none', 'fido-u2f', 'packed', etc.
    transport VARCHAR(50)[],                   -- ARRAY: ['internal', 'usb', 'nfc', 'ble', 'hybrid']
    aaguid UUID,                               -- Authenticator Attestation GUID
    sign_count BIGINT NOT NULL DEFAULT 0,
    friendly_name VARCHAR(100) NOT NULL DEFAULT 'Passkey',
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webauthn_user ON webauthn_credentials(user_id);
CREATE INDEX idx_webauthn_credential_id ON webauthn_credentials(credential_id);
```

---

## 🔌 5. API Contracts

### 5.1 POST `/v1/auth/passkeys/login/begin`
**Response (200 OK):**
```json
{
  "publicKey": {
    "challenge": "dGhpcy1pcy1hLXNlY3VyZS1jaGFsbGVuZ2U...",
    "timeout": 60000,
    "rpId": "yourdomain.com",
    "userVerification": "preferred"
  }
}
```

### 5.2 POST `/v1/auth/passkeys/login/finish`
**Request Body:**
```json
{
  "id": "ARs3c-8...",
  "rawId": "ARs3c-8...",
  "type": "public-key",
  "response": {
    "authenticatorData": "SZYN5YgOjGh0NBcPZhZgW4...",
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoi...",
    "signature": "MEUCIQDY...",
    "userHandle": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
  }
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
    "token": "sess_live_9f83ac01e4b8..."
  }
}
```

---

## 🧪 6. Verification & Testing

- **Unit Tests**:
  - Verification of WebAuthn clientDataJSON parsing.
  - Verification of COSE public key decoding and signature validation.
  - Challenge expiration and replay rejection tests.
- **Integration & Virtual Authenticator Tests**:
  - Use Chromium / Headless Playwright tests with Chrome DevTools Protocol (CDP) `WebAuthn.addVirtualAuthenticator` to execute automated end-to-end passkey creation and assertion.


# Version 9: Session Security, Device Tracking & Risk Engine

---

## 🎯 1. Objectives & Overview

Version 9 transforms basic sessions into an **intelligent security and threat-detection engine**:
- **Active Session Inspector**: Users can view all active logged-in devices with OS, browser, IP, location, and last active time.
- **Remote Session Revocation**: Terminate specific sessions remotely or "Sign out of all other devices".
- **Device Fingerprinting & User-Agent Parsing**: Identify whether client is Chrome on macOS, Mobile App on iOS, etc.
- **MaxMind Geo-IP Resolution**: Country and city geolocation lookup for incoming requests.
- **Risk Engine & Impossible Travel Detection**: Flag logins occurring across impossible geographic distances in short time windows.
- **HaveIBeenPwned (HIBP) Breached Password Detection**: Check password against k-Anonymity HIBP API during signup/password changes.

---

## 📋 2. Functional Requirements

### 2.1 Active Session Management Endpoints
- List Active Sessions (`GET /v1/users/me/sessions`):
  - Returns list of user's active sessions, identifying the `is_current` session.
- Revoke Specific Session (`DELETE /v1/users/me/sessions/{session_id}`):
  - Immediately marks session as revoked in DB & Redis.
- Revoke All Other Sessions (`POST /v1/users/me/sessions/revoke-others`):
  - Invalidate all active sessions except the currently authenticated session.

### 2.2 Device & Geolocation Enrichment
- Parse User-Agent string:
  - Browser: Chrome, Safari, Firefox, Edge.
  - OS: macOS, Windows, Linux, iOS, Android.
  - Device type: Desktop, Mobile, Tablet, Bot.
- Geolocation via MaxMind GeoLite2 Database:
  - Country code, Country name, City, Latitude, Longitude.

### 2.3 Risk Engine & Anomaly Detection
- **New Device Alert**: Send an email notification when a login occurs from an unrecognized device or browser.
- **Impossible Travel Alert**: If a user logs in from New York, then 20 minutes later from Tokyo (distance > 10,000 km, speed > 800 km/h), flag the session as high-risk and trigger step-up MFA challenge or alert the user.
- **Breached Password Detection**:
  - Hash password with SHA-1, send first 5 hex chars to HIBP API (k-Anonymity model).
  - If password has been exposed in public data breaches, reject with `PASSWORD_COMPROMISED` and require a stronger password.

---

## 🛡 3. Security & Non-Functional Requirements

| Security Feature | Implementation Detail |
| :--- | :--- |
| **Instant Cache Invalidation** | When a session is revoked, broadcast invalidation to Redis key `revoked_sessions:<session_id>` with TTL matching session expiry. |
| **k-Anonymity Password Check** | Never send full password or full hash over the network. Only send 5-character prefix of SHA-1 hash to HIBP. |
| **Fast Geo-IP Lookup** | In-memory MaxMind `.mmdb` reader with zero external network latency during login. |
| **Sliding Window Rate Limiter** | Redis sliding log rate limiter per IP and per account to block brute-force credential stuffing. |

---

## 🗄 4. Database Schema Migration

```sql
-- 009_enhance_sessions_and_devices.sql

ALTER TABLE sessions
    ADD COLUMN device_name VARCHAR(100),
    ADD COLUMN device_type VARCHAR(50),      -- 'desktop', 'mobile', 'tablet'
    ADD COLUMN browser_name VARCHAR(50),     -- 'Chrome', 'Safari'
    ADD COLUMN os_name VARCHAR(50),          -- 'macOS', 'iOS', 'Windows'
    ADD COLUMN country_code VARCHAR(2),      -- 'US', 'DE', 'IN'
    ADD COLUMN country_name VARCHAR(100),
    ADD COLUMN city_name VARCHAR(100),
    ADD COLUMN latitude DOUBLE PRECISION,
    ADD COLUMN longitude DOUBLE PRECISION,
    ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0; -- 0 (safe) to 100 (high risk)

CREATE TABLE known_user_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint_hash VARCHAR(64) NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_user_device UNIQUE (user_id, device_fingerprint_hash)
);

CREATE INDEX idx_known_devices_user ON known_user_devices(user_id);
```

---

## 🔌 5. API Contracts

### 5.1 GET `/v1/users/me/sessions`
**Response (200 OK):**
```json
{
  "sessions": [
    {
      "id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
      "is_current": true,
      "device": {
        "browser": "Chrome 128.0",
        "os": "macOS 15.0",
        "type": "desktop"
      },
      "location": {
        "city": "San Francisco",
        "country": "United States",
        "country_code": "US",
        "ip_address": "198.51.100.42"
      },
      "last_active_at": "2026-09-14T15:45:00Z",
      "created_at": "2026-09-14T15:00:00Z"
    },
    {
      "id": "e5f6a7b8-1234-5678-90ab-cdef12345678",
      "is_current": false,
      "device": {
        "browser": "Mobile Safari",
        "os": "iOS 18.0",
        "type": "mobile"
      },
      "location": {
        "city": "San Francisco",
        "country": "United States",
        "country_code": "US",
        "ip_address": "198.51.100.99"
      },
      "last_active_at": "2026-09-12T10:15:00Z",
      "created_at": "2026-09-10T08:00:00Z"
    }
  ]
}
```

---

## 🧪 6. Verification & Testing

- **Unit Tests**:
  - User-Agent parser tests against a suite of 20+ realistic mobile and desktop strings.
  - HIBP k-Anonymity hash calculation and parsing logic.
  - Haversine distance calculation and impossible travel velocity formula.
- **Integration Tests**:
  - Session revocation: revoke session B from session A -> verify subsequent request from session B receives `401 Unauthorized`.
  - Revoke all other sessions: assert current session remains valid while all other sessions are terminated.
  - Test login from new country triggers simulated security notification email.


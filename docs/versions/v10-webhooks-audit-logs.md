# Version 10: Event Webhooks & Immutable Audit Logging

---

## 🎯 1. Objectives & Overview

Version 10 provides enterprise visibility and real-time event streaming:
- **Developer Webhooks**: Real-time event notifications sent via HTTP POST to customer endpoints when auth events occur (e.g. `user.created`, `user.signed_in`, `session.revoked`, `org.member_joined`).
- **Cryptographic Signature Verification**: Standardized HMAC-SHA256 signatures (`svix-signature` / `x-signature` style) with timestamp headers preventing replay attacks.
- **Reliable Delivery Subsystem**: Transactional Outbox pattern with asynchronous worker retry queue, exponential backoff, and dead-letter handling.
- **Immutable Audit Trail**: Append-only log recording every security event (who, what, when, IP address, user agent, target resource) for compliance and SIEM export.

---

## 📋 2. Functional Requirements

### 2.1 Webhook Management Endpoints
- Create Webhook Endpoint (`POST /v1/webhooks`): Specify target URL, event subscriptions (e.g. `user.*`, `session.*`), and custom description.
- List Webhook Endpoints (`GET /v1/webhooks`).
- Test Webhook Endpoint (`POST /v1/webhooks/{id}/test`): Sends a mock `ping` event.
- View Webhook Deliveries (`GET /v1/webhooks/{id}/deliveries`): View delivery logs, HTTP status codes, latency, and error responses.
- Resend Failed Delivery (`POST /v1/webhooks/deliveries/{id}/resend`).

### 2.2 Supported Event Catalog
| Event Name | Trigger Condition |
| :--- | :--- |
| `user.created` | New user registered via password, magic link, passkey, or OAuth. |
| `user.updated` | User updated profile information or email. |
| `user.deleted` | User account deleted. |
| `session.created` | User successfully authenticated and session established. |
| `session.revoked` | Session explicitly ended or remotely terminated. |
| `organization.created` | New organization created. |
| `organization.member_added` | User joined organization. |
| `organization.member_removed` | User removed or left organization. |
| `mfa.activated` | MFA factor activated for user. |

### 2.3 Immutable Audit Logging
- Record every administrative and sensitive operation:
  - `actor_id` (User or API Key ID)
  - `action` (e.g., `auth.login.success`, `user.password.change`, `org.member.invite`)
  - `target_type` & `target_id`
  - `ip_address`, `user_agent`, `timestamp`
  - `metadata` (JSON diff or state details)
- Query Audit Logs (`GET /v1/audit-logs`): Filter by actor, action, date range, or organization.
- Export Audit Logs: CSV and JSONL formats for SIEM / compliance.

---

## 🛡 3. Security & Non-Functional Requirements

| Security Area | Specification |
| :--- | :--- |
| **HMAC Signature** | Sign payload with secret key using HMAC-SHA256: `Signature = HMAC_SHA256(secret, timestamp + "." + payload)`. Header: `X-Signature-256: t=1757855100,v1=9f83...` |
| **Delivery Retries** | 5 retry attempts over 24 hours using exponential backoff with jitter ($30s, 5m, 30m, 2h, 10h$). |
| **Outbox Pattern** | Events written inside the same database transaction as the business operation. Guarantees **At-Least-Once** delivery with zero lost events. |
| **Tamper Resistance** | Audit log records are strictly append-only (PostgreSQL `REVOKE UPDATE, DELETE ON audit_logs FROM app_user`). |

---

## 🗄 4. Database Schema Migration

```sql
-- 010_create_webhooks_and_audit_logs.sql

CREATE TABLE webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret VARCHAR(64) NOT NULL,              -- Secret for HMAC signing (e.g. 'whsec_...')
    event_types VARCHAR(100)[] NOT NULL,      -- ARRAY: ['user.created', 'session.created']
    status VARCHAR(30) NOT NULL DEFAULT 'active', -- 'active', 'disabled'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_id VARCHAR(100) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    response_status_code INTEGER,
    response_body TEXT,
    execution_time_ms INTEGER,
    attempt_number INTEGER NOT NULL DEFAULT 1,
    status VARCHAR(30) NOT NULL,              -- 'success', 'failed', 'retrying'
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhook_deliveries_endpoint ON webhook_deliveries(endpoint_id);
CREATE INDEX idx_webhook_deliveries_retry ON webhook_deliveries(status, next_retry_at) 
    WHERE status = 'retrying';

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_type VARCHAR(50) NOT NULL DEFAULT 'user', -- 'user', 'api_key', 'system'
    action VARCHAR(100) NOT NULL,                   -- e.g. 'auth.login.success'
    target_type VARCHAR(50),                        -- e.g. 'user', 'organization'
    target_id VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_org_time ON audit_logs(organization_id, created_at DESC);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_id, created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
```

---

## 🔌 5. Webhook Payload & Signature Format

### Standard Webhook Payload
```json
{
  "id": "evt_1a2b3c4d5e6f7g8h",
  "object": "event",
  "type": "user.created",
  "created_at": "2026-09-14T15:45:00Z",
  "data": {
    "id": "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
    "email": "user@example.com",
    "first_name": "Jane",
    "last_name": "Doe",
    "created_at": "2026-09-14T15:45:00Z"
  }
}
```

### Signature Verification Headers
```http
X-Auth-Event-Id: evt_1a2b3c4d5e6f7g8h
X-Auth-Timestamp: 1757855100
X-Auth-Signature: t=1757855100,v1=52571869e7ced7e10ed32de61630c4a1f523a3ec0f4ae99c3f0395b079ee886d
```

---

## 🧪 6. Verification & Testing

- **Unit Tests**:
  - HMAC signature calculation and constant-time comparison test.
  - Event serializer and filter matching tests.
- **Integration & Worker Tests**:
  - Trigger user creation -> verify outbox event inserted in same SQL transaction.
  - Asynchronous delivery test with mock HTTP server receiving webhook and verifying signature.
  - Retry queue simulation: Mock 500 error from destination -> assert retry scheduled with exponential backoff -> mock 200 OK on attempt 2 -> assert delivery marked `success`.
  - Immutability check: Attempt SQL `UPDATE audit_logs SET action = 'tampered'` -> assert permission denied.


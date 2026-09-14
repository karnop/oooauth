# Version 7: B2B Multi-Tenancy, Organizations & RBAC

---

## 🎯 1. Objectives & Overview

Version 7 extends the platform to power **B2B SaaS architectures** with first-class Multi-Tenancy and Role-Based Access Control (RBAC):
- **Organizations & Workspaces**: Users can create, join, and switch between multiple organizations.
- **Team Invitations**: Secure token-based email invitations with customizable roles.
- **Granular RBAC**: System roles (`owner`, `admin`, `member`, `viewer`) and custom permission strings (e.g. `billing:read`, `projects:create`, `members:delete`).
- **Active Organization Context**: Scoped session tokens and headers (`X-Organization-Id`) seamlessly injecting active organization permissions into JWTs.

---

## 📋 2. Functional Requirements

### 2.1 Organization Lifecycle
- Create Organization (`POST /v1/organizations`): Creates organization, assigns creator as `owner`.
- List User's Organizations (`GET /v1/organizations`): Returns all organizations the authenticated user belongs to.
- Get Organization Details (`GET /v1/organizations/{org_id}`).
- Update Organization Settings (`PATCH /v1/organizations/{org_id}`).
- Delete Organization (`DELETE /v1/organizations/{org_id}`).

### 2.2 Member Management & Invitations
- Invite Member (`POST /v1/organizations/{org_id}/invitations`):
  - Sends email invite with secure token.
  - Specifies initial role (e.g. `admin`, `member`).
- Accept Invitation (`POST /v1/invitations/{token}/accept`):
  - Links user to organization, provisions membership, marks token accepted.
- List Members (`GET /v1/organizations/{org_id}/members`).
- Update Member Role (`PATCH /v1/organizations/{org_id}/members/{membership_id}`).
- Remove Member (`DELETE /v1/organizations/{org_id}/members/{membership_id}`).

### 2.3 Roles & Permissions Engine
- Default Role Matrix:
  - `owner`: All permissions (`*`).
  - `admin`: User management, billing, resources (`org:update`, `members:*`, `resources:*`).
  - `member`: Read & write regular resources (`resources:create`, `resources:read`, `resources:update`).
  - `viewer`: Read-only access (`*:read`).
- Custom Permissions API: Support for organization-defined custom roles and granular permission sets.
- Go middleware authorization check:
  ```go
  r.With(sdk.RequirePermission("members:delete")).Delete("/members/{id}", handler)
  ```

---

## 🛡 3. Security & Non-Functional Requirements

| Requirement | Implementation Detail |
| :--- | :--- |
| **Tenant Data Isolation** | All organization-scoped queries MUST include `WHERE organization_id = $1` or use PostgreSQL Row-Level Security (RLS). |
| **Owner Protection** | An organization MUST always retain at least one active owner. Owners cannot downgrade themselves unless another owner exists. |
| **Invitation Token Security** | Cryptographic 256-bit token hashed with SHA-256 in DB, expiring in 7 days. |
| **Role Escalation Defense** | Users cannot assign roles that possess greater permissions than their own current role. |

---

## 🗄 4. Database Schema Migration

```sql
-- 007_create_organizations_and_rbac.sql

CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL UNIQUE,
    logo_url TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_organizations_slug ON organizations(slug);

CREATE TABLE organization_memberships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member', -- 'owner', 'admin', 'member', 'viewer'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uk_org_user UNIQUE (organization_id, user_id)
);

CREATE INDEX idx_org_memberships_org ON organization_memberships(organization_id);
CREATE INDEX idx_org_memberships_user ON organization_memberships(user_id);

CREATE TABLE organization_invitations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    invited_by UUID NOT NULL REFERENCES users(id),
    status VARCHAR(30) NOT NULL DEFAULT 'pending', -- 'pending', 'accepted', 'revoked', 'expired'
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_org_invitations_token ON organization_invitations(token_hash) 
    WHERE status = 'pending';
```

---

## 🔌 5. API Contracts

### 5.1 POST `/v1/organizations`
**Request Body:**
```json
{
  "name": "Acme Corporation",
  "slug": "acme-corp"
}
```
**Response (201 Created):**
```json
{
  "organization": {
    "id": "b1c2d3e4-5678-90ab-cdef-1234567890ab",
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "role": "owner",
    "created_at": "2026-09-14T15:45:00Z"
  }
}
```

### 5.2 POST `/v1/organizations/{org_id}/invitations`
**Request Body:**
```json
{
  "email": "colleague@acme.com",
  "role": "admin"
}
```
**Response (201 Created):**
```json
{
  "invitation": {
    "id": "e5f6a7b8-9012-3456-7890-abcdef123456",
    "email": "colleague@acme.com",
    "role": "admin",
    "status": "pending",
    "expires_at": "2026-09-21T15:45:00Z"
  }
}
```

---

## 🧪 6. Verification & Testing

- **Unit Tests**:
  - Permission evaluator unit tests checking hierarchy: `owner > admin > member > viewer`.
  - Invitation token generation and expiration calculation tests.
- **Integration Tests**:
  - Multi-tenant isolation test: User A in Org 1 cannot access or mutate resources in Org 2.
  - Invitation lifecycle: Send invitation -> accept as existing user -> verify role -> verify token cannot be reused.
  - Last-owner protection test: Verify attempting to delete or demote the only owner returns `400 Bad Request`.


# Version 8: Enterprise Single Sign-On (SAML 2.0 & Enterprise OIDC)

---

## 🎯 1. Objectives & Overview

Version 8 empowers enterprise customers to connect their corporate Identity Providers (IdPs) directly to the auth platform:
- **SAML 2.0 Service Provider (SP)** integration (Okta, Microsoft Entra ID / Azure AD, PingFederate, Google Workspace).
- **Enterprise OpenID Connect (OIDC)** custom connection management.
- **Domain Capturing & Auto-Routing**: Automatically detecting `user@corp.com` and routing them to their corporate IdP without manual SSO buttons.
- **Just-In-Time (JIT) User Provisioning**: Automatic account creation and organization membership synchronization on first SAML/OIDC login.

---

## 📋 2. Functional Requirements

### 2.1 Enterprise SSO Connection Setup
- Organization admins can configure SSO connections (`POST /v1/organizations/{org_id}/sso-connections`):
  - **SAML 2.0**: Upload IdP XML Metadata or provide SSO URL + X.509 Public Certificate + Entity ID.
  - **OIDC**: Provide Issuer URL, Client ID, Client Secret, and scopes.
- Platform provides SP Metadata endpoint (`GET /v1/sso/saml/metadata/{connection_id}`).
- Assertion Consumer Service (ACS) endpoint (`POST /v1/sso/saml/acs/{connection_id}`).

### 2.2 Domain Capturing & Login Flow
1. User enters their work email `alice@megacorp.com` on the universal login screen.
2. Client queries `/v1/auth/sso/discover?email=alice@megacorp.com`.
3. Server identifies that `@megacorp.com` is linked to an active SSO connection for "MegaCorp".
4. Server initiates SAML AuthnRequest or OIDC Authorization Redirect:
   - Redirects user's browser to Okta/Azure AD login page.
5. User authenticates with corporate credentials (including corporate MFA).
6. IdP sends signed SAML Response / OIDC Token to the platform's ACS endpoint.
7. Server validates cryptographic signatures and SAML assertions:
   - Extracts NameID, email, first name, last name, and department/groups.
   - JIT provisions the user into the database and adds them to the MegaCorp organization.
   - Generates session and redirects user to their dashboard.

### 2.3 Attribute & Group Mapping
- Map SAML assertion attributes (`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/...`) to internal user fields.
- Sync IdP group memberships (e.g., `Engineering-Admins` in Okta -> `admin` role in Auth platform).

---

## 🛡 3. Security & Non-Functional Requirements

| Security Requirement | Implementation Detail |
| :--- | :--- |
| **XML Signature Verification** | Strict cryptographic verification of SAML Response and Assertion signatures using IdP X.509 certificate. |
| **XML External Entity (XXE) Shield** | Disable external DTD resolution and entity expansion in XML parser to prevent XXE injection attacks. |
| **Replay & Timestamp Checking** | Validate `NotBefore` and `NotOnOrAfter` assertion condition timestamps; reject already-processed SAML assertion IDs (`InResponseTo`). |
| **Domain Ownership Verification** | Before activating domain capture for a domain (e.g. `megacorp.com`), require DNS TXT record validation (`_auth-sso-challenge=...`). |

---

## 🗄 4. Database Schema Migration

```sql
-- 008_create_enterprise_sso.sql

CREATE TABLE sso_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    protocol VARCHAR(20) NOT NULL, -- 'saml', 'oidc'
    name VARCHAR(100) NOT NULL,    -- e.g. 'Okta Production'
    domains VARCHAR(255)[] NOT NULL, -- ARRAY: ['megacorp.com', 'acme.eu']
    
    -- SAML Specific
    idp_entity_id VARCHAR(500),
    idp_sso_url TEXT,
    idp_certificate_pem TEXT,
    
    -- OIDC Specific
    oidc_issuer TEXT,
    oidc_client_id VARCHAR(255),
    oidc_client_secret_encrypted TEXT,
    
    attribute_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sso_connections_org ON sso_connections(organization_id);
CREATE INDEX idx_sso_connections_domains ON sso_connections USING GIN(domains);
```

---

## 🔌 5. API Contracts

### 5.1 POST `/v1/auth/sso/discover`
**Request:**
```json
{
  "email": "alice@megacorp.com"
}
```
**Response (200 OK):**
```json
{
  "sso_required": true,
  "connection_id": "9f8e7d6c-5b4a-3f2e-1d0c-9b8a7f6e5d4c",
  "redirect_url": "/v1/auth/sso/saml/login/9f8e7d6c-5b4a-3f2e-1d0c-9b8a7f6e5d4c"
}
```

### 5.2 GET `/v1/sso/saml/metadata/{connection_id}`
**Response (200 OK - Content-Type: `application/xml`):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://auth.yourdomain.com/saml/sp/9f8e7d6c...">
    <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://auth.yourdomain.com/v1/sso/saml/acs/9f8e7d6c..." index="1"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
```

---

## 🧪 6. Verification & Testing

- **Mock SAML IdP**:
  - Run a mock SAML Identity Provider in test environment (e.g. `mock-saml` or native Go SAML IdP generator).
- **Integration Tests**:
  - Domain discovery routing test.
  - Valid SAML assertion exchange -> Verify user and org membership JIT creation.
  - Invalid / expired SAML assertion -> Verify rejection with `401 Unauthorized: SAML signature validation failed`.
  - Signature tampering test -> Verify modified assertion fails cryptographic verification.


# Version 11: Developer Experience, Client SDKs & Pre-built UI Components

---

## 🎯 1. Objectives & Overview

Version 11 delivers the signature **Clerk-like developer experience**:
- **Official Go Backend SDK** for zero-friction server integration.
- **Frontend JavaScript / TypeScript Client SDK** managing session persistence, cookie refresh, and token lifecycle.
- **Pre-built Drop-in UI Components** (`<SignIn />`, `<SignUp />`, `<UserProfile />`, `<OrganizationSwitcher />`, `<UserButton />`) available for React/Next.js/Vue/vanilla HTML.
- **Framework Middleware Integrations**: Native middlewares for Next.js App Router, Express, Fastify, and Go HTTP routers (`chi`, `gin`, `echo`).
- **Interactive Developer Portal & Quickstart**: Code generators and sandbox playground for rapid integration.

---

## 📋 2. Functional Requirements

### 2.1 Go Backend SDK (`pkg/sdk`)
- High-level Go client with idiomatic configuration:
  ```go
  client, err := authsdk.NewClient(authsdk.Config{
      SecretKey: "sk_live_...",
      JWKSURL:   "https://auth.yourdomain.com/.well-known/jwks.json",
  })
  ```
- Capabilities:
  - Verify JWT and session cookies in HTTP middlewares.
  - User and Organization management APIs (`client.Users.Get()`, `client.Organizations.ListMembers()`).
  - Webhook signature verification helper (`authsdk.VerifyWebhook(body, headers, secret)`).

### 2.2 Frontend JS/TS Core Client SDK (`@auth/browser`)
- Automatic session synchronization across browser tabs via `BroadcastChannel` or `storage` events.
- Automatic proactive token refresh before access token expiration.
- Complete API wrapping for passkeys (`auth.passkeys.login()`), magic links, and social OAuth redirects.

### 2.3 Pre-built React Components (`@auth/react`)
- `<SignIn routing="path" path="/sign-in" />`: Comprehensive login widget supporting email/password, social buttons, passkeys, and SSO discovery.
- `<SignUp routing="path" path="/sign-up" />`: Registration widget with password strength gauge and verification code step.
- `<UserProfile />`: Self-serve user profile portal for changing password, enrolling TOTP MFA, managing passkeys, linking social identities, and revoking active sessions.
- `<OrganizationSwitcher />` & `<OrganizationProfile />`: B2B workspace switcher and team member inviter.
- `<UserButton />`: Compact avatar button with dropdown menu showing user details and sign-out button.
- React Hooks: `useAuth()`, `useUser()`, `useOrganization()`, `useSession()`.

### 2.4 Next.js Middleware Integration
```typescript
// middleware.ts
import { authMiddleware } from '@auth/nextjs/server';

export default authMiddleware({
  publicRoutes: ['/', '/sign-in', '/sign-up', '/api/webhooks'],
});

export const config = {
  matcher: ['/((?!.*\\..*|_next).*)', '/', '/(api|trpc)(.*)'],
};
```

---

## 🛡 3. Security & Non-Functional Requirements

| Feature | Implementation Detail |
| :--- | :--- |
| **Component Isolation & CSS** | Zero style leakage using scoped CSS variables / Shadow DOM or Tailwind-ready class overrides. |
| **XSS Defense** | Strict HTML escaping in all rendered user fields (names, emails, org names). No `dangerouslySetInnerHTML`. |
| **API Key Scoping** | Distinct key pairs: **Publishable Key** (`pk_live_...` safe for frontend client) vs **Secret Key** (`sk_live_...` strictly backend only). |

---

## 💻 4. Code Architecture & Component Blueprint

```
packages/
├── sdk-go/                 # Go Server SDK
│   ├── client.go
│   ├── users.go
│   ├── orgs.go
│   ├── webhooks.go
│   └── middleware.go
├── sdk-js/                 # Core TypeScript Browser SDK
│   ├── src/
│   │   ├── client.ts
│   │   ├── session.ts
│   │   ├── passkeys.ts
│   │   └── storage.ts
├── react/                  # React UI Component Library
│   ├── src/
│   │   ├── components/
│   │   │   ├── SignIn.tsx
│   │   │   ├── SignUp.tsx
│   │   │   ├── UserProfile.tsx
│   │   │   ├── UserButton.tsx
│   │   │   └── OrgSwitcher.tsx
│   │   ├── hooks/
│   │   │   ├── useAuth.ts
│   │   │   └── useUser.ts
│   │   └── index.ts
└── nextjs/                 # Next.js Server & Edge Adapter
    ├── src/
    │   ├── middleware.ts
    │   └── server.ts
```

---

## 🔌 5. Developer Experience Example

### Go Backend Integration Example
```go
package main

import (
	"net/http"
	"github.com/go-chi/chi/v5"
	"github.com/yourorg/auth/pkg/sdk"
)

func main() {
	authClient, _ := sdk.NewClient(sdk.Config{
		SecretKey: "sk_live_123456789...",
	})

	r := chi.NewRouter()

	// Public route
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello Public"))
	})

	// Protected route group
	r.Group(func(protected chi.Router) {
		protected.Use(authClient.RequireAuth())

		protected.Get("/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
			session := sdk.GetSessionFromContext(r.Context())
			w.Write([]byte("Welcome user: " + session.UserID))
		})
	})

	http.ListenAndServe(":8080", r)
}
```

---

## 🧪 6. Verification & Testing

- **SDK Unit Tests**:
  - Mock HTTP responses and verify correct deserialization of user and organization models.
  - Test middleware token validation and context injection.
- **Frontend Component Tests (Jest / React Testing Library)**:
  - Render `<SignIn />` and verify switching between email/password, social login, and magic link tabs.
  - Verify accessibility (a11y) labels and keyboard navigation.
- **E2E Integration Testing (Playwright)**:
  - Spin up Next.js test application using `@auth/nextjs`.
  - Simulate user login via `<SignIn />` UI -> assert redirect to protected `/dashboard` -> verify session persistence across page refreshes.


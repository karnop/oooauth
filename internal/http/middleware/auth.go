package middleware

import (
	"auth/internal/auth"
	"auth/internal/domain"
	"auth/internal/http/response"
	"context"
	"net/http"
	"strings"
)

type contextKey string

const (
	userContextKey    contextKey = "auth_user"
	sessionContextKey contextKey = "auth_session"
)

type AuthMiddleware struct {
	authService  *auth.Service
	cookieSecure bool
}

func NewAuthMiddleware(authService *auth.Service, cookieSecure bool) *AuthMiddleware {
	return &AuthMiddleware{
		authService:  authService,
		cookieSecure: cookieSecure,
	}
}

// ensures the request has a valid active session
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := m.extractToken(r)
		if token == "" {
			response.Problem(w, r, http.StatusUnauthorized, "Unauthorized", "Missing session token in cookie or Authorization header", "AUTHENTICATION_REQUIRED")
			return
		}

		user, session, err := m.authService.AuthenticateSession(r.Context(), token)
		if err != nil {
			response.Error(w, r, err)
			return
		}

		// injecting authenticated session and user into request context
		ctx := context.WithValue(r.Context(), userContextKey, user)
		ctx = context.WithValue(ctx, sessionContextKey, session)

		next.ServeHTTP(w, r.WithContext(ctx))

	})
}

// helper methods to receive user and session context in downstream handlers
func UserFromContext(ctx context.Context) (*domain.User, bool) {
	u, ok := ctx.Value(userContextKey).(*domain.User)
	return u, ok
}

func SessionFromContext(ctx context.Context) (*domain.Session, bool) {
	s, ok := ctx.Value(sessionContextKey).(*domain.Session)
	return s, ok
}

// inspect cookie first, then fallback to authorization header
func (m *AuthMiddleware) extractToken(r *http.Request) string {
	cookieName := "session_token"
	if m.cookieSecure {
		cookieName = "__Host-session_token"
	}

	if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// fallback - checking session token without prefix if in dev
	if cookie, err := r.Cookie("session_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// fallback - Authorization: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}

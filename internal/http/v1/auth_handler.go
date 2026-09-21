package v1

import (
	"auth/internal/auth"
	"auth/internal/config"
	"auth/internal/http/middleware"
	"auth/internal/http/response"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

type AuthHandler struct {
	authService *auth.Service
	cfg         *config.Config
}

func NewAuthHandler(authService *auth.Service, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		cfg:         cfg,
	}
}

type SignUpRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SessionResponse struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type AuthSuccessResponse struct {
	User    any             `json:"user"`
	Session SessionResponse `json:"session"`
}

// POST v1//auth/sign-up
func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	// limit request payload to 1 mb
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req SignUpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Problem(w, r, http.StatusBadRequest, "Invalid Request Body", "Request payload must be valid JSON", "INVALID_JSON")
		return
	}

	ip := clientIP(r)
	ua := r.UserAgent()

	result, err := h.authService.SignUp(r.Context(), auth.SignUpInput{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		IPAddress: ip,
		UserAgent: &ua,
	})

	if err != nil {
		response.Error(w, r, err)
		return
	}

	// setting httpOnly session cookie
	h.setSessionCookie(w, result.RawToken, h.cfg.SessionTTL)

	response.JSON(w, http.StatusCreated, AuthSuccessResponse{
		User: result.User,
		Session: SessionResponse{
			ID:        result.Session.ID.String(),
			Token:     result.RawToken,
			ExpiresAt: result.Session.ExpiresAt,
		},
	})
}

// POST /v1/auth/sign-in
func (h *AuthHandler) SignIn(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req SignInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Problem(w, r, http.StatusBadRequest, "Invalid Request Body", "Request payload must be valid JSON", "INVALID_JSON")
		return
	}

	ip := clientIP(r)
	ua := r.UserAgent()

	result, err := h.authService.SignIn(r.Context(), auth.SignInInput{
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: ip,
		UserAgent: &ua,
	})

	if err != nil {
		response.Error(w, r, err)
		return
	}

	h.setSessionCookie(w, result.RawToken, h.cfg.SessionTTL)

	response.JSON(w, http.StatusOK, AuthSuccessResponse{
		User: result.User,
		Session: SessionResponse{
			ID:        result.Session.ID.String(),
			Token:     result.RawToken,
			ExpiresAt: result.Session.ExpiresAt,
		},
	})
}

// POST /v1/auth/sign-out
func (h *AuthHandler) SignOut(w http.ResponseWriter, r *http.Request) {
	token := h.extractToken(r)
	if token != "" {
		_ = h.authService.SignOut(r.Context(), token)
	}

	// Expire the cookie in browser
	h.clearSessionCookie(w)

	response.JSON(w, http.StatusOK, map[string]string{
		"message": "successfully signed out",
	})
}

// POST /v1/auth/sign-out-all
func (h *AuthHandler) SignOutAll(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		response.Problem(w, r, http.StatusUnauthorized, "Unauthorized", "User context not found", "UNAUTHORIZED")
		return
	}
	if err := h.authService.SignOutAll(r.Context(), user.ID); err != nil {
		response.Error(w, r, err)
		return
	}

	h.clearSessionCookie(w)

	response.JSON(w, http.StatusOK, map[string]string{
		"message": "successfully revoked all active sessions",
	})
}

// Cookie helpers
func (h *AuthHandler) cookieName() string {
	if h.cfg.CookieSecure {
		return "__Host-session_token"
	}

	return "session_token"
}

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, token string, ttl time.Duration) {
	cookie := &http.Cookie{
		Name:     h.cookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	}

	// Note: __Host- cookies must NOT specify a Domain attribute according to RFC 6265bis
	if !h.cfg.CookieSecure && h.cfg.CookieDomain != "" {
		cookie.Domain = h.cfg.CookieDomain
	}

	http.SetCookie(w, cookie)
}

func (h *AuthHandler) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     h.cookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}

	if !h.cfg.CookieSecure && h.cfg.CookieDomain != "" {
		cookie.Domain = h.cfg.CookieDomain
	}

	http.SetCookie(w, cookie)
}

func (h *AuthHandler) extractToken(r *http.Request) string {
	if cookie, err := r.Cookie(h.cookieName()); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	if cookie, err := r.Cookie("session_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	return ""
}

// clientIP extracts a clean IPv4 or IPv6 address suitable for PostgreSQL INET
func clientIP(r *http.Request) *string {
	var ip string

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip = strings.TrimSpace(parts[0])
	} else if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		ip = strings.TrimSpace(xrip)
	} else {
		// net.SplitHostPort cleanly handles both "[::1]:port" and "127.0.0.1:port"
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			ip = host
		} else {
			ip = r.RemoteAddr
		}
	}

	// Strip IPv6 enclosing brackets if any remain
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")
	if ip == "" {
		return nil
	}

	return &ip
}

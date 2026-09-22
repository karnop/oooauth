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

// magic link and otp requests
type SendMagicLinkRequest struct {
	Email string `json:"email"`
}

type VerifyMagicLinkRequest struct {
	Token string `json:"token"`
}

type SendOTPRequest struct {
	Email string `json:"email"`
}

type VerifyEmailRequest struct {
	Token string `json:"token,omitempty"`
	Email string `json:"email,omitempty"`
	Code  string `json:"code,omitempty"`
}

type VerifyOTPRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
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

// ------- magic link and otp handlers

// POST /v1/auth/magic-link/send
func (h *AuthHandler) SendMagicLink(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req SendMagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Problem(w, r, http.StatusBadRequest, "Invalid Request Body", "Request payload must be valid JSON", "INVALID_JSON")
		return
	}

	ip := clientIP(r)
	ua := r.UserAgent()
	if err := h.authService.SendMagicLink(r.Context(), req.Email, ip, &ua); err != nil {
		response.Error(w, r, err)
		return
	}
	response.JSON(w, http.StatusOK, map[string]string{
		"message": "If an account exists or is eligible, a magic sign-in link has been sent.",
	})

}

// POST & GET /v1/auth/magic-link/verify
func (h *AuthHandler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	var token string
	if r.Method == http.MethodGet {
		token = r.URL.Query().Get("token")
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req VerifyMagicLinkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			response.Problem(w, r, http.StatusBadRequest, "Invalid Request Body", "Request payload must be valid JSON", "INVALID_JSON")
			return
		}
		token = req.Token
	}

	if token == "" {
		response.Problem(w, r, http.StatusBadRequest, "Missing Token", "Verification token is required", "MISSING_TOKEN")
		return
	}

	ip := clientIP(r)
	ua := r.UserAgent()

	result, err := h.authService.VerifyMagicLink(r.Context(), token, ip, &ua)
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

// POST /v1/auth/otp/send
func (h *AuthHandler) SendOTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req SendOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Problem(w, r, http.StatusBadRequest, "Invalid Request Body", "Request payload must be valid JSON", "INVALID_JSON")
		return
	}

	ip := clientIP(r)
	ua := r.UserAgent()

	if err := h.authService.SendOTP(r.Context(), req.Email, ip, &ua); err != nil {
		response.Error(w, r, err)
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"message": "If an account exists, a 6-digit login passcode has been sent.",
	})
}

// POST /v1/auth/otp/verify
func (h *AuthHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req VerifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Problem(w, r, http.StatusBadRequest, "Invalid Request Body", "Request payload must be valid JSON", "INVALID_JSON")
		return
	}

	ip := clientIP(r)
	ua := r.UserAgent()

	result, err := h.authService.VerifyOTP(r.Context(), req.Email, req.Code, ip, &ua)
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

// POST & GET /v1/auth/verify-email
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	// Support query parameter for GET link clicks
	if r.Method == http.MethodGet {
		token := r.URL.Query().Get("token")
		if token == "" {
			response.Problem(w, r, http.StatusBadRequest, "Missing Token", "Verification token is required in query", "MISSING_TOKEN")
			return
		}

		user, err := h.authService.VerifyEmailToken(r.Context(), token)
		if err != nil {
			response.Error(w, r, err)
			return
		}

		response.JSON(w, http.StatusOK, map[string]any{
			"message": "Email successfully verified",
			"user":    user,
		})
		return
	}

	// JSON POST: support either token string OR email + 6-digit code
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Problem(w, r, http.StatusBadRequest, "Invalid Request Body", "Request payload must be valid JSON", "INVALID_JSON")
		return
	}

	if req.Token != "" {
		user, err := h.authService.VerifyEmailToken(r.Context(), req.Token)
		if err != nil {
			response.Error(w, r, err)
			return
		}
		response.JSON(w, http.StatusOK, map[string]any{
			"message": "Email successfully verified",
			"user":    user,
		})
		return
	}

	if req.Email != "" && req.Code != "" {
		user, err := h.authService.VerifyEmailOTP(r.Context(), req.Email, req.Code)
		if err != nil {
			response.Error(w, r, err)
			return
		}
		response.JSON(w, http.StatusOK, map[string]any{
			"message": "Email successfully verified",
			"user":    user,
		})
		return
	}

	response.Problem(w, r, http.StatusBadRequest, "Missing Verification Credentials", "Provide either 'token' or both 'email' and 'code'", "MISSING_CREDENTIALS")
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

package response

import (
	"auth/internal/domain"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

type InvalidParam struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// implements RFC 7807 problem details specification
type ProblemDetails struct {
	Type          string         `json:"type"`
	Title         string         `json:"title"`
	Status        int            `json:"status"`
	Detail        string         `json:"detail"`
	Code          string         `json:"code"`
	Timestamp     time.Time      `json:"timestamp"`
	Instance      string         `json:"instance,omitempty"`
	InvalidParams []InvalidParam `json:"invalid_params,omitempty"`
}

// sends a json response with a status code
func JSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
	}
}

// sends an RFC 7807 compliant problem response
func Problem(w http.ResponseWriter, r *http.Request, status int, title, detail, code string, invalidParams ...InvalidParam) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)

	prob := ProblemDetails{
		Type:          "about:blank",
		Title:         title,
		Status:        status,
		Detail:        detail,
		Code:          code,
		Timestamp:     time.Now().UTC(),
		Instance:      r.URL.Path,
		InvalidParams: invalidParams,
	}

	_ = json.NewEncoder(w).Encode(prob)
}

// Error maps domain errors directly to RFC 7807 HTTP responses
func Error(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		Problem(w, r, http.StatusUnauthorized, "Invalid Credentials", "The email or password provided is incorrect", "INVALID_CREDENTIALS")
	case errors.Is(err, domain.ErrUserAlreadyExists):
		Problem(w, r, http.StatusConflict, "User Conflict", "An account with this email address already exists", "EMAIL_ALREADY_EXISTS")
	case errors.Is(err, domain.ErrUserNotFound):
		Problem(w, r, http.StatusNotFound, "Resource Not Found", "The requested user was not found", "USER_NOT_FOUND")
	case errors.Is(err, domain.ErrSessionNotFound), errors.Is(err, domain.ErrSessionExpired), errors.Is(err, domain.ErrSessionRevoked):
		Problem(w, r, http.StatusUnauthorized, "Unauthorized", "Your session is invalid, revoked, or has expired", "UNAUTHORIZED")
	case errors.Is(err, domain.ErrUserSuspended):
		Problem(w, r, http.StatusForbidden, "Account Suspended", "This user account has been suspended", "USER_SUSPENDED")
	case errors.Is(err, domain.ErrInvalidEmail), errors.Is(err, domain.ErrPasswordTooWeak), errors.Is(err, domain.ErrEmptyField):
		Problem(w, r, http.StatusBadRequest, "Validation Error", err.Error(), "VALIDATION_FAILED")

	// passwordless magic link and otp errors
	case errors.Is(err, domain.ErrTokenNotFound):
		Problem(w, r, http.StatusNotFound, "Token Not Found", "The verification token is invalid or does not exist", "TOKEN_NOT_FOUND")
	case errors.Is(err, domain.ErrTokenExpired):
		Problem(w, r, http.StatusBadRequest, "Token Expired", "The verification token or OTP has expired", "TOKEN_EXPIRED")
	case errors.Is(err, domain.ErrTokenConsumed):
		Problem(w, r, http.StatusConflict, "Token Already Used", "This token has already been verified and cannot be reused", "TOKEN_ALREADY_USED")
	case errors.Is(err, domain.ErrMaxAttemptsExceeded):
		Problem(w, r, http.StatusTooManyRequests, "Max Attempts Exceeded", "Maximum verification attempts exceeded; this code has been permanently invalidated", "MAX_ATTEMPTS_EXCEEDED")
	case errors.Is(err, domain.ErrInvalidOTPCode):
		Problem(w, r, http.StatusBadRequest, "Invalid Code", "The 6-digit verification code is incorrect", "INVALID_OTP_CODE")
	case errors.Is(err, domain.ErrRateLimitExceeded):
		Problem(w, r, http.StatusTooManyRequests, "Rate Limited", "Please wait at least 60 seconds before requesting another code", "RATE_LIMIT_EXCEEDED")

	default:
		// Never leak internal database or server error traces to API callers
		slog.Error("internal server error", "error", err, "path", r.URL.Path)
		Problem(w, r, http.StatusInternalServerError, "Internal Server Error", "An unexpected server error occurred", "INTERNAL_SERVER_ERROR")
	}
}

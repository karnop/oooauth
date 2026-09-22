package domain

import "errors"

var (
	// user domain errors
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("a user with this email already exists")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserSuspended      = errors.New("user account is suspended")
	ErrUserDeleted        = errors.New("user account has been deleted")

	// session domain errors
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session has expired")
	ErrSessionRevoked  = errors.New("session has been revoked")

	// validation domain errors
	ErrInvalidEmail    = errors.New("invalid email address format")
	ErrPasswordTooWeak = errors.New("password does not meet security requirements")
	ErrEmptyField      = errors.New("required field is empty")

	// verifiction, magic link and OTP domain errors
	ErrTokenNotFound       = errors.New("verification token not found")
	ErrTokenExpired        = errors.New("verification token has expired")
	ErrTokenConsumed       = errors.New("verification token has already been used")
	ErrMaxAttemptsExceeded = errors.New("maximum verification attempts exceeded; token has been invalidated")
	ErrInvalidOTPCode      = errors.New("invalid 6-digit verification code")
	ErrRateLimitExceeded   = errors.New("too many requests; please wait before requesting another code")
)

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
)

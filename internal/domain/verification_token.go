package domain

import (
	"time"

	"github.com/google/uuid"
)

type TokenType string

const (
	TokenTypeEmailVerification TokenType = "email_verification"
	TokenTypeMagicLink         TokenType = "magic_link"
	TokenTypeEmailOTP          TokenType = "email_otp"
)

type VerificationToken struct {
	ID            uuid.UUID  `json:"id"`
	UserID        *uuid.UUID `json:"user_id,omitempty"`
	Email         string     `json:"email"`
	TokenType     TokenType  `json:"token_type"`
	TokenHash     string     `json:"-"`
	OTPCodeHash   *string    `json:"-"`
	AttemptsCount int        `json:"attempts_count"`
	MaxAttempts   int        `json:"max_attempts"`
	ExpiresAt     time.Time  `json:"expires_at"`
	ConsumedAt    *time.Time `json:"consumed_at,omitempty"`
	IPAddress     *string    `json:"ip_address,omitempty"`
	UserAgent     *string    `json:"user_agent,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

func (v *VerificationToken) IsExpired() bool {
	return time.Now().UTC().After(v.ExpiresAt)
}

func (v *VerificationToken) IsConsumed() bool {
	return v.ConsumedAt != nil
}

func (v *VerificationToken) IsMaxAttemptsExceeded() bool {
	return v.AttemptsCount >= v.MaxAttempts
}

func (v *VerificationToken) IsValid() bool {
	return !v.IsExpired() && !v.IsConsumed() && !v.IsMaxAttemptsExceeded()
}

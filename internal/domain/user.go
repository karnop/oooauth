package domain

import (
	"time"

	"github.com/google/uuid"
)

type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusDeleted   UserStatus = "deleted"
)

type User struct {
	ID            uuid.UUID  `json:"id"`
	Email         string     `json:"email"`
	EmailVerified bool       `json:"email_verified"`
	PasswordHash  string     `json:"-"` // not sending this to user
	FirstName     string     `json:"first_name"`
	LastName      string     `json:"last_name"`
	AvatarURL     string     `json:"avatar_url"`
	Status        UserStatus `json:"status"`
	SignInCount   int        `json:"sign_in_count"`
	LastSignInAt  *time.Time `json:"last_signin_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// IsActive verifies whether the user is eligible to log in
func (u *User) IsActive() bool {
	return u.Status == UserStatusActive
}

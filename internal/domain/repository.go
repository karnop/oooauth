package domain

import (
	"context"

	"github.com/google/uuid"
)

type UserRepository interface {
	Create(ctx context.Context, user *User) error
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetById(ctx context.Context, id uuid.UUID) (*User, error)
	Update(ctx context.Context, user *User) error
	UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	IncrementSignInCount(ctx context.Context, id uuid.UUID) error
	SetEmailVerified(ctx context.Context, id uuid.UUID, verified bool) error
}

type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	Revoke(ctx context.Context, id uuid.UUID) error
	RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error
	UpdateLastActive(ctx context.Context, id uuid.UUID) error
}

type VerificationTokenRepository interface {
	Create(ctx context.Context, token *VerificationToken) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*VerificationToken, error)
	GetLatestActiveByEmailAndType(ctx context.Context, email string, TokenType TokenType) (*VerificationToken, error)
	IncrementAttempts(ctx context.Context, id uuid.UUID) error
	MarkConsumed(ctx context.Context, id uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

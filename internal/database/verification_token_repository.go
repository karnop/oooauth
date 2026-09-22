package database

import (
	"auth/internal/domain"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ domain.VerificationTokenRepository = (*PostgresVerificationTokenRepository)(nil)

type PostgresVerificationTokenRepository struct {
	pool *pgxpool.Pool
}

func NewVerificationTokenRepository(pool *pgxpool.Pool) *PostgresVerificationTokenRepository {
	return &PostgresVerificationTokenRepository{pool: pool}
}

func (r *PostgresVerificationTokenRepository) Create(ctx context.Context, t *domain.VerificationToken) error {
	query := `
		INSERT INTO verification_tokens (
			id, user_id, email, token_type, token_hash, otp_code_hash,
			attempts_count, max_attempts, expires_at, consumed_at,
			ip_address, user_agent, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
	`
	_, err := r.pool.Exec(
		ctx,
		query,
		t.ID,
		t.UserID,
		t.Email,
		string(t.TokenType),
		t.TokenHash,
		t.OTPCodeHash,
		t.AttemptsCount,
		t.MaxAttempts,
		t.ExpiresAt,
		t.ConsumedAt,
		t.IPAddress,
		t.UserAgent,
		t.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert verification token: %w", err)
	}
	return nil
}

func (r *PostgresVerificationTokenRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.VerificationToken, error) {
	query := `
		SELECT 
			id, user_id, email, token_type, token_hash, otp_code_hash,
			attempts_count, max_attempts, expires_at, consumed_at,
			ip_address::text, user_agent, created_at
		FROM verification_tokens
		WHERE token_hash = $1
	`

	var t domain.VerificationToken
	var tokenTypeStr string

	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&t.ID,
		&t.UserID,
		&t.Email,
		&tokenTypeStr,
		&t.TokenHash,
		&t.OTPCodeHash,
		&t.AttemptsCount,
		&t.MaxAttempts,
		&t.ExpiresAt,
		&t.ConsumedAt,
		&t.IPAddress,
		&t.UserAgent,
		&t.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to query token by hash: %w", err)
	}

	t.TokenType = domain.TokenType(tokenTypeStr)
	return &t, nil
}

// GetLatestActiveByEmailAndType finds the most recent unconsumed token of a specific type for an email.
func (r *PostgresVerificationTokenRepository) GetLatestActiveByEmailAndType(ctx context.Context, email string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	query := `
		SELECT 
			id, user_id, email, token_type, token_hash, otp_code_hash,
			attempts_count, max_attempts, expires_at, consumed_at,
			ip_address::text, user_agent, created_at
		FROM verification_tokens
		WHERE email = $1 AND token_type = $2 AND consumed_at IS NULL
		ORDER BY created_at DESC
		LIMIT 1
	`
	var t domain.VerificationToken
	var tokenTypeStr string

	err := r.pool.QueryRow(ctx, query, email, string(tokenType)).Scan(
		&t.ID,
		&t.UserID,
		&t.Email,
		&tokenTypeStr,
		&t.TokenHash,
		&t.OTPCodeHash,
		&t.AttemptsCount,
		&t.MaxAttempts,
		&t.ExpiresAt,
		&t.ConsumedAt,
		&t.IPAddress,
		&t.UserAgent,
		&t.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrTokenNotFound
		}
		return nil, fmt.Errorf("failed to query active token by email and type: %w", err)
	}

	t.TokenType = domain.TokenType(tokenTypeStr)
	return &t, nil
}

func (r *PostgresVerificationTokenRepository) IncrementAttempts(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE verification_tokens
		SET attempts_count = attempts_count + 1
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment verification attempts: %w", err)
	}

	return nil
}

func (r *PostgresVerificationTokenRepository) MarkConsumed(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE verification_tokens
		SET consumed_at = NOW()
		WHERE id = $1 AND consumed_at IS NULL
	`
	cmdTag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to mark token as consumed: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return domain.ErrTokenConsumed
	}

	return nil
}

func (r *PostgresVerificationTokenRepository) DeleteExpired(ctx context.Context) error {
	query := `
		DELETE FROM verification_tokens
		WHERE expires_at < NOW() OR consumed_at IS NOT NULL
	`

	_, err := r.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	return nil
}

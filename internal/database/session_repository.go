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

// this implements every single method of SessionRepository interface
var _ domain.SessionRepository = (*PostgresSessionRepository)(nil)

type PostgresSessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) *PostgresSessionRepository {
	return &PostgresSessionRepository{pool: pool}
}

func (r *PostgresSessionRepository) Create(ctx context.Context, s *domain.Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, token_hash, ip_address, user_agent, expires_at, revoked_at, last_active_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		)
	`
	_, err := r.pool.Exec(
		ctx,
		query,
		s.ID,
		s.UserID,
		s.TokenHash,
		s.IPAddress,
		s.UserAgent,
		s.ExpiresAt,
		s.RevokedAt,
		s.LastActiveAt,
		s.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert session: %w", err)
	}
	return nil
}
func (r *PostgresSessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	query := `
		SELECT 
			id, user_id, token_hash, ip_address::text, user_agent, expires_at, revoked_at, last_active_at, created_at
		FROM sessions
		WHERE token_hash = $1 AND revoked_at IS NULL
	`
	var s domain.Session
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&s.ID,
		&s.UserID,
		&s.TokenHash,
		&s.IPAddress,
		&s.UserAgent,
		&s.ExpiresAt,
		&s.RevokedAt,
		&s.LastActiveAt,
		&s.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to query session by token hash: %w", err)
	}
	return &s, nil
}
func (r *PostgresSessionRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`
	cmdTag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}
	if cmdTag.RowsAffected() == 0 {
		return domain.ErrSessionNotFound
	}
	return nil
}
func (r *PostgresSessionRepository) RevokeAllByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all sessions for user: %w", err)
	}
	return nil
}
func (r *PostgresSessionRepository) UpdateLastActive(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE sessions
		SET last_active_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to update session activity: %w", err)
	}
	return nil
}

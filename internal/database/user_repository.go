package database

import (
	"auth/internal/domain"
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// this implements every single method of UserRepository interface
var _ domain.UserRepository = (*PostgresUserRepository)(nil)

const (
	// postgres unique violation error code
	pgErrUniqueViolation = "23505"
)

type PostgresUserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{pool: pool}
}

func (r *PostgresUserRepository) Create(ctx context.Context, u *domain.User) error {
	query := `
	INSERT INTO users (id, email, email_verified, password_hash, first_name, last_name, avatar_url, status, sign_in_count, created_at, updated_at) 
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.pool.Exec(ctx, query, u.ID, u.Email, u.EmailVerified, u.PasswordHash, u.FirstName, u.LastName, u.AvatarURL, string(u.Status), u.SignInCount, u.CreatedAt, u.UpdatedAt)

	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgErrUniqueViolation {
			return domain.ErrUserAlreadyExists
		}
		return fmt.Errorf("failed to insert user: %w", err)
	}
	return nil
}

func (r *PostgresUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
	SELECT id, email, email_verified, password_hash, COALESCE(first_name, ''), COALESCE(last_name, ''), avatar_url, status, sign_in_count, last_sign_in_at, created_at, updated_at
	FROM users 
	WHERE email = $1`

	var u domain.User
	var statusStr string
	err := r.pool.QueryRow(ctx, query, email).Scan(
		&u.ID, &u.Email, &u.EmailVerified, &u.PasswordHash, &u.FirstName, &u.LastName, &u.AvatarURL, &statusStr, &u.SignInCount, &u.LastSignInAt, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	u.Status = domain.UserStatus(statusStr)
	return &u, nil
}

func (r *PostgresUserRepository) GetById(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
	SELECT id, email, email_verified, password_hash, COALESCE(first_name, ''), COALESCE(last_name, ''), avatar_url, status, sign_in_count, last_sign_in_at, created_at, updated_at
	FROM users 
	WHERE id = $1`

	var u domain.User
	var statusStr string
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&u.ID, &u.Email, &u.EmailVerified, &u.PasswordHash, &u.FirstName, &u.LastName, &u.AvatarURL, &statusStr, &u.SignInCount, &u.LastSignInAt, &u.CreatedAt, &u.UpdatedAt)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	u.Status = domain.UserStatus(statusStr)
	return &u, nil
}

func (r *PostgresUserRepository) Update(ctx context.Context, u *domain.User) error {
	query := `
	UPDATE users 
	SET first_name = $1, last_name = $2, avatar_url = $3, updated_at = NOW()
	WHERE id = $4`

	cmdTag, err := r.pool.Exec(ctx, query, u.FirstName, u.LastName, u.AvatarURL, u.ID)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (r *PostgresUserRepository) UpdatePassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	query := `
	UPDATE users 
	SET password_hash = $1, updated_at = NOW()
	WHERE id = $2`

	cmdTag, err := r.pool.Exec(ctx, query, passwordHash, id)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (r *PostgresUserRepository) IncrementSignInCount(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET sign_in_count = sign_in_count + 1, last_sign_in_at = NOW(), updated_at = NOW()
		WHERE id = $1
	`
	cmdTag, err := r.pool.Exec(ctx, query, id)

	if err != nil {
		return fmt.Errorf("failed to increment sign in count: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

func (r *PostgresUserRepository) SetEmailVerified(ctx context.Context, id uuid.UUID, verified bool) error {
	query := `
		UPDATE users 
		SET email_verified = $1, updated_at = NOW() 
		WHERE id = $2
	`

	cmdTag, err := r.pool.Exec(ctx, query, verified, id)

	if err != nil {
		return fmt.Errorf("failed to set email verified: %w", err)
	}

	if cmdTag.RowsAffected() == 0 {
		return domain.ErrUserNotFound
	}

	return nil
}

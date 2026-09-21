package auth

import (
	"auth/internal/config"
	"auth/internal/domain"
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Service struct {
	userRepo    domain.UserRepository
	sessionRepo domain.SessionRepository
	cfg         *config.Config
}

func NewService(userRepo domain.UserRepository, sessionRepo domain.SessionRepository, cfg *config.Config) *Service {
	return &Service{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		cfg:         cfg,
	}
}

// DTO (Data transfer objects) for service inputs and outputs
type SignUpInput struct {
	Email     string
	Password  string
	FirstName string
	LastName  string
	IPAddress *string
	UserAgent *string
}

type SignInInput struct {
	Email     string
	Password  string
	IPAddress *string
	UserAgent *string
}

type AuthResult struct {
	User     *domain.User
	Session  *domain.Session
	RawToken string
}

// signup registers a new user, hashes their password with Argon2id, and immediately issues an active session
func (s *Service) SignUp(ctx context.Context, input SignUpInput) (*AuthResult, error) {
	email := normalizeEmail(input.Email)
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	if err := ValidatePasswordStrength(input.Password); err != nil {
		return nil, fmt.Errorf("%w: %s", domain.ErrPasswordTooWeak, err.Error())
	}

	argonParams := Argon2Params{
		Memory:      s.cfg.Argon2Memory,
		Iterations:  s.cfg.Argon2Time,
		Parallelism: s.cfg.Argon2Threads,
		SaltLength:  16,
		KeyLength:   32,
	}

	passwordHash, err := HashPassword(input.Password, argonParams)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:            uuid.New(),
		Email:         email,
		EmailVerified: false,
		PasswordHash:  passwordHash,
		FirstName:     input.FirstName,
		LastName:      input.LastName,
		AvatarURL:     "",
		Status:        domain.UserStatusActive,
		SignInCount:   1,
		LastSignInAt:  &now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	// creating initial session for the newly registered user
	rawToken, tokenHash, err := GenerateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	session := &domain.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		TokenHash:    tokenHash,
		IPAddress:    input.IPAddress,
		UserAgent:    input.UserAgent,
		ExpiresAt:    now.Add(s.cfg.SessionTTL),
		RevokedAt:    nil,
		LastActiveAt: now,
		CreatedAt:    now,
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to persist session: %w", err)
	}

	return &AuthResult{
		User:     user,
		Session:  session,
		RawToken: rawToken,
	}, nil
}

// verifies user credentials with timing attack mitigation and issues a new session
func (s *Service) SignIn(ctx context.Context, input SignInInput) (*AuthResult, error) {
	email := normalizeEmail(input.Email)
	if err := validateEmail(email); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			_, _ = VerifyPassword(input.Password, DummyHash)
			return nil, domain.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("database query error during sign-in :%w", err)
	}

	// verify account status
	if user.Status == domain.UserStatusSuspended {
		return nil, domain.ErrUserSuspended
	}

	if user.Status == domain.UserStatusDeleted {
		return nil, domain.ErrUserDeleted
	}

	// verify password in constant time
	match, err := VerifyPassword(input.Password, user.PasswordHash)
	if err != nil || !match {
		return nil, domain.ErrInvalidCredentials
	}

	// tracking login stat
	_ = s.userRepo.IncrementSignInCount(ctx, user.ID)

	// issuing new session
	now := time.Now().UTC()
	rawToken, tokenHash, err := GenerateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	session := &domain.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		TokenHash:    tokenHash,
		IPAddress:    input.IPAddress,
		UserAgent:    input.UserAgent,
		ExpiresAt:    now.Add(s.cfg.SessionTTL),
		RevokedAt:    nil,
		LastActiveAt: now,
		CreatedAt:    now,
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to persist session %w", err)
	}

	return &AuthResult{
		User:     user,
		Session:  session,
		RawToken: rawToken,
	}, nil
}

// verifies a raw session token, updates its last active timestamp
func (s *Service) AuthenticateSession(ctx context.Context, rawToken string) (*domain.User, *domain.Session, error) {
	tokenHash := HashSessionToken(rawToken)
	session, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)

	if err != nil {
		return nil, nil, err
	}

	if !session.IsValid() {
		return nil, nil, domain.ErrSessionExpired
	}

	user, err := s.userRepo.GetById(ctx, session.UserID)
	if err != nil {
		return nil, nil, err
	}

	if !user.IsActive() {
		return nil, nil, domain.ErrUserSuspended
	}

	// Update last active timestamp asynchronously or synchronously
	_ = s.sessionRepo.UpdateLastActive(ctx, session.ID)
	return user, session, nil
}

// SignOut revokes the current active session.
func (s *Service) SignOut(ctx context.Context, rawToken string) error {
	tokenHash := HashSessionToken(rawToken)
	session, err := s.sessionRepo.GetByTokenHash(ctx, tokenHash)

	if err != nil {
		if errors.Is(err, domain.ErrSessionNotFound) {
			return nil // Idempotent sign-out: already revoked or expired
		}
		return err
	}

	return s.sessionRepo.Revoke(ctx, session.ID)
}

// SignOutAll revokes every session belonging to the user.
func (s *Service) SignOutAll(ctx context.Context, userID uuid.UUID) error {
	return s.sessionRepo.RevokeAllByUserID(ctx, userID)
}

// UpdateProfile updates user profile attributes.
func (s *Service) UpdateProfile(ctx context.Context, userID uuid.UUID, firstName, lastName, avatarURL string) (*domain.User, error) {
	user, err := s.userRepo.GetById(ctx, userID)

	if err != nil {
		return nil, err
	}

	user.FirstName = firstName
	user.LastName = lastName
	user.AvatarURL = avatarURL

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// ChangePassword verifies the old password, hashes the new one, and revokes all other sessions.
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error {
	user, err := s.userRepo.GetById(ctx, userID)
	if err != nil {
		return err
	}

	match, err := VerifyPassword(currentPassword, user.PasswordHash)
	if err != nil || !match {
		return domain.ErrInvalidCredentials
	}

	if err := ValidatePasswordStrength(newPassword); err != nil {
		return fmt.Errorf("%w: %s", domain.ErrPasswordTooWeak, err.Error())
	}

	argonParams := Argon2Params{
		Memory:      s.cfg.Argon2Memory,
		Iterations:  s.cfg.Argon2Time,
		Parallelism: s.cfg.Argon2Threads,
		SaltLength:  16,
		KeyLength:   32,
	}

	newHash, err := HashPassword(newPassword, argonParams)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	if err := s.userRepo.UpdatePassword(ctx, userID, newHash); err != nil {
		return err
	}

	// Security requirement: Revoke all other active sessions when password changes
	_ = s.sessionRepo.RevokeAllByUserID(ctx, userID)

	return nil
}

// Helper validation functions
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func validateEmail(email string) error {
	if email == "" {
		return domain.ErrEmptyField
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return domain.ErrInvalidEmail
	}

	if addr.Address != email {
		return domain.ErrInvalidEmail
	}

	return nil
}

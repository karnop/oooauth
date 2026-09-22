package auth

import (
	"auth/internal/config"
	"auth/internal/domain"
	"auth/internal/mailer"
	"context"
	"crypto/subtle"
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
	tokenRepo   domain.VerificationTokenRepository
	mailer      mailer.Mailer
	cfg         *config.Config
}

func NewService(
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	tokenRepo domain.VerificationTokenRepository,
	mailer mailer.Mailer,
	cfg *config.Config,
) *Service {
	return &Service{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		tokenRepo:   tokenRepo,
		mailer:      mailer,
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

// signup registers a new user, hashes their password with Argon2id, issues an active session and asynchronously dispatches an email verification link + otp
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

	// asynchronously dispatching verification email so signup returns in sun 100ms
	go func() {
		_ = s.SendEmailVerification(context.Background(), user.ID, user.Email, input.IPAddress, input.UserAgent)
	}()

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

// ------------ MAGIC LINK AND OTP LOGIC
func (s *Service) SendEmailVerification(ctx context.Context, userID uuid.UUID, email string, ip, userAgent *string) error {
	rawToken, tokenHash, err := GenerateMagicLinkToken(EmailVerifyPrefix)
	if err != nil {
		return err
	}

	rawOTP, otpHash, err := GenerateSecureOTP(6)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:            uuid.New(),
		UserID:        &userID,
		Email:         email,
		TokenType:     domain.TokenTypeEmailVerification,
		TokenHash:     tokenHash,
		OTPCodeHash:   &otpHash,
		AttemptsCount: 0,
		MaxAttempts:   5,
		ExpiresAt:     now.Add(24 * time.Hour), // 24-hour verification window
		ConsumedAt:    nil,
		IPAddress:     ip,
		UserAgent:     userAgent,
		CreatedAt:     now,
	}
	if err := s.tokenRepo.Create(ctx, token); err != nil {
		return err
	}
	return s.mailer.SendEmailVerification(ctx, email, rawToken, rawOTP)
}

// VerifyEmailToken marks email as verified when user clicks link.
func (s *Service) VerifyEmailToken(ctx context.Context, rawToken string) (*domain.User, error) {
	tokenHash := HashVerificationToken(rawToken)

	token, err := s.tokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	if token.TokenType != domain.TokenTypeEmailVerification {
		return nil, domain.ErrTokenNotFound
	}
	if token.IsConsumed() {
		return nil, domain.ErrTokenConsumed
	}
	if token.IsExpired() {
		return nil, domain.ErrTokenExpired
	}
	if err := s.tokenRepo.MarkConsumed(ctx, token.ID); err != nil {
		return nil, err
	}

	if token.UserID != nil {
		if err := s.userRepo.SetEmailVerified(ctx, *token.UserID, true); err != nil {
			return nil, err
		}
		return s.userRepo.GetById(ctx, *token.UserID)
	}

	return nil, domain.ErrUserNotFound
}

// VerifyEmailOTP marks email as verified when user submits 6-digit code.
func (s *Service) VerifyEmailOTP(ctx context.Context, email, code string) (*domain.User, error) {
	email = normalizeEmail(email)

	token, err := s.tokenRepo.GetLatestActiveByEmailAndType(ctx, email, domain.TokenTypeEmailVerification)
	if err != nil {
		return nil, err
	}

	if token.IsConsumed() {
		return nil, domain.ErrTokenConsumed
	}
	if token.IsExpired() {
		return nil, domain.ErrTokenExpired
	}
	if token.IsMaxAttemptsExceeded() {
		return nil, domain.ErrMaxAttemptsExceeded
	}

	_ = s.tokenRepo.IncrementAttempts(ctx, token.ID)
	codeHash := HashVerificationToken(code)
	if token.OTPCodeHash == nil || subtle.ConstantTimeCompare([]byte(codeHash), []byte(*token.OTPCodeHash)) != 1 {
		if token.AttemptsCount+1 >= token.MaxAttempts {
			return nil, domain.ErrMaxAttemptsExceeded
		}
		return nil, domain.ErrInvalidOTPCode
	}

	if err := s.tokenRepo.MarkConsumed(ctx, token.ID); err != nil {
		return nil, err
	}

	if token.UserID != nil {
		if err := s.userRepo.SetEmailVerified(ctx, *token.UserID, true); err != nil {
			return nil, err
		}
		return s.userRepo.GetById(ctx, *token.UserID)
	}

	return nil, domain.ErrUserNotFound
}

// SendMagicLink issues a single-use login link. Anti-enumeration: always returns nil error to caller.
func (s *Service) SendMagicLink(ctx context.Context, email string, ip, userAgent *string) error {
	email = normalizeEmail(email)
	if err := validateEmail(email); err != nil {
		return nil // Anti-enumeration: won't reveal invalid syntax to attackers
	}

	// 60-second cooldown rate limit check
	latest, err := s.tokenRepo.GetLatestActiveByEmailAndType(ctx, email, domain.TokenTypeMagicLink)
	if err == nil && latest != nil && time.Since(latest.CreatedAt) < 60*time.Second {
		return domain.ErrRateLimitExceeded
	}

	rawToken, tokenHash, err := GenerateMagicLinkToken(MagicLinkTokenPrefix)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:            uuid.New(),
		Email:         email,
		TokenType:     domain.TokenTypeMagicLink,
		TokenHash:     tokenHash,
		OTPCodeHash:   nil,
		AttemptsCount: 0,
		MaxAttempts:   5,
		ExpiresAt:     now.Add(15 * time.Minute), // 15-minute expiration
		ConsumedAt:    nil,
		IPAddress:     ip,
		UserAgent:     userAgent,
		CreatedAt:     now,
	}

	// Link user_id if user already exists
	if user, err := s.userRepo.GetByEmail(ctx, email); err == nil && user != nil {
		token.UserID = &user.ID
	}

	if err := s.tokenRepo.Create(ctx, token); err != nil {
		return err
	}

	return s.mailer.SendMagicLink(ctx, email, rawToken)
}

// VerifyMagicLink validates the link, handles JIT user creation, and issues a session.
func (s *Service) VerifyMagicLink(ctx context.Context, rawToken string, ip, userAgent *string) (*AuthResult, error) {
	tokenHash := HashVerificationToken(rawToken)
	token, err := s.tokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, domain.ErrTokenNotFound
	}

	if token.TokenType != domain.TokenTypeMagicLink {
		return nil, domain.ErrTokenNotFound
	}

	if token.IsConsumed() {
		return nil, domain.ErrTokenConsumed
	}
	if token.IsExpired() {
		return nil, domain.ErrTokenExpired
	}

	if err := s.tokenRepo.MarkConsumed(ctx, token.ID); err != nil {
		return nil, err
	}

	// Find or JIT (Just-In-Time) create user
	user, err := s.userRepo.GetByEmail(ctx, token.Email)
	now := time.Now().UTC()
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// JIT Provisioning: User signed in via Magic Link for the first time
			user = &domain.User{
				ID:            uuid.New(),
				Email:         token.Email,
				EmailVerified: true, // Proved possession of email
				PasswordHash:  "",   // Passwordless account
				FirstName:     "",
				LastName:      "",
				AvatarURL:     "",
				Status:        domain.UserStatusActive,
				SignInCount:   1,
				LastSignInAt:  &now,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			if err := s.userRepo.Create(ctx, user); err != nil {
				return nil, fmt.Errorf("failed to create user: %w", err)
			}
		} else {
			return nil, err
		}
	} else {
		// Existing user: mark email verified and bump sign-in count
		_ = s.userRepo.SetEmailVerified(ctx, user.ID, true)
		_ = s.userRepo.IncrementSignInCount(ctx, user.ID)
		user.EmailVerified = true
	}

	if !user.IsActive() {
		return nil, domain.ErrUserSuspended
	}
	// Issue active session
	rawSessionToken, sessionTokenHash, err := GenerateSessionToken()
	if err != nil {
		return nil, err
	}

	session := &domain.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		TokenHash:    sessionTokenHash,
		IPAddress:    ip,
		UserAgent:    userAgent,
		ExpiresAt:    now.Add(s.cfg.SessionTTL),
		RevokedAt:    nil,
		LastActiveAt: now,
		CreatedAt:    now,
	}
	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	return &AuthResult{
		User:     user,
		Session:  session,
		RawToken: rawSessionToken,
	}, nil
}

// SendOTP generates a 6-digit passcode and sends it.
func (s *Service) SendOTP(ctx context.Context, email string, ip, userAgent *string) error {
	email = normalizeEmail(email)
	if err := validateEmail(email); err != nil {
		return nil // Anti-enumeration
	}

	latest, err := s.tokenRepo.GetLatestActiveByEmailAndType(ctx, email, domain.TokenTypeEmailOTP)
	if err == nil && latest != nil && time.Since(latest.CreatedAt) < 60*time.Second {
		return domain.ErrRateLimitExceeded
	}

	otpCode, otpHash, err := GenerateSecureOTP(6)
	if err != nil {
		return err
	}

	// Generate a unique token hash to satisfy database UNIQUE constraint
	_, tokenHash, err := GenerateMagicLinkToken("otp_")
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:            uuid.New(),
		Email:         email,
		TokenType:     domain.TokenTypeEmailOTP,
		TokenHash:     tokenHash,
		OTPCodeHash:   &otpHash,
		AttemptsCount: 0,
		MaxAttempts:   5,
		ExpiresAt:     now.Add(10 * time.Minute), // 10-minute OTP expiration
		ConsumedAt:    nil,
		IPAddress:     ip,
		UserAgent:     userAgent,
		CreatedAt:     now,
	}

	if user, err := s.userRepo.GetByEmail(ctx, email); err == nil && user != nil {
		token.UserID = &user.ID
	}

	if err := s.tokenRepo.Create(ctx, token); err != nil {
		return err
	}

	return s.mailer.SendOTP(ctx, email, otpCode)
}

// VerifyOTP checks the 6-digit code against stored hash with brute-force lockout.
func (s *Service) VerifyOTP(ctx context.Context, email, code string, ip, userAgent *string) (*AuthResult, error) {
	email = normalizeEmail(email)
	token, err := s.tokenRepo.GetLatestActiveByEmailAndType(ctx, email, domain.TokenTypeEmailOTP)
	if err != nil {
		return nil, domain.ErrTokenNotFound
	}

	if token.IsConsumed() {
		return nil, domain.ErrTokenConsumed
	}
	if token.IsExpired() {
		return nil, domain.ErrTokenExpired
	}
	if token.IsMaxAttemptsExceeded() {
		return nil, domain.ErrMaxAttemptsExceeded
	}

	_ = s.tokenRepo.IncrementAttempts(ctx, token.ID)
	codeHash := HashVerificationToken(code)
	if token.OTPCodeHash == nil || subtle.ConstantTimeCompare([]byte(codeHash), []byte(*token.OTPCodeHash)) != 1 {
		if token.AttemptsCount+1 >= token.MaxAttempts {
			return nil, domain.ErrMaxAttemptsExceeded
		}

		return nil, domain.ErrInvalidOTPCode
	}

	if err := s.tokenRepo.MarkConsumed(ctx, token.ID); err != nil {
		return nil, err
	}

	// Find or JIT create user
	user, err := s.userRepo.GetByEmail(ctx, token.Email)
	now := time.Now().UTC()
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			user = &domain.User{
				ID:            uuid.New(),
				Email:         token.Email,
				EmailVerified: true,
				PasswordHash:  "",
				FirstName:     "",
				LastName:      "",
				AvatarURL:     "",
				Status:        domain.UserStatusActive,
				SignInCount:   1,
				LastSignInAt:  &now,
				CreatedAt:     now,
				UpdatedAt:     now,
			}
			if err := s.userRepo.Create(ctx, user); err != nil {
				return nil, fmt.Errorf("failed to JIT create user: %w", err)
			}
		} else {
			return nil, err
		}
	} else {
		_ = s.userRepo.SetEmailVerified(ctx, user.ID, true)
		_ = s.userRepo.IncrementSignInCount(ctx, user.ID)
		user.EmailVerified = true
	}
	if !user.IsActive() {
		return nil, domain.ErrUserSuspended
	}

	rawSessionToken, sessionTokenHash, err := GenerateSessionToken()
	if err != nil {
		return nil, err
	}

	session := &domain.Session{
		ID:           uuid.New(),
		UserID:       user.ID,
		TokenHash:    sessionTokenHash,
		IPAddress:    ip,
		UserAgent:    userAgent,
		ExpiresAt:    now.Add(s.cfg.SessionTTL),
		RevokedAt:    nil,
		LastActiveAt: now,
		CreatedAt:    now,
	}
	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	return &AuthResult{
		User:     user,
		Session:  session,
		RawToken: rawSessionToken,
	}, nil
}

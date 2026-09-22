package mailer

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

type DevMailer struct {
	frontendURL string
}

func NewDevMailer(frontendURL string) *DevMailer {
	return &DevMailer{
		frontendURL: strings.TrimRight(frontendURL, "/"),
	}
}

func (m *DevMailer) SendEmailVerification(ctx context.Context, toEmail, rawToken, otpCode string) error {
	verifyURL := fmt.Sprintf("%s/v1/auth/verify-email?token=%s", m.frontendURL, rawToken)
	banner := fmt.Sprintf(`
	================================================================================
	📧 [DEV MAILER] EMAIL VERIFICATION
	To: %s
	--------------------------------------------------------------------------------
	Click to verify your email:
	👉 %s
	Or enter your 6-digit verification code:
	┌──────────────────────────────────────────────┐
	│                    %s                    │
	└──────────────────────────────────────────────┘
	(Valid for 15 minutes)
	================================================================================`, toEmail, verifyURL, otpCode)
	fmt.Println(banner)
	slog.Info("email verification sent (dev)", "to", toEmail)
	return nil
}

func (m *DevMailer) SendMagicLink(ctx context.Context, toEmail, rawToken string) error {
	magicURL := fmt.Sprintf("%s/v1/auth/magic-link/verify?token=%s", m.frontendURL, rawToken)
	banner := fmt.Sprintf(`
	================================================================================
	✨ [DEV MAILER] MAGIC SIGN-IN LINK
	To: %s
	--------------------------------------------------------------------------------
	Click the link below to sign in instantly (no password required):
	👉 %s
	(Valid for 15 minutes. Single-use only.)
	================================================================================`, toEmail, magicURL)
	fmt.Println(banner)
	slog.Info("magic link sent (dev)", "to", toEmail)
	return nil
}

func (m *DevMailer) SendOTP(ctx context.Context, toEmail, otpCode string) error {
	banner := fmt.Sprintf(`
	================================================================================
	🔐 [DEV MAILER] ONE-TIME LOGIN CODE (OTP)
	To: %s
	--------------------------------------------------------------------------------
	Your 6-digit login passcode is:
	┌──────────────────────────────────────────────┐
	│                    %s                    │
	└──────────────────────────────────────────────┘
	(Valid for 10 minutes. Maximum 5 attempts.)
	================================================================================`, toEmail, otpCode)
	fmt.Println(banner)
	slog.Info("OTP sent (dev)", "to", toEmail)
	return nil
}

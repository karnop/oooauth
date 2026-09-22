package mailer

import "context"

type Mailer interface {
	SendEmailVerification(ctx context.Context, toEmail, rawToken, otpCode string) error
	SendMagicLink(ctx context.Context, toEmail, rawToken string) error
	SendOTP(ctx context.Context, toEmail, otpCode string) error
}

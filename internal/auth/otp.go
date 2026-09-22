package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	MagicLinkTokenPrefix = "mlk_"
	EmailVerifyPrefix    = "emv_"
)

// generates a cryptographically secure n-digit numeric string
func GenerateSecureOTP(digits int) (rawOTP string, otpHash string, err error) {
	if digits <= 0 || digits > 10 {
		digits = 6
	}

	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate random OTP: %w", err)
	}

	format := fmt.Sprintf("%%0%dd", digits)
	rawOTP = fmt.Sprintf(format, n.Int64())
	otpHash = HashVerificationToken(rawOTP)

	return rawOTP, otpHash, nil
}

// produces a rawToken sent in the email link
// tokenhash stored in the db
func GenerateMagicLinkToken(prefix string) (rawToken string, tokenhash string, err error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("failed to generate magic link token: %w", err)
	}

	rawToken = prefix + base64.RawURLEncoding.EncodeToString(bytes)
	tokenhash = HashVerificationToken(rawToken)

	return rawToken, tokenhash, nil
}

func HashVerificationToken(raw string) string {
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

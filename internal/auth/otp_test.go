package auth

import (
	"strconv"
	"strings"
	"testing"
)

func TestGenerateSecureOTP(t *testing.T) {
	otp, _, err := GenerateSecureOTP(6)
	if err != nil {
		t.Fatalf("GenerateSecureOTP failed: %v", err)
	}

	if len(otp) != 6 {
		t.Errorf("expected 6 digits, got %d (%q)", len(otp), otp)
	}

	// Verify all characters are digits
	if _, err := strconv.Atoi(otp); err != nil {
		t.Errorf("expected numeric string, got non-digit characters in %q", otp)
	}
}

func TestGenerateMagicLinkToken(t *testing.T) {
	rawToken, tokenHash, err := GenerateMagicLinkToken(MagicLinkTokenPrefix)
	if err != nil {
		t.Fatalf("GenerateMagicLinkToken failed: %v", err)
	}

	if !strings.HasPrefix(rawToken, MagicLinkTokenPrefix) {
		t.Errorf("expected token to start with %q, got %q", MagicLinkTokenPrefix, rawToken)
	}

	if len(tokenHash) != 64 {
		t.Errorf("expected 64 character SHA-256 hash, got %d", len(tokenHash))
	}
}

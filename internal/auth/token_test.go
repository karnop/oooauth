package auth

import (
	"strings"
	"testing"
)

func TestGenerateSessionToken(t *testing.T) {
	rawToken, tokenHash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken failed: %v", err)
	}

	if !strings.HasPrefix(rawToken, SessionTokenPrefix) {
		t.Errorf("expected token to start with %q, got %q", SessionTokenPrefix, rawToken)
	}

	if len(tokenHash) != 64 { // SHA-256 hex string is exactly 64 chars
		t.Errorf("expected SHA-256 token hash to be 64 characters, got %d", len(tokenHash))
	}

	// HashSessionToken idempotency
	recalculatedHash := HashSessionToken(rawToken)
	if recalculatedHash != tokenHash {
		t.Errorf("expected HashSessionToken to match generated tokenHash")
	}
}

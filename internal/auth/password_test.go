package auth

import (
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	password := "SecurePassword123!"

	// Fast test parameters to keep test suite snappy
	testParams := Argon2Params{
		Memory:      16 * 1024,
		Iterations:  1,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := HashPassword(password, testParams)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Verify with correct password
	match, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
	if !match {
		t.Errorf("expected password to verify successfully")
	}

	// Verify with wrong password
	wrongMatch, err := VerifyPassword("WrongPassword123!", hash)
	if err != nil {
		t.Fatalf("VerifyPassword failed on mismatch check: %v", err)
	}
	if wrongMatch {
		t.Errorf("expected mismatch, but password verified")
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid strong password", "P@ssw0rd2026!", false},
		{"too short", "Pass1!", true},
		{"no uppercase", "password123!", true},
		{"no lowercase", "PASSWORD123!", true},
		{"no number", "Password!!!!", true},
		{"no special char", "Password1234", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordStrength(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordStrength(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
		})
	}
}

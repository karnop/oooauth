package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	SessionTokenBytes  = 32
	SessionTokenPrefix = "sess_"
)

func GenerateSessionToken() (rawToken string, tokenHash string, err error) {
	bytes := make([]byte, SessionTokenBytes)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("failed to read random bytes for session token: %w", err)
	}

	// RawURLEncoding avoids +, /, = and makes the cookie URL safe
	rawToken = SessionTokenPrefix + base64.RawURLEncoding.EncodeToString(bytes)
	tokenHash = HashSessionToken(rawToken)

	return rawToken, tokenHash, nil
}

func HashSessionToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}

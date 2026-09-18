package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port           string
	Environment    string
	DatabaseURL    string
	SessionTTL     time.Duration
	CookieSecure   bool
	CookieDomain   string
	AllowedOrigins []string
	Argon2Memory   uint32
	Argon2Time     uint32
	Argon2Threads  uint8
}

func Load() (*Config, error) {
	port := getEnv("PORT", "8080")
	env := getEnv("ENV", "development")
	dbURL := getEnv("DATABASE_URL", "")

	sessionTTLHours, err := strconv.Atoi(getEnv("SESSION_TTL_HOURS", "720"))
	if err != nil {
		return nil, fmt.Errorf("invalid SESSION_TTL_HOURS: %w", err)
	}

	cookieDomain := getEnv("COOKIE_DOMAIN", "")
	cookieSecure := env == "production"
	allowedOrigins := []string{getEnv("FRONTEND_URL", "http://localhost:3000")}

	return &Config{
		Port:           port,
		Environment:    env,
		DatabaseURL:    dbURL,
		SessionTTL:     time.Duration(sessionTTLHours) * time.Hour,
		CookieSecure:   cookieSecure,
		CookieDomain:   cookieDomain,
		AllowedOrigins: allowedOrigins,
		Argon2Memory:   64 * 1024, // 64MB
		Argon2Time:     3,         // 3 iterations
		Argon2Threads:  4,         // 4 parallel threads
	}, nil
}

func getEnv(key, defaultValue string) string {
	if val, exists := os.LookupEnv(key); exists && val != "" {
		return val
	}
	return defaultValue
}

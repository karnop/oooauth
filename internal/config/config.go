package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
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
	// Auto-load .env file if present in the working directory
	if err := loadEnvFile(".env"); err != nil {
		return nil, fmt.Errorf("failed to load env file: %w", err)
	}

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

// loadEnvFile parses key=value pairs from a .env file without overriding existing system envs
func loadEnvFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File does not exist, fall back to system environment variables
		}
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`) // Strip quotation marks if present
			if _, exists := os.LookupEnv(key); !exists {
				_ = os.Setenv(key, val)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading %s: %w", filename, err)
	}

	return nil
}

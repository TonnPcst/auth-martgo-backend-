package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env                string
	HTTPAddr           string
	LogLevel           slog.Level
	DatabaseURL        string
	RedisURL           string
	JWTPrivateKeyFile  string
	JWTTTL             time.Duration
	ShutdownTimeout    time.Duration
	TrustProxy         bool
	EnableDocs         bool
	CORSAllowedOrigins []string
	SMSProvider        string
	TelbizURL          string
	TelbizClientID     string
	TelbizSecret       string
}

func Load() (Config, error) {
	cfg := Config{
		Env:               getEnv("APP_ENV", "development"),
		HTTPAddr:          getEnv("HTTP_ADDR", ":8081"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		RedisURL:          getEnv("REDIS_URL", "redis://localhost:6380/0"),
		JWTPrivateKeyFile: getEnv("JWT_PRIVATE_KEY_FILE", "keys/jwt_private.pem"),
		SMSProvider:       getEnv("SMS_PROVIDER", "log"),
		TelbizURL:         getEnv("TELBIZ_URL", "https://api.telbiz.la"),
		TelbizClientID:    getEnv("TELBIZ_CLIENT_ID", ""),
		TelbizSecret:      getEnv("TELBIZ_SECRET", ""),
	}

	var errs []error
	if cfg.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}

	var err error
	if cfg.JWTTTL, err = time.ParseDuration(getEnv("JWT_TTL", "24h")); err != nil {
		errs = append(errs, fmt.Errorf("JWT_TTL: %w", err))
	}
	if cfg.ShutdownTimeout, err = time.ParseDuration(getEnv("SHUTDOWN_TIMEOUT", "10s")); err != nil {
		errs = append(errs, fmt.Errorf("SHUTDOWN_TIMEOUT: %w", err))
	}
	if err = cfg.LogLevel.UnmarshalText([]byte(getEnv("LOG_LEVEL", "info"))); err != nil {
		errs = append(errs, fmt.Errorf("LOG_LEVEL: %w", err))
	}
	if cfg.TrustProxy, err = getBool("TRUST_PROXY", false); err != nil {
		errs = append(errs, err)
	}
	if cfg.EnableDocs, err = getBool("ENABLE_DOCS", cfg.Env != "production"); err != nil {
		errs = append(errs, err)
	}
	cfg.CORSAllowedOrigins = splitList(os.Getenv("CORS_ALLOWED_ORIGINS"))

	if cfg.Env == "production" && strings.Contains(cfg.DatabaseURL, "sslmode=disable") {
		errs = append(errs, errors.New("DATABASE_URL must not use sslmode=disable in production"))
	}
	switch cfg.SMSProvider {
	case "log":
		if cfg.Env == "production" {
			errs = append(errs, errors.New("SMS_PROVIDER=log writes login codes to the log and is not allowed in production"))
		}
	case "telbiz":
		if cfg.TelbizClientID == "" || cfg.TelbizSecret == "" {
			errs = append(errs, errors.New("TELBIZ_CLIENT_ID and TELBIZ_SECRET are required when SMS_PROVIDER=telbiz"))
		}
	default:
		errs = append(errs, fmt.Errorf("SMS_PROVIDER must be log or telbiz, got %q", cfg.SMSProvider))
	}

	return cfg, errors.Join(errs...)
}

// getEnv trims whitespace because make keeps trailing spaces from .env lines.
func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getBool(key string, fallback bool) (bool, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false", key)
	}
	return b, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

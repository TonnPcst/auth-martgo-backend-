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
	Env                 string
	HTTPAddr            string
	LogLevel            slog.Level
	DatabaseURL         string
	RedisURL            string
	JWTPrivateKeyFile   string
	JWTTTL              time.Duration
	ShutdownTimeout     time.Duration
	TrustProxy          bool
	EnableDocs          bool
	CORSAllowedOrigins  []string
	SMSProvider         string
	TelbizURL           string
	TelbizClientID      string
	TelbizSecret        string
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleRedirectURL   string
	GoogleAllowedDomain string
	OAuthFrontendURL    string
}

// Load reads the service configuration from environment variables.
//
// ENG: Applies defaults (HTTP_ADDR=:8081, JWT_TTL=24h, SMS_PROVIDER=log, ...) and
// collects every problem instead of stopping at the first one. DATABASE_URL is
// required and must not use sslmode=disable in production. SMS_PROVIDER must be
// "log" or "telbiz": "log" is refused in production because it writes login codes
// to the log, and "telbiz" needs TELBIZ_CLIENT_ID and TELBIZ_SECRET.
// Google login is optional: when GOOGLE_CLIENT_ID is set, GOOGLE_CLIENT_SECRET and OAUTH_FRONTEND_URL are required too.
// LAO: ອ່ານການຕັ້ງຄ່າຈາກ env ພ້ອມຄ່າເລີ່ມຕົ້ນ ແລະ ກວດສອບ (ລວມທັງຜູ້ໃຫ້ບໍລິການ SMS).
//
// @returns the config, and a joined error listing every invalid setting
func Load() (Config, error) {
	cfg := Config{
		Env:                 getEnv("APP_ENV", "development"),
		HTTPAddr:            getEnv("HTTP_ADDR", ":8081"),
		DatabaseURL:         os.Getenv("DATABASE_URL"),
		RedisURL:            getEnv("REDIS_URL", "redis://localhost:6380/0"),
		JWTPrivateKeyFile:   getEnv("JWT_PRIVATE_KEY_FILE", "keys/jwt_private.pem"),
		SMSProvider:         getEnv("SMS_PROVIDER", "log"),
		TelbizURL:           getEnv("TELBIZ_URL", "https://api.telbiz.la"),
		TelbizClientID:      getEnv("TELBIZ_CLIENT_ID", ""),
		TelbizSecret:        getEnv("TELBIZ_SECRET", ""),
		GoogleClientID:      getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret:  getEnv("GOOGLE_CLIENT_SECRET", ""),
		GoogleRedirectURL:   getEnv("GOOGLE_REDIRECT_URL", "http://localhost:8081/api/v1/auth/google/callback"),
		GoogleAllowedDomain: getEnv("GOOGLE_ALLOWED_DOMAIN", ""),
		OAuthFrontendURL:    getEnv("OAUTH_FRONTEND_URL", ""),
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

	if cfg.GoogleEnabled() {
		if cfg.GoogleClientSecret == "" || cfg.OAuthFrontendURL == "" {
			errs = append(errs, errors.New("GOOGLE_CLIENT_SECRET and OAUTH_FRONTEND_URL are required when GOOGLE_CLIENT_ID is set"))
		}
		if cfg.Env == "production" && (!strings.HasPrefix(cfg.GoogleRedirectURL, "https://") || !strings.HasPrefix(cfg.OAuthFrontendURL, "https://")) {
			errs = append(errs, errors.New("GOOGLE_REDIRECT_URL and OAUTH_FRONTEND_URL must use https in production"))
		}
	}

	return cfg, errors.Join(errs...)
}

// GoogleEnabled reports whether "Login with Google" is configured.
//
// ENG: The feature is on when GOOGLE_CLIENT_ID is set; without it the Google routes are not mounted.
// LAO: ກວດວ່າເປີດໃຊ້ login ດ້ວຍ Google ຫຼືບໍ່ (ມີ GOOGLE_CLIENT_ID).
//
// @returns true when Google login is enabled
func (c Config) GoogleEnabled() bool { return c.GoogleClientID != "" }

// getEnv reads an environment variable, falling back to a default when it is empty.
//
// ENG: The value is trimmed because make keeps trailing spaces from .env lines.
// LAO: ອ່ານຕົວແປ env (ຕັດຍະຫວ່າງອອກ) — ຖ້າວ່າງຈະໃຊ້ຄ່າເລີ່ມຕົ້ນ.
//
// @param key - environment variable name
// @param fallback - value used when the variable is unset or blank
// @returns the trimmed value or the fallback
func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// getBool reads a boolean environment variable.
//
// ENG: Accepts anything strconv.ParseBool accepts (true/false, 1/0, ...).
// Returns the fallback when the variable is unset or blank.
// LAO: ອ່ານຕົວແປ env ແບບ true/false — ຖ້າວ່າງຈະໃຊ້ຄ່າເລີ່ມຕົ້ນ.
//
// @param key - environment variable name
// @param fallback - value used when the variable is unset or blank
// @returns the parsed bool, or an error if the value is not a valid boolean
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

// splitList splits a comma-separated string into a list.
//
// ENG: Trims each item and drops empty ones, so "a, ,b," gives ["a", "b"].
// LAO: ແຍກສະຕຣິງທີ່ຂັ້ນດ້ວຍ comma ເປັນລາຍການ ແລະ ຕັດລາຍການທີ່ວ່າງອອກ.
//
// @param s - comma-separated values
// @returns the non-empty, trimmed items (nil when there are none)
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TonnPcst/martgo-auth/internal/config"
	"github.com/TonnPcst/martgo-auth/internal/handler"
	"github.com/TonnPcst/martgo-auth/internal/oauth"
	"github.com/TonnPcst/martgo-auth/internal/otp"
	"github.com/TonnPcst/martgo-auth/internal/service"
	"github.com/TonnPcst/martgo-auth/internal/session"
	"github.com/TonnPcst/martgo-auth/internal/sms"
	"github.com/TonnPcst/martgo-auth/internal/store"
	"github.com/TonnPcst/martgo-auth/internal/token"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// main is the entry point of the auth API server.
//
// ENG: Calls run and exits with code 1 if it returns an error.
// LAO: ຈຸດເລີ່ມຕົ້ນຂອງ auth server — ຖ້າ run ຜິດພາດຈະອອກດ້ວຍ code 1.
func main() {
	if err := run(); err != nil {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

// run wires up all dependencies and serves HTTP until a shutdown signal arrives.
//
// ENG: Loads config, sets up the JSON logger, connects to Postgres and Redis (5-second
// ping timeout), loads the Ed25519 private key used to sign tokens, picks the SMS
// sender (Telbiz, or the log sender for local dev), builds the OTP manager, session
// writer, services and router, then starts the server. On SIGINT/SIGTERM it shuts
// down gracefully within SHUTDOWN_TIMEOUT.
// LAO: ເຊື່ອມຕໍ່ DB, Redis, ໂຫຼດ private key, ເລືອກຜູ້ສົ່ງ SMS, ສ້າງ router ແລ້ວເປີດ server.
//
// @returns error if startup fails, the server crashes or shutdown times out
func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("create db pool: %w", err)
	}
	defer pool.Close()

	pingCtx, cancelPing := context.WithTimeout(ctx, 5*time.Second)
	defer cancelPing()
	if err := pool.Ping(pingCtx); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}

	redisOpt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("parse REDIS_URL: %w", err)
	}
	rdb := redis.NewClient(redisOpt)
	defer rdb.Close()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		return fmt.Errorf("connect to redis: %w", err)
	}

	privPEM, err := os.ReadFile(cfg.JWTPrivateKeyFile)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	tokens, err := token.NewManager(privPEM, cfg.JWTTTL)
	if err != nil {
		return err
	}

	var sender otp.Sender
	switch cfg.SMSProvider {
	case "telbiz":
		sender = sms.NewTelbiz(cfg.TelbizURL, cfg.TelbizClientID, cfg.TelbizSecret)
	default:
		sender = sms.LogSender{Logger: logger}
	}
	otps := otp.NewManager(rdb, sender, otp.DefaultConfig())

	st := store.New(pool)
	sessions := session.NewWriter(rdb, tokens.TTL())
	services := handler.Services{
		Auth:  service.NewAuthService(st, tokens, sessions, otps, oauth.NewHandoffs(rdb)),
		Users: service.NewUserService(st, sessions),
	}

	if cfg.GoogleEnabled() {
		discoverCtx, cancelDiscover := context.WithTimeout(ctx, 10*time.Second)
		defer cancelDiscover()
		google, err := oauth.NewGoogle(discoverCtx, rdb, oauth.GoogleConfig{
			ClientID:      cfg.GoogleClientID,
			ClientSecret:  cfg.GoogleClientSecret,
			RedirectURL:   cfg.GoogleRedirectURL,
			AllowedDomain: cfg.GoogleAllowedDomain,
		})
		if err != nil {
			return err
		}
		services.Google = google
	}

	checks := []handler.HealthCheck{
		{Name: "database", Pinger: pool},
		{Name: "redis", Pinger: handler.PingFunc(func(ctx context.Context) error { return rdb.Ping(ctx).Err() })},
	}
	router := handler.NewRouter(logger, tokens, st, checks, services, handler.RouterOptions{
		TrustProxy:         cfg.TrustProxy,
		EnableDocs:         cfg.EnableDocs,
		CORSAllowedOrigins: cfg.CORSAllowedOrigins,
		OAuthFrontendURL:   cfg.OAuthFrontendURL,
		SecureCookies:      cfg.Env == "production",
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	serverErr := make(chan error, 1)
	go func() {
		logger.Info("http server started", "addr", cfg.HTTPAddr, "env", cfg.Env)
		serverErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}
	stop()

	logger.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	logger.Info("server stopped")
	return nil
}

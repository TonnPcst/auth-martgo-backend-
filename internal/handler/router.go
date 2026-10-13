package handler

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/TonnPcst/martgo-auth/internal/domain"
	"github.com/TonnPcst/martgo-auth/internal/httpx"
	mw "github.com/TonnPcst/martgo-auth/internal/middleware"
	"github.com/TonnPcst/martgo-auth/internal/service"
	"github.com/TonnPcst/martgo-auth/internal/token"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

type Services struct {
	Auth  *service.AuthService
	Users *service.UserService
}

type RouterOptions struct {
	TrustProxy         bool
	EnableDocs         bool
	CORSAllowedOrigins []string
}

type Pinger interface {
	Ping(ctx context.Context) error
}

// NewRouter keeps the same /api/v1 paths mart-api used to serve, so the gateway
// can route by prefix and clients do not change.
func NewRouter(logger *slog.Logger, tokens *token.Manager, users mw.UserLookup, db Pinger, svc Services, opts RouterOptions) http.Handler {
	authH := &AuthHandler{auth: svc.Auth, users: svc.Users}
	userH := &UserHandler{svc: svc.Users}

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	if opts.TrustProxy {
		r.Use(chimw.RealIP)
	}
	r.Use(mw.RequestLogger(logger), mw.Recoverer(logger), mw.SecureHeaders)
	if len(opts.CORSAllowedOrigins) > 0 {
		r.Use(mw.CORS(opts.CORSAllowedOrigins))
	}

	r.NotFound(func(w http.ResponseWriter, _ *http.Request) {
		httpx.Error(w, http.StatusNotFound, "route not found")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, _ *http.Request) {
		httpx.Error(w, http.StatusMethodNotAllowed, "method not allowed")
	})

	r.Get("/healthz", health(db))
	if opts.EnableDocs {
		r.Get("/docs", swaggerUI)
		r.Get("/docs/openapi.yaml", openAPISpec)
	}

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(mw.APIHeaders)
		r.With(mw.RateLimit(5, time.Minute)).Post("/auth/login", authH.Login)

		r.Group(func(r chi.Router) {
			r.Use(mw.Authenticate(tokens, users))

			r.Get("/auth/me", authH.Me)
			r.Post("/auth/logout", authH.Logout)

			r.Route("/users", func(r chi.Router) {
				r.Use(mw.RequireRole(domain.RoleAdmin))
				r.Get("/", userH.List)
				r.Post("/", userH.Create)
				r.Get("/{id}", userH.Get)
				r.Patch("/{id}", userH.Update)
			})
		})
	})

	return r
}

func health(db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			httpx.Error(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func actorFrom(r *http.Request) service.Actor {
	claims, ok := token.ClaimsFromContext(r.Context())
	if !ok {
		return service.Actor{}
	}
	return service.Actor{UserID: claims.UserID, Role: claims.Role}
}

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

// PingFunc adapts a plain function (e.g. a Redis ping) to Pinger.
type PingFunc func(ctx context.Context) error

func (f PingFunc) Ping(ctx context.Context) error { return f(ctx) }

// HealthCheck is one dependency /healthz must reach, such as "database" or "redis".
type HealthCheck struct {
	Name   string
	Pinger Pinger
}

// NewRouter builds the HTTP router with all middleware and routes.
//
// ENG: Keeps the same /api/v1 paths mart-api used to serve, so the gateway can route
// by prefix and clients do not change. The login endpoints are public but rate
// limited per IP; /auth/me and /auth/logout need a token; /users is admin only.
// LAO: ສ້າງ router — ເສັ້ນທາງ login ເປີດສາທາລະນະແຕ່ຈຳກັດຈຳນວນ, /users ສະເພາະ admin.
//
// @param logger - logger for request logs and panics
// @param tokens - signs and verifies the JWT access tokens
// @param users - loads users for the Authenticate middleware
// @param checks - dependencies pinged by /healthz
// @param svc - auth and user services used by the handlers
// @param opts - proxy, docs and CORS settings
// @returns the root HTTP handler
func NewRouter(logger *slog.Logger, tokens *token.Manager, users mw.UserLookup, checks []HealthCheck, svc Services, opts RouterOptions) http.Handler {
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

	r.Get("/healthz", health(checks))
	if opts.EnableDocs {
		r.Get("/docs", swaggerUI)
		r.Get("/docs/openapi.yaml", openAPISpec)
	}

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(mw.APIHeaders)
		r.With(mw.RateLimit(5, time.Minute)).Post("/auth/login", authH.Login)
		r.With(mw.RateLimit(10, time.Minute)).Post("/auth/login/verify", authH.VerifyOTP)
		r.With(mw.RateLimit(5, time.Minute)).Post("/auth/login/resend", authH.ResendOTP)

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

// health builds the health check handler. GET /healthz
//
// ENG: Pings every dependency (Postgres, Redis) within one 2-second timeout. Returns
// 200 {"status":"ok"} when all answer, or 503 naming the first one that does not, so
// load balancers take the instance out while it cannot serve requests.
// LAO: ສ້າງ handler ກວດສຸຂະພາບລະບົບ — ping DB ແລະ Redis ພາຍໃນ 2 ວິນາທີ, ຕອບ 200 ຫຼື 503.
//
// @param checks - dependencies to ping, in order
// @returns the HTTP handler
func health(checks []HealthCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		for _, c := range checks {
			if err := c.Pinger.Ping(ctx); err != nil {
				httpx.Error(w, http.StatusServiceUnavailable, c.Name+" unavailable")
				return
			}
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// actorFrom returns the logged-in user from the request context.
//
// ENG: Reads the token claims that the Authenticate middleware stored. Returns an
// empty Actor when the request is not authenticated.
// LAO: ດຶງຂໍ້ມູນຜູ້ໃຊ້ທີ່ເຂົ້າສູ່ລະບົບ (ID, role) ຈາກ context ຂອງ request.
//
// @param r - incoming request
// @returns the actor (user ID and role)
func actorFrom(r *http.Request) service.Actor {
	claims, ok := token.ClaimsFromContext(r.Context())
	if !ok {
		return service.Actor{}
	}
	return service.Actor{UserID: claims.UserID, Role: claims.Role}
}

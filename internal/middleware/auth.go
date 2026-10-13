package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/TonnPcst/martgo-auth/internal/httpx"
	"github.com/TonnPcst/martgo-auth/internal/store"
	"github.com/TonnPcst/martgo-auth/internal/token"
)

type UserLookup interface {
	GetUserByID(ctx context.Context, id int64) (db.User, error)
}

func Authenticate(tokens *token.Manager, users UserLookup) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			schema, raw, ok := strings.Cut(r.Header.Get("Authorization"), " ")
			if !ok || !strings.EqualFold(schema, "Bearer") || raw == "" {
				httpx.Error(w, http.StatusUnauthorized, "missing or malformed bearer token")
				return
			}

			claims, err := tokens.Parse(raw)
			if err != nil {
				httpx.Error(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			user, err := users.GetUserByID(r.Context(), claims.UserID)
			if err != nil {
				if store.IsNotFound(err) {
					httpx.Error(w, http.StatusUnauthorized, "account is disabled")
					return
				}
				httpx.HandleError(w, r, err)
				return
			}
			if !user.IsActive {
				httpx.Error(w, http.StatusUnauthorized, "account is disabled")
				return
			}
			if claims.TokenVersion != user.TokenVersion {
				httpx.Error(w, http.StatusUnauthorized, "token has been revoked")
				return
			}
			claims.Role = user.Role

			next.ServeHTTP(w, r.WithContext(token.WithClaims(r.Context(), claims)))
		})
	}
}

func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, role := range roles {
		allowed[role] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := token.ClaimsFromContext(r.Context())
			if !ok {
				httpx.Error(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if !allowed[claims.Role] {
				httpx.Error(w, http.StatusForbidden, "you do not have permission to access this resource")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

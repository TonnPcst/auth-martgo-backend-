package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/TonnPcst/martgo-auth/internal/httpx"
	chimw "github.com/go-chi/chi/v5/middleware"
)

func Recoverer(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				logger.ErrorContext(r.Context(), "panic recovered",
					"panic", rec,
					"stack", string(debug.Stack()),
					"request_id", chimw.GetReqID(r.Context()),
				)
				if ww.Status() == 0 {
					httpx.Error(ww, http.StatusInternalServerError, "internal server error")
				}
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

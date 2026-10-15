package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/TonnPcst/martgo-auth/internal/httpx"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// Recoverer turns a panic in a handler into a 500 response.
//
// ENG: Logs the panic value, stack trace and request ID. http.ErrAbortHandler is
// re-panicked on purpose. The 500 body is only written if nothing was sent yet.
// LAO: ດັກ panic ໃນ handler, ບັນທຶກ log ແລ້ວຕອບ 500 ແທນທີ່ server ຈະລົ້ມ.
//
// @param logger - structured logger to write to
// @returns the middleware
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

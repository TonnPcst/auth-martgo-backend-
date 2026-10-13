package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
	chimw "github.com/go-chi/chi/v5/middleware"
)

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode response", "err", err)
	}
}

type errorBody struct {
	Error string `json:"error"`
}

func Error(w http.ResponseWriter, status int, message string) {
	JSON(w, status, errorBody{Error: message})
}

func HandleError(w http.ResponseWriter, r *http.Request, err error) {
	var appErr *apperr.Error
	if errors.As(err, &appErr) {
		Error(w, statusFor(appErr.Kind), appErr.Message)
		return
	}
	slog.ErrorContext(r.Context(), "request failed",
		"err", err,
		"method", r.Method,
		"path", r.URL.Path,
		"request_id", chimw.GetReqID(r.Context()),
	)
	Error(w, http.StatusInternalServerError, "internal server error")
}

func statusFor(kind apperr.Kind) int {
	switch kind {
	case apperr.KindValidation:
		return http.StatusBadRequest
	case apperr.KindNotFound:
		return http.StatusNotFound
	case apperr.KindConflict:
		return http.StatusConflict
	case apperr.KindUnauthorized:
		return http.StatusUnauthorized
	case apperr.KindForbidden:
		return http.StatusForbidden
	case apperr.KindTooManyRequests:
		return http.StatusTooManyRequests
	}
	return http.StatusInternalServerError
}

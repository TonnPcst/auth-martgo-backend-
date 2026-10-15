package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// JSON writes v as a JSON response with the given status code.
//
// ENG: Sets Content-Type to application/json. An encoding error is only logged,
// because the status line has already been sent.
// LAO: ຕອບກັບເປັນ JSON ພ້ອມ status code ທີ່ກຳນົດ.
//
// @param w - response writer
// @param status - HTTP status code
// @param v - value to encode
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

// Error writes a JSON error body: {"error": message}.
//
// ENG: Used for every error response so clients always get the same shape.
// LAO: ຕອບກັບຂໍ້ຜິດພາດເປັນ JSON ຮູບແບບ {"error": "..."}.
//
// @param w - response writer
// @param status - HTTP status code
// @param message - message shown to the client
func Error(w http.ResponseWriter, status int, message string) {
	JSON(w, status, errorBody{Error: message})
}

// HandleError maps an error to the right HTTP response.
//
// ENG: An *apperr.Error is sent with its own status and message. Any other error is
// logged with the method, path and request ID, and the client only gets a generic
// 500 so internal details never leak.
// LAO: ແປງຂໍ້ຜິດພາດເປັນ HTTP response — apperr ຕອບຕາມປະເພດ, ອື່ນໆ log ໄວ້ແລ້ວຕອບ 500.
//
// @param w - response writer
// @param r - incoming request (used for logging)
// @param err - error returned by a service
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

// statusFor maps an apperr.Kind to its HTTP status code.
//
// ENG: Validation=400, NotFound=404, Conflict=409, Unauthorized=401, Forbidden=403,
// TooManyRequests=429, anything else=500.
// LAO: ແປງປະເພດຂໍ້ຜິດພາດເປັນ HTTP status code.
//
// @param kind - error kind
// @returns the HTTP status code
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

package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
)

const maxBodyBytes = 1 << 20

var validate = newValidator()

func newValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.RegisterTagNameFunc(func(f reflect.StructField) string {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			return ""
		}
		if name == "" {
			return f.Name
		}
		return name
	})
	return v
}

func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	if dec.More() {
		return apperr.Validation("request body must contain a single JSON object")
	}
	if err := validate.Struct(dst); err != nil {
		return validationError(err)
	}
	return nil
}

func decodeError(err error) error {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var maxErr *http.MaxBytesError
	switch {
	case errors.Is(err, io.EOF):
		return apperr.Validation("request body must not be empty")
	case errors.As(err, &syntaxErr), errors.Is(err, io.ErrUnexpectedEOF):
		return apperr.Validation("request body contains malformed JSON")
	case errors.As(err, &typeErr):
		return apperr.Validation("field %q has an invalid type", typeErr.Field)
	case errors.As(err, &maxErr):
		return apperr.Validation("request body must not exceed %d bytes", maxErr.Limit)
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return apperr.Validation("request body contains unknown field %s",
			strings.TrimPrefix(err.Error(), "json: unknown field "))
	}
	return apperr.Validation("invalid request body")
}

func validationError(err error) error {
	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) {
		return apperr.Validation("%s", err.Error())
	}
	msgs := make([]string, 0, len(verrs))
	for _, fe := range verrs {
		msgs = append(msgs, fieldMessage(fe))
	}
	return apperr.Validation("%s", strings.Join(msgs, "; "))
}

func fieldMessage(fe validator.FieldError) string {
	field := fe.Namespace()
	if i := strings.IndexByte(field, '.'); i >= 0 {
		field = field[i+1:]
	}
	switch fe.Tag() {
	case "required":
		return field + " is required"
	case "email":
		return field + " must be a valid email address"
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, strings.ReplaceAll(fe.Param(), " ", ", "))
	case "min", "max":
		bound := "at least"
		if fe.Tag() == "max" {
			bound = "at most"
		}
		switch fe.Kind() {
		case reflect.String:
			return fmt.Sprintf("%s must be %s %s characters", field, bound, fe.Param())
		case reflect.Slice:
			return fmt.Sprintf("%s must contain %s %s items", field, bound, fe.Param())
		}
		return fmt.Sprintf("%s must be %s %s", field, bound, fe.Param())
	case "gt":
		return fmt.Sprintf("%s must be greater than %s", field, fe.Param())
	case "gte":
		return fmt.Sprintf("%s must be greater than or equal to %s", field, fe.Param())
	case "lte":
		return fmt.Sprintf("%s must be less than or equal to %s", field, fe.Param())
	}
	return field + " is invalid"
}

func IDParam(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	if err != nil || id <= 0 {
		return 0, apperr.Validation("invalid %s", name)
	}
	return id, nil
}

func QueryString(r *http.Request, key string) *string {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return nil
	}
	return &v
}

func QueryInt64(r *http.Request, key string) (*int64, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil, apperr.Validation("%s must be an integer", key)
	}
	return &v, nil
}

func QueryBool(r *http.Request, key string) (*bool, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, apperr.Validation("%s must be true or false", key)
	}
	return &v, nil
}

func queryInt32(r *http.Request, key string, fallback int32) (int32, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, apperr.Validation("%s must be an integer", key)
	}
	return int32(v), nil
}

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

// newValidator creates the shared struct validator.
//
// ENG: Makes validation errors use the JSON field names (e.g. "full_name") instead of
// the Go field names, so error messages match what the client sent.
// LAO: ສ້າງ validator ທີ່ໃຊ້ຊື່ field ຕາມ JSON ໃນຂໍ້ຄວາມຂໍ້ຜິດພາດ.
//
// @returns the configured validator
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

// DecodeJSON decodes and validates a JSON request body into dst.
//
// ENG: Limits the body to 1 MB, rejects unknown fields and trailing data, then runs
// the struct's `validate` tags. Errors are turned into readable validation messages.
// LAO: ອ່ານ JSON ຈາກ body (ສູງສຸດ 1 MB), ຫ້າມມີ field ທີ່ບໍ່ຮູ້ຈັກ, ແລ້ວກວດສອບຕາມ validate tag.
//
// @param w - response writer (needed by http.MaxBytesReader)
// @param r - incoming request
// @param dst - pointer to the request struct to fill
// @returns nil on success, or a validation error
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

// decodeError turns a JSON decoding error into a client-friendly validation error.
//
// ENG: Handles empty body, malformed JSON, wrong field type, body too large and
// unknown field. Anything else becomes "invalid request body".
// LAO: ແປງຂໍ້ຜິດພາດຕອນອ່ານ JSON ໃຫ້ເປັນຂໍ້ຄວາມທີ່ client ເຂົ້າໃຈງ່າຍ.
//
// @param err - error from json.Decoder
// @returns a validation error
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

// validationError joins all field validation failures into one validation error.
//
// ENG: Messages are separated by "; ", e.g. "name is required; price must be greater than 0".
// LAO: ລວມຂໍ້ຜິດພາດການກວດສອບທຸກ field ເປັນຂໍ້ຄວາມດຽວ.
//
// @param err - error from validator.Struct
// @returns a validation error
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

// fieldMessage builds a readable message for one failed validation rule.
//
// ENG: Supports required, email, oneof, min, max, gt, gte and lte. The top-level struct
// name is removed so nested fields read like "items[0].quantity".
// LAO: ສ້າງຂໍ້ຄວາມອະທິບາຍສຳລັບ field ທີ່ບໍ່ຜ່ານການກວດສອບ.
//
// @param fe - the failed field
// @returns the message, e.g. "price must be greater than 0"
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

// IDParam reads a positive integer ID from a chi URL parameter.
//
// ENG: Used for routes like /products/{id}.
// LAO: ອ່ານ ID (ຈຳນວນເຕັມບວກ) ຈາກ URL path.
//
// @param r - incoming request
// @param name - URL parameter name, usually "id"
// @returns the ID, or a validation error if it is missing, not a number or <= 0
func IDParam(r *http.Request, name string) (int64, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, name), 10, 64)
	if err != nil || id <= 0 {
		return 0, apperr.Validation("invalid %s", name)
	}
	return id, nil
}

// QueryString reads an optional string query parameter.
//
// ENG: The value is trimmed. Returns nil when the parameter is missing or blank.
// LAO: ອ່ານ query string (ບໍ່ບັງຄັບ) — ຖ້າວ່າງຈະສົ່ງຄືນ nil.
//
// @param r - incoming request
// @param key - query parameter name
// @returns pointer to the value, or nil
func QueryString(r *http.Request, key string) *string {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return nil
	}
	return &v
}

// QueryInt64 reads an optional int64 query parameter.
//
// ENG: Returns nil when the parameter is missing.
// LAO: ອ່ານ query ແບບຈຳນວນເຕັມ (ບໍ່ບັງຄັບ) — ຖ້າບໍ່ມີຈະສົ່ງຄືນ nil.
//
// @param r - incoming request
// @param key - query parameter name
// @returns pointer to the value, nil, or a validation error if it is not an integer
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

// QueryBool reads an optional boolean query parameter.
//
// ENG: Returns nil when the parameter is missing.
// LAO: ອ່ານ query ແບບ true/false (ບໍ່ບັງຄັບ) — ຖ້າບໍ່ມີຈະສົ່ງຄືນ nil.
//
// @param r - incoming request
// @param key - query parameter name
// @returns pointer to the value, nil, or a validation error if it is not a boolean
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

// queryInt32 reads an int32 query parameter with a default.
//
// ENG: Used by ParsePagination for limit and offset.
// LAO: ອ່ານ query ແບບ int32 — ຖ້າບໍ່ມີຈະໃຊ້ຄ່າເລີ່ມຕົ້ນ.
//
// @param r - incoming request
// @param key - query parameter name
// @param fallback - value used when the parameter is missing
// @returns the value, or a validation error if it is not an integer
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

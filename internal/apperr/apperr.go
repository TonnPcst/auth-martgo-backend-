package apperr

import (
	"errors"
	"fmt"
)

type Kind int

const (
	KindInternal Kind = iota
	KindValidation
	KindNotFound
	KindConflict
	KindUnauthorized
	KindForbidden
	KindTooManyRequests
)

type Error struct {
	Kind    Kind
	Message string
}

func (e *Error) Error() string { return e.Message }

func newf(kind Kind, format string, args ...any) error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

func Validation(format string, args ...any) error   { return newf(KindValidation, format, args...) }
func NotFound(format string, args ...any) error     { return newf(KindNotFound, format, args...) }
func Conflict(format string, args ...any) error     { return newf(KindConflict, format, args...) }
func Unauthorized(format string, args ...any) error { return newf(KindUnauthorized, format, args...) }
func Forbidden(format string, args ...any) error    { return newf(KindForbidden, format, args...) }
func TooManyRequests(format string, args ...any) error {
	return newf(KindTooManyRequests, format, args...)
}

func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindInternal
}

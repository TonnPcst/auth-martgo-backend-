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

// Error implements the error interface.
//
// ENG: Returns the client-safe message that is sent in the JSON error body.
// LAO: ສົ່ງຄືນຂໍ້ຄວາມຂໍ້ຜິດພາດ ທີ່ປອດໄພສຳລັບສະແດງໃຫ້ client.
//
// @returns the error message
func (e *Error) Error() string { return e.Message }

// newf builds an *Error of the given kind with a printf-style message.
//
// ENG: Shared helper behind Validation, NotFound, Conflict and the other constructors.
// LAO: ສ້າງ *Error ຕາມປະເພດທີ່ກຳນົດ ພ້ອມຂໍ້ຄວາມແບບ printf.
//
// @param kind - error category, decides the HTTP status later
// @param format - fmt format string for the message
// @param args - values for the format string
// @returns the new error
func newf(kind Kind, format string, args ...any) error {
	return &Error{Kind: kind, Message: fmt.Sprintf(format, args...)}
}

// Validation creates a KindValidation error (HTTP 400).
//
// ENG: Use for bad input: missing fields, wrong format, values out of range.
// LAO: ສ້າງຂໍ້ຜິດພາດປະເພດ ຂໍ້ມູນບໍ່ຖືກຕ້ອງ (400).
//
// @param format - fmt format string for the message
// @param args - values for the format string
// @returns the validation error
func Validation(format string, args ...any) error { return newf(KindValidation, format, args...) }

// NotFound creates a KindNotFound error (HTTP 404).
//
// ENG: Use when the requested record does not exist.
// LAO: ສ້າງຂໍ້ຜິດພາດປະເພດ ບໍ່ພົບຂໍ້ມູນ (404).
//
// @param format - fmt format string for the message
// @param args - values for the format string
// @returns the not-found error
func NotFound(format string, args ...any) error { return newf(KindNotFound, format, args...) }

// Conflict creates a KindConflict error (HTTP 409).
//
// ENG: Use for duplicates or a state that blocks the action (e.g. not enough stock).
// LAO: ສ້າງຂໍ້ຜິດພາດປະເພດ ຂໍ້ມູນຂັດແຍ່ງ ເຊັ່ນ ຊ້ຳກັນ ຫຼື ສະຕັອກບໍ່ພໍ (409).
//
// @param format - fmt format string for the message
// @param args - values for the format string
// @returns the conflict error
func Conflict(format string, args ...any) error { return newf(KindConflict, format, args...) }

// Unauthorized creates a KindUnauthorized error (HTTP 401).
//
// ENG: Use when the caller is not logged in or the credentials are wrong.
// LAO: ສ້າງຂໍ້ຜິດພາດປະເພດ ຍັງບໍ່ໄດ້ຢືນຢັນຕົວຕົນ (401).
//
// @param format - fmt format string for the message
// @param args - values for the format string
// @returns the unauthorized error
func Unauthorized(format string, args ...any) error { return newf(KindUnauthorized, format, args...) }

// Forbidden creates a KindForbidden error (HTTP 403).
//
// ENG: Use when the caller is logged in but is not allowed to do the action.
// LAO: ສ້າງຂໍ້ຜິດພາດປະເພດ ບໍ່ມີສິດເຂົ້າເຖິງ (403).
//
// @param format - fmt format string for the message
// @param args - values for the format string
// @returns the forbidden error
func Forbidden(format string, args ...any) error { return newf(KindForbidden, format, args...) }

// TooManyRequests creates a KindTooManyRequests error (HTTP 429).
//
// ENG: Use when the caller is rate limited or locked out for a while.
// LAO: ສ້າງຂໍ້ຜິດພາດປະເພດ ຮ້ອງຂໍຫຼາຍເກີນໄປ (429).
//
// @param format - fmt format string for the message
// @param args - values for the format string
// @returns the too-many-requests error
func TooManyRequests(format string, args ...any) error {
	return newf(KindTooManyRequests, format, args...)
}

// KindOf returns the Kind of an error.
//
// ENG: Unwraps the error chain looking for *Error. Any other error (DB failure,
// network error, ...) is treated as KindInternal.
// LAO: ສົ່ງຄືນປະເພດຂອງຂໍ້ຜິດພາດ — ຖ້າບໍ່ແມ່ນ *Error ຈະຖືວ່າເປັນ KindInternal.
//
// @param err - any error, may be wrapped
// @returns the error kind
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindInternal
}

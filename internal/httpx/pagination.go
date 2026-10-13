package httpx

import (
	"net/http"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
)

const (
	DefaultLimit = 20
	MaxLimit     = 100
)

type Pagination struct {
	Limit  int32 `json:"limit"`
	Offset int32 `json:"offset"`
	Total  int64 `json:"total"`
}

type Page[T any] struct {
	Data       []T        `json:"data"`
	Pagination Pagination `json:"pagination"`
}

func ParsePagination(r *http.Request) (limit, offset int32, err error) {
	if limit, err = queryInt32(r, "limit", DefaultLimit); err != nil {
		return 0, 0, err
	}
	if offset, err = queryInt32(r, "offset", 0); err != nil {
		return 0, 0, err
	}
	if limit < 1 || limit > MaxLimit {
		return 0, 0, apperr.Validation("limit must be between 1 and %d", MaxLimit)
	}
	if offset < 0 {
		return 0, 0, apperr.Validation("offset must not be negative")
	}
	return limit, offset, nil
}

func WritePage[T any](w http.ResponseWriter, items []T, limit, offset int32, total int64) {
	JSON(w, http.StatusOK, Page[T]{
		Data:       items,
		Pagination: Pagination{Limit: limit, Offset: offset, Total: total},
	})
}

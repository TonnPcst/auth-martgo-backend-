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

// ParsePagination reads the limit and offset query parameters.
//
// ENG: limit defaults to 20 and must be between 1 and 100. offset defaults to 0
// and must not be negative.
// LAO: ອ່ານ limit ແລະ offset ຈາກ query — limit ຄ່າເລີ່ມຕົ້ນ 20 (1-100), offset ຫ້າມຕິດລົບ.
//
// @param r - incoming request
// @returns limit, offset, or a validation error
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

// WritePage writes a paginated list as JSON with status 200.
//
// ENG: The body has the shape {"data": [...], "pagination": {"limit", "offset", "total"}}.
// LAO: ຕອບກັບລາຍການແບບແບ່ງໜ້າ ເປັນ JSON ພ້ອມຂໍ້ມູນ pagination.
//
// @param w - response writer
// @param items - the items of the current page
// @param limit - page size that was used
// @param offset - offset that was used
// @param total - total number of matching items
func WritePage[T any](w http.ResponseWriter, items []T, limit, offset int32, total int64) {
	JSON(w, http.StatusOK, Page[T]{
		Data:       items,
		Pagination: Pagination{Limit: limit, Offset: offset, Total: total},
	})
}

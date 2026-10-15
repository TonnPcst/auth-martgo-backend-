package service

import (
	"strings"

	"github.com/TonnPcst/martgo-auth/internal/apperr"
	"github.com/TonnPcst/martgo-auth/internal/store"
)

type Actor struct {
	UserID int64
	Role   string
}

// dbError converts a database error into an apperr error.
//
// ENG: No rows becomes NotFound, a unique violation becomes Conflict ("already
// exists") and a foreign key violation becomes Conflict ("still in use"). Other
// errors are returned unchanged.
// LAO: ແປງຂໍ້ຜິດພາດຈາກ DB ເປັນ apperr — ບໍ່ພົບ=404, ຊ້ຳ/ຖືກອ້າງອີງ=409.
//
// @param err - error from the store, may be nil
// @param entity - name used in the message, e.g. "product"
// @returns the converted error, or nil
func dbError(err error, entity string) error {
	switch {
	case err == nil:
		return nil
	case store.IsNotFound(err):
		return apperr.NotFound("%s not found", entity)
	case store.IsUniqueViolation(err):
		return apperr.Conflict("%s already exists", entity)
	case store.IsForeignKeyViolation(err):
		return apperr.Conflict("%s reference a missing record or is still in use", entity)
	}
	return err
}

// normalizeEmail trims and lower-cases an email address.
//
// ENG: Used before saving and before lookups so emails match case-insensitively.
// LAO: ຕັດຍະຫວ່າງ ແລະ ປ່ຽນ email ເປັນຕົວພິມນ້ອຍ.
//
// @param email - raw email
// @returns the normalized email
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

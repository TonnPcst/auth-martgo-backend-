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

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

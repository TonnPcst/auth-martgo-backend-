package migrations

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"

	"github.com/pressly/goose/v3"
	"golang.org/x/crypto/bcrypt"
)

// init registers the seed-admin Go migration with goose.
//
// ENG: Goose picks up Go migrations through init, using the file name for the version.
// LAO: ລົງທະບຽນ migration seed admin ກັບ goose.
func init() {
	goose.AddMigrationContext(upSeedAdmin, downSeedAdmin)
}

// upSeedAdmin creates the first admin user from environment variables.
//
// ENG: Needs ADMIN_EMAIL and ADMIN_PASSWORD (8-72 chars); ADMIN_NAME defaults to
// "Administrator". In production the example password "admin12345" is refused.
// Does nothing if a user with that email already exists.
// LAO: ສ້າງ admin ຄົນທຳອິດຈາກ env — ຖ້າ email ມີແລ້ວຈະບໍ່ເຮັດຫຍັງ.
//
// @param ctx - migration context
// @param tx - migration transaction
// @returns error if the env vars are missing or invalid, or the insert fails
func upSeedAdmin(ctx context.Context, tx *sql.Tx) error {
	email := strings.ToLower(strings.TrimSpace(os.Getenv(("ADMIN_EMAIL"))))
	password := os.Getenv("ADMIN_PASSWORD")
	name := strings.TrimSpace(os.Getenv("ADMIN_NAME"))
	if email == "" || password == "" {
		return errors.New("seed admin: ADMIN_EMAIL and ADMIN_PASSWORD must be set")
	}
	if len(password) < 8 || len(password) > 72 {
		return errors.New("seed admin: ADMIN_PASSWORD must be 8-72 characters")
	}
	if os.Getenv("APP_ENV") == "production" && password == "admin12345" {
		return errors.New("seed admin: ADMIN_PASSWORD is still the example value")
	}
	if name == "" {
		name = "Administrator"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO users (email, password_hash, full_name, role)
		VALUES ($1, $2, $3, 'admin')
		ON CONFLICT (email) DO NOTHING`,
		email, string(hash), name,
	)
	return err
}

// downSeedAdmin removes the admin user created by upSeedAdmin.
//
// ENG: Deletes the admin whose email matches ADMIN_EMAIL.
// LAO: ລຶບ admin ທີ່ສ້າງໂດຍ upSeedAdmin.
//
// @param ctx - migration context
// @param tx - migration transaction
// @returns error if the delete fails
func downSeedAdmin(ctx context.Context, tx *sql.Tx) error {
	email := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_EMAIL")))
	_, err := tx.ExecContext(ctx, `DELETE FROM users WHERE email = $1 AND role = 'admin'`, email)
	return err
}

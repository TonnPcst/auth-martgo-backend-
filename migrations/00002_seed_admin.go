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

func init() {
	goose.AddMigrationContext(upSeedAdmin, downSeedAdmin)
}

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

func downSeedAdmin(ctx context.Context, tx *sql.Tx) error {
	email := strings.ToLower(strings.TrimSpace(os.Getenv("ADMIN_EMAIL")))
	_, err := tx.ExecContext(ctx, `DELETE FROM users WHERE email = $1 AND role = 'admin'`, email)
	return err
}

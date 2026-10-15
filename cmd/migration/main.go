package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/TonnPcst/martgo-auth/migrations"
)

// main is the entry point of the migration CLI.
//
// ENG: Reads the goose command (up, down, status, version, redo, reset) from the
// first argument and passes the rest as extra args. Prints usage and exits with
// code 2 when no command is given, or exits with code 1 if the migration fails.
// LAO: ຈຸດເລີ່ມຕົ້ນຂອງ CLI migration — ອ່ານຄຳສັ່ງ goose ຈາກ argument ແລ້ວແລ່ນ migration.
func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: migrate <up|down|status|version|redo|reset> [args]")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2:]); err != nil {
		slog.Error("migration failed", "err", err)
		os.Exit(1)
	}
}

// run opens the database and executes one goose migration command.
//
// ENG: Requires DATABASE_URL, opens a pgx connection, waits up to 30 seconds for the
// database to accept connections, then runs the command against the embedded
// migrations FS using the postgres dialect.
// LAO: ເປີດການເຊື່ອມຕໍ່ຖານຂໍ້ມູນ, ລໍຖ້າໃຫ້ DB ພ້ອມ, ແລ້ວແລ່ນຄຳສັ່ງ goose ກັບໄຟລ໌ migration ທີ່ embed ໄວ້.
//
// @param command - goose command name, e.g. "up" or "status"
// @param args - extra arguments passed to goose (e.g. a target version)
// @returns error if DATABASE_URL is missing, the DB is unreachable or the migration fails
func run(command string, args []string) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return errors.New("DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	if err := waitForDB(ctx, db, 30*time.Second); err != nil {
		return err
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.RunContext(ctx, command, db, ".", args...)
}

// waitForDB pings the database once per second until it responds or the timeout passes.
//
// ENG: Useful when the migration container starts before Postgres is ready.
// Logs every failed ping so the wait is visible in the output.
// LAO: Ping DB ທຸກໆ 1 ວິນາທີ ຈົນກວ່າ DB ຈະຕອບ ຫຼື ໝົດເວລາ.
//
// @param ctx - context for the ping calls
// @param db - database handle to ping
// @param timeout - how long to keep retrying
// @returns nil once the DB answers, or an error wrapping the last ping failure
func waitForDB(ctx context.Context, db *sql.DB, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := db.PingContext(ctx)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("database not reachable after %s: %w", timeout, err)
		}
		slog.Info("waiting for database", "err", err)
		time.Sleep(time.Second)
	}
}

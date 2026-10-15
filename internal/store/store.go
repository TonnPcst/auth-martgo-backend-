package store

import (
	"context"
	"errors"

	"github.com/TonnPcst/martgo-auth/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store interface {
	db.Querier
	ExecTx(ctx context.Context, fn func(q db.Querier) error) error
}

type PostgresStore struct {
	*db.Queries
	pool *pgxpool.Pool
}

// New creates a Postgres-backed store from a connection pool.
//
// ENG: Wraps the sqlc queries and keeps the pool so ExecTx can open transactions.
// LAO: ສ້າງ store ທີ່ໃຊ້ Postgres ຈາກ connection pool.
//
// @param pool - pgx connection pool
// @returns the store
func New(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{
		Queries: db.New(pool),
		pool:    pool,
	}
}

// ExecTx runs fn inside a database transaction.
//
// ENG: Commits if fn returns nil, rolls back if it returns an error or panics.
// fn must use the given q, not the store, for its queries to be part of the transaction.
// LAO: ແລ່ນ fn ພາຍໃນ transaction — ສຳເລັດຈະ commit, ຜິດພາດຈະ rollback.
//
// @param ctx - request context
// @param fn - work to run with the transaction-bound queries
// @returns the error from fn, or a begin/commit error
func (s *PostgresStore) ExecTx(ctx context.Context, fn func(q db.Querier) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(s.Queries.WithTx(tx))
	})
}

// IsNotFound reports whether err means the query returned no rows.
//
// ENG: Checks for pgx.ErrNoRows anywhere in the error chain.
// LAO: ກວດວ່າຂໍ້ຜິດພາດແມ່ນ ບໍ່ພົບຂໍ້ມູນ (no rows) ຫຼືບໍ່.
//
// @param err - error from a query
// @returns true if no row was found
func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// IsUniqueViolation reports whether err is a Postgres unique violation (23505).
//
// ENG: Happens when inserting or updating a duplicate value in a unique column.
// LAO: ກວດວ່າຂໍ້ຜິດພາດແມ່ນ ຂໍ້ມູນຊ້ຳ (unique) ຫຼືບໍ່.
//
// @param err - error from a query
// @returns true for a unique violation
func IsUniqueViolation(err error) bool { return pgCode(err) == "23505" }

// IsForeignKeyViolation reports whether err is a Postgres foreign key violation (23503).
//
// ENG: Happens when referencing a missing row, or deleting a row that is still referenced.
// LAO: ກວດວ່າຂໍ້ຜິດພາດແມ່ນ foreign key (ອ້າງອີງບໍ່ພົບ ຫຼື ຍັງຖືກໃຊ້ຢູ່) ຫຼືບໍ່.
//
// @param err - error from a query
// @returns true for a foreign key violation
func IsForeignKeyViolation(err error) bool { return pgCode(err) == "23503" }

// ConstraintName tells which constraint a Postgres error violated, e.g. "users_phone_key".
//
// ENG: Returns "" when the error is not a *pgconn.PgError.
// LAO: ບອກຊື່ constraint ທີ່ຖືກລະເມີດໃນຂໍ້ຜິດພາດຂອງ Postgres.
//
// @param err - error from a query
// @returns the constraint name, or ""
func ConstraintName(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName
	}
	return ""
}

// pgCode extracts the Postgres SQLSTATE code from an error.
//
// ENG: Returns "" when the error is not a *pgconn.PgError.
// LAO: ດຶງລະຫັດຂໍ້ຜິດພາດ SQLSTATE ຂອງ Postgres.
//
// @param err - error from a query
// @returns the SQLSTATE code, or ""
func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

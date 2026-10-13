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

func New(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{
		Queries: db.New(pool),
		pool:    pool,
	}
}

func (s *PostgresStore) ExecTx(ctx context.Context, fn func(q db.Querier) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(s.Queries.WithTx(tx))
	})
}

func IsNotFound(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func IsUniqueViolation(err error) bool     { return pgCode(err) == "23505" }
func IsForeignKeyViolation(err error) bool { return pgCode(err) == "23503" }

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

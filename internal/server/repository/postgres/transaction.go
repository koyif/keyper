package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// txKey is used as a key for storing transaction in context.
type txKey struct{}

// Transactor provides transaction support for multi-step database operations.
type Transactor struct {
	pool *pgxpool.Pool
}

// NewTransactor creates a new Transactor instance.
func NewTransactor(pool *pgxpool.Pool) *Transactor {
	return &Transactor{
		pool: pool,
	}
}

// WithTransaction executes a function within a database transaction.
// If the function returns an error, the transaction is rolled back.
// If the function panics, the transaction is rolled back and the panic is re-raised.
// Otherwise, the transaction is committed.
//
// The transaction is stored in the context and can be retrieved using GetTx.
// Repository methods should use GetTx to determine whether to use the transaction or pool.
func (t *Transactor) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	// Check if we're already in a transaction
	if tx := getTx(ctx); tx != nil {
		// Nested transaction - just execute the function
		return fn(ctx)
	}

	// Begin transaction
	tx, err := t.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure rollback on panic or error
	defer func() {
		if p := recover(); p != nil {
			// Best effort rollback on panic - error can be safely ignored since we're re-panicking
			_ = tx.Rollback(ctx) //nolint:errcheck // intentional - panic recovery path
			panic(p)             // re-raise panic
		}
	}()

	// Store transaction in context
	txCtx := context.WithValue(ctx, txKey{}, tx)

	// Execute function
	if err := fn(txCtx); err != nil {
		if rbErr := tx.Rollback(ctx); rbErr != nil {
			return fmt.Errorf("transaction error: %w, rollback error: %v", err, rbErr)
		}
		return err
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// getTx retrieves the transaction from context if it exists.
func getTx(ctx context.Context) pgx.Tx {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return tx
	}
	return nil
}

// getQuerier returns either the transaction from context or the pool.
// This allows repository methods to work both within and outside transactions.
func getQuerier(ctx context.Context, pool *pgxpool.Pool) querier {
	if tx := getTx(ctx); tx != nil {
		return tx
	}
	return pool
}

// querier is an interface that both pgxpool.Pool and pgx.Tx implement.
// This allows us to use the same query methods for both transactional and non-transactional operations.
type querier interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

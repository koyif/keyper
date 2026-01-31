package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/koyif/keyper/internal/server/repository"
)

func classifyRowsAffectedError(ctx context.Context, conn querier, err error, rowsAffected int64, secretID uuid.UUID) error {
	if err != nil {
		return fmt.Errorf("operation failed: %w", err)
	}

	if rowsAffected == 0 {
		exists, checkErr := secretExists(ctx, conn, secretID)
		if checkErr != nil {
			return checkErr
		}
		if !exists {
			return repository.ErrNotFound
		}
		return repository.ErrVersionConflict
	}

	return nil
}

func secretExists(ctx context.Context, conn querier, secretID uuid.UUID) (bool, error) {
	var exists bool
	query := `SELECT EXISTS(SELECT 1 FROM secrets WHERE id = $1 AND is_deleted = false)`
	err := conn.QueryRow(ctx, query, secretID).Scan(&exists)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check secret existence: %w", err)
	}
	return exists, nil
}

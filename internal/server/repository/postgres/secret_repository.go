package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koyif/keyper/internal/server/repository"
)

// SecretRepository implements secret data access operations using PostgreSQL.
type SecretRepository struct {
	pool *pgxpool.Pool
}

// NewSecretRepository creates a new SecretRepository instance.
func NewSecretRepository(pool *pgxpool.Pool) *SecretRepository {
	return &SecretRepository{
		pool: pool,
	}
}

// Create creates a new secret and returns the created secret with generated ID and version 1.
func (r *SecretRepository) Create(ctx context.Context, secret *repository.Secret) (*repository.Secret, error) {
	query := `
		INSERT INTO secrets (user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted)
		VALUES ($1, $2, $3, $4, $5, $6, 1, false)
		RETURNING id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
	`

	q := getQuerier(ctx, r.pool)
	var result repository.Secret
	err := q.QueryRow(
		ctx,
		query,
		secret.UserID,
		secret.Name,
		secret.Type,
		secret.EncryptedData,
		secret.Nonce,
		secret.Metadata,
	).Scan(
		&result.ID,
		&result.UserID,
		&result.Name,
		&result.Type,
		&result.EncryptedData,
		&result.Nonce,
		&result.Metadata,
		&result.Version,
		&result.IsDeleted,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}

	return &result, nil
}

// Get retrieves a secret by ID.
// Returns repository.ErrNotFound if the secret doesn't exist or is deleted.
func (r *SecretRepository) Get(ctx context.Context, id uuid.UUID) (*repository.Secret, error) {
	query := `
		SELECT id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
		FROM secrets
		WHERE id = $1 AND is_deleted = false
	`

	q := getQuerier(ctx, r.pool)
	var secret repository.Secret
	err := q.QueryRow(ctx, query, id).Scan(
		&secret.ID,
		&secret.UserID,
		&secret.Name,
		&secret.Type,
		&secret.EncryptedData,
		&secret.Nonce,
		&secret.Metadata,
		&secret.Version,
		&secret.IsDeleted,
		&secret.CreatedAt,
		&secret.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	return &secret, nil
}

// Update updates an existing secret using optimistic locking.
// Returns repository.ErrVersionConflict if the version doesn't match (indicating concurrent update).
// Returns repository.ErrNotFound if the secret doesn't exist.
// The version is automatically incremented on successful update.
func (r *SecretRepository) Update(ctx context.Context, secret *repository.Secret) (*repository.Secret, error) {
	query := `
		UPDATE secrets
		SET name = $1, type = $2, encrypted_data = $3, nonce = $4, metadata = $5,
		    version = version + 1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $6 AND version = $7 AND is_deleted = false
		RETURNING id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
	`

	q := getQuerier(ctx, r.pool)
	var result repository.Secret
	err := q.QueryRow(
		ctx,
		query,
		secret.Name,
		secret.Type,
		secret.EncryptedData,
		secret.Nonce,
		secret.Metadata,
		secret.ID,
		secret.Version,
	).Scan(
		&result.ID,
		&result.UserID,
		&result.Name,
		&result.Type,
		&result.EncryptedData,
		&result.Nonce,
		&result.Metadata,
		&result.Version,
		&result.IsDeleted,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Check if secret exists to differentiate between not found and version conflict
			var exists bool
			checkQuery := `SELECT EXISTS(SELECT 1 FROM secrets WHERE id = $1 AND is_deleted = false)`
			if err := q.QueryRow(ctx, checkQuery, secret.ID).Scan(&exists); err != nil {
				return nil, fmt.Errorf("failed to check secret existence: %w", err)
			}
			if !exists {
				return nil, repository.ErrNotFound
			}
			return nil, repository.ErrVersionConflict
		}
		return nil, fmt.Errorf("failed to update secret: %w", err)
	}

	return &result, nil
}

// Delete performs a soft delete by setting is_deleted=true.
// Returns repository.ErrNotFound if the secret doesn't exist.
// Uses optimistic locking to prevent concurrent modification issues.
func (r *SecretRepository) Delete(ctx context.Context, id uuid.UUID, currentVersion int64) error {
	query := `
		UPDATE secrets
		SET is_deleted = true, version = version + 1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND version = $2 AND is_deleted = false
	`

	q := getQuerier(ctx, r.pool)
	result, err := q.Exec(ctx, query, id, currentVersion)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	if result.RowsAffected() == 0 {
		// Check if secret exists to differentiate between not found and version conflict
		var exists bool
		checkQuery := `SELECT EXISTS(SELECT 1 FROM secrets WHERE id = $1 AND is_deleted = false)`
		if err := q.QueryRow(ctx, checkQuery, id).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check secret existence: %w", err)
		}
		if !exists {
			return repository.ErrNotFound
		}
		return repository.ErrVersionConflict
	}

	return nil
}

// ListByUser retrieves all non-deleted secrets for a user.
// Results are ordered by updated_at DESC.
func (r *SecretRepository) ListByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*repository.Secret, error) {
	if limit <= 0 {
		limit = 100 // Default limit
	}
	if offset < 0 {
		offset = 0
	}

	query := `
		SELECT id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
		FROM secrets
		WHERE user_id = $1 AND is_deleted = false
		ORDER BY updated_at DESC
		LIMIT $2 OFFSET $3
	`

	q := getQuerier(ctx, r.pool)
	rows, err := q.Query(ctx, query, userID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets by user: %w", err)
	}
	defer rows.Close()

	var secrets []*repository.Secret
	for rows.Next() {
		var secret repository.Secret
		if err := rows.Scan(
			&secret.ID,
			&secret.UserID,
			&secret.Name,
			&secret.Type,
			&secret.EncryptedData,
			&secret.Nonce,
			&secret.Metadata,
			&secret.Version,
			&secret.IsDeleted,
			&secret.CreatedAt,
			&secret.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}
		secrets = append(secrets, &secret)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating secrets: %w", err)
	}

	return secrets, nil
}

// ListModifiedSince retrieves all secrets (including soft-deleted) modified since a timestamp.
// This is used for sync operations. Results include both created, updated, and deleted items.
// Returns secrets ordered by updated_at ASC for cursor-based pagination.
func (r *SecretRepository) ListModifiedSince(ctx context.Context, userID uuid.UUID, since time.Time, limit int) ([]*repository.Secret, error) {
	if limit <= 0 {
		limit = 100 // Default limit
	}

	query := `
		SELECT id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
		FROM secrets
		WHERE user_id = $1 AND updated_at > $2
		ORDER BY updated_at ASC
		LIMIT $3
	`

	q := getQuerier(ctx, r.pool)
	rows, err := q.Query(ctx, query, userID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to list modified secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*repository.Secret
	for rows.Next() {
		var secret repository.Secret
		if err := rows.Scan(
			&secret.ID,
			&secret.UserID,
			&secret.Name,
			&secret.Type,
			&secret.EncryptedData,
			&secret.Nonce,
			&secret.Metadata,
			&secret.Version,
			&secret.IsDeleted,
			&secret.CreatedAt,
			&secret.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}
		secrets = append(secrets, &secret)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating secrets: %w", err)
	}

	return secrets, nil
}

// HardDeleteTombstones permanently removes soft-deleted secrets older than the specified time.
// This is used by the background cleanup job to purge tombstones after the retention period.
// Deletes in batches to avoid long-running transactions and excessive table locks.
// Returns the number of records deleted.
func (r *SecretRepository) HardDeleteTombstones(ctx context.Context, olderThan time.Time, batchSize int) (int, error) {
	if batchSize <= 0 {
		batchSize = 1000
	}

	query := `
		DELETE FROM secrets
		WHERE id IN (
			SELECT id
			FROM secrets
			WHERE is_deleted = true AND updated_at < $1
			ORDER BY updated_at ASC
			LIMIT $2
		)
	`

	q := getQuerier(ctx, r.pool)
	result, err := q.Exec(ctx, query, olderThan, batchSize)
	if err != nil {
		return 0, fmt.Errorf("failed to hard delete tombstones: %w", err)
	}

	deletedCount := int(result.RowsAffected())
	return deletedCount, nil
}

package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteRepository implements the Repository interface using SQLite
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new SQLite repository
func NewSQLiteRepository(dbPath string) (*SQLiteRepository, error) {
	// Open database with SQLite URI
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s?cache=shared&mode=rwc&_journal_mode=WAL", dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(1) // SQLite works best with single connection
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Verify connection
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	repo := &SQLiteRepository{db: db}

	// Run migrations
	if err := repo.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return repo, nil
}

// migrate runs database migrations
func (r *SQLiteRepository) migrate() error {
	ctx := context.Background()
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Create schema_migrations table
	if _, err := tx.Exec(createSchemaMigrationsTableSQL); err != nil {
		return fmt.Errorf("failed to create schema_migrations table: %w", err)
	}

	// Get current schema version
	var currentVersion int
	err = tx.QueryRow(getCurrentVersionSQL).Scan(&currentVersion)
	if err != nil {
		return fmt.Errorf("failed to get current schema version: %w", err)
	}

	// Run migrations in order
	migrations := []struct {
		version int
		sql     []string
	}{
		{
			version: 1,
			sql: []string{
				createSecretsTableSQL,
				createSecretsTypeIndexSQL,
				createSecretsSyncStatusIndexSQL,
				createSecretsUpdatedAtIndexSQL,
				createSecretsNameIndexSQL,
			},
		},
	}

	for _, migration := range migrations {
		if currentVersion >= migration.version {
			continue
		}

		// Execute migration SQL statements
		for _, statement := range migration.sql {
			if _, err := tx.Exec(statement); err != nil {
				return fmt.Errorf("failed to execute migration %d: %w", migration.version, err)
			}
		}

		// Record migration
		if _, err := tx.Exec(insertMigrationSQL, migration.version); err != nil {
			return fmt.Errorf("failed to record migration %d: %w", migration.version, err)
		}
	}

	return tx.Commit()
}

// Create creates a new secret
func (r *SQLiteRepository) Create(ctx context.Context, secret *LocalSecret) error {
	query := `
		INSERT INTO secrets (
			id, name, type, encrypted_data, nonce, metadata,
			version, is_deleted, sync_status, server_version,
			created_at, updated_at, local_updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	if secret.CreatedAt.IsZero() {
		secret.CreatedAt = now
	}
	if secret.UpdatedAt.IsZero() {
		secret.UpdatedAt = now
	}
	if secret.LocalUpdatedAt.IsZero() {
		secret.LocalUpdatedAt = now
	}
	if secret.Version == 0 {
		secret.Version = 1
	}
	if secret.SyncStatus == "" {
		secret.SyncStatus = SyncStatusPending
	}

	_, err := r.db.ExecContext(ctx, query,
		secret.ID, secret.Name, secret.Type, secret.EncryptedData, secret.Nonce,
		secret.Metadata, secret.Version, secret.IsDeleted, secret.SyncStatus,
		secret.ServerVersion, secret.CreatedAt, secret.UpdatedAt, secret.LocalUpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	return nil
}

// Get retrieves a secret by ID
func (r *SQLiteRepository) Get(ctx context.Context, id string) (*LocalSecret, error) {
	query := `
		SELECT id, name, type, encrypted_data, nonce, metadata,
		       version, is_deleted, sync_status, server_version,
		       created_at, updated_at, local_updated_at
		FROM secrets
		WHERE id = ?
	`

	secret := &LocalSecret{}
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&secret.ID, &secret.Name, &secret.Type, &secret.EncryptedData, &secret.Nonce,
		&secret.Metadata, &secret.Version, &secret.IsDeleted, &secret.SyncStatus,
		&secret.ServerVersion, &secret.CreatedAt, &secret.UpdatedAt, &secret.LocalUpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("secret not found: %s", id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	return secret, nil
}

// GetByName retrieves a secret by name
func (r *SQLiteRepository) GetByName(ctx context.Context, name string) (*LocalSecret, error) {
	query := `
		SELECT id, name, type, encrypted_data, nonce, metadata,
		       version, is_deleted, sync_status, server_version,
		       created_at, updated_at, local_updated_at
		FROM secrets
		WHERE name = ? AND is_deleted = 0
		ORDER BY created_at DESC
		LIMIT 1
	`

	secret := &LocalSecret{}
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&secret.ID, &secret.Name, &secret.Type, &secret.EncryptedData, &secret.Nonce,
		&secret.Metadata, &secret.Version, &secret.IsDeleted, &secret.SyncStatus,
		&secret.ServerVersion, &secret.CreatedAt, &secret.UpdatedAt, &secret.LocalUpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("secret not found: %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get secret by name: %w", err)
	}

	return secret, nil
}

// Update updates an existing secret
func (r *SQLiteRepository) Update(ctx context.Context, secret *LocalSecret) error {
	query := `
		UPDATE secrets
		SET name = ?, type = ?, encrypted_data = ?, nonce = ?, metadata = ?,
		    version = ?, is_deleted = ?, sync_status = ?, server_version = ?,
		    updated_at = ?, local_updated_at = ?
		WHERE id = ?
	`

	secret.LocalUpdatedAt = time.Now()
	if secret.SyncStatus == SyncStatusSynced {
		secret.SyncStatus = SyncStatusPending
	}

	result, err := r.db.ExecContext(ctx, query,
		secret.Name, secret.Type, secret.EncryptedData, secret.Nonce, secret.Metadata,
		secret.Version, secret.IsDeleted, secret.SyncStatus, secret.ServerVersion,
		secret.UpdatedAt, secret.LocalUpdatedAt, secret.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("secret not found: %s", secret.ID)
	}

	return nil
}

// Delete soft-deletes a secret (sets is_deleted flag)
func (r *SQLiteRepository) Delete(ctx context.Context, id string) error {
	query := `
		UPDATE secrets
		SET is_deleted = 1, sync_status = ?, local_updated_at = ?
		WHERE id = ?
	`

	result, err := r.db.ExecContext(ctx, query, SyncStatusPending, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("secret not found: %s", id)
	}

	return nil
}

// HardDelete permanently removes a secret from the database
func (r *SQLiteRepository) HardDelete(ctx context.Context, id string) error {
	query := `DELETE FROM secrets WHERE id = ?`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to hard delete secret: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("secret not found: %s", id)
	}

	return nil
}

// List retrieves all secrets with optional filters
func (r *SQLiteRepository) List(ctx context.Context, filters ListFilters) ([]*LocalSecret, error) {
	query := `
		SELECT id, name, type, encrypted_data, nonce, metadata,
		       version, is_deleted, sync_status, server_version,
		       created_at, updated_at, local_updated_at
		FROM secrets
		WHERE 1=1
	`
	args := []interface{}{}

	if filters.Type != nil {
		query += " AND type = ?"
		args = append(args, *filters.Type)
	}

	if filters.SyncStatus != nil {
		query += " AND sync_status = ?"
		args = append(args, *filters.SyncStatus)
	}

	if !filters.IncludeDeleted {
		query += " AND is_deleted = 0"
	}

	query += " ORDER BY created_at DESC"

	if filters.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filters.Limit)
	}

	if filters.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filters.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*LocalSecret
	for rows.Next() {
		secret := &LocalSecret{}
		err := rows.Scan(
			&secret.ID, &secret.Name, &secret.Type, &secret.EncryptedData, &secret.Nonce,
			&secret.Metadata, &secret.Version, &secret.IsDeleted, &secret.SyncStatus,
			&secret.ServerVersion, &secret.CreatedAt, &secret.UpdatedAt, &secret.LocalUpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}
		secrets = append(secrets, secret)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating secrets: %w", err)
	}

	return secrets, nil
}

// GetPendingSync retrieves all secrets that need to be synced
func (r *SQLiteRepository) GetPendingSync(ctx context.Context) ([]*LocalSecret, error) {
	syncStatus := SyncStatusPending
	return r.List(ctx, ListFilters{
		SyncStatus:     &syncStatus,
		IncludeDeleted: true, // Include deleted items for sync
	})
}

// UpdateSyncStatus updates the sync status of a secret
func (r *SQLiteRepository) UpdateSyncStatus(ctx context.Context, id string, status SyncStatus, serverVersion int64) error {
	query := `
		UPDATE secrets
		SET sync_status = ?, server_version = ?
		WHERE id = ?
	`

	result, err := r.db.ExecContext(ctx, query, status, serverVersion, id)
	if err != nil {
		return fmt.Errorf("failed to update sync status: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("secret not found: %s", id)
	}

	return nil
}

// Close closes the database connection
func (r *SQLiteRepository) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

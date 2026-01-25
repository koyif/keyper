package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	// Register SQLite driver for database/sql
	_ "modernc.org/sqlite"
)

// SQLiteRepository implements the Repository interface using SQLite.
type SQLiteRepository struct {
	db *sql.DB
}

// NewSQLiteRepository creates a new SQLite repository.
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

// migrate runs database migrations.
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
		{
			version: 2,
			sql: []string{
				createConflictsTableSQL,
				createConflictsSecretIDIndexSQL,
				createConflictsResolvedIndexSQL,
			},
		},
		{
			version: 3,
			sql: []string{
				// Remove foreign key constraint by recreating conflicts table
				// SQLite doesn't support ALTER TABLE DROP CONSTRAINT, so we need to recreate
				`CREATE TABLE conflicts_new (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					secret_id TEXT NOT NULL,
					conflict_type INTEGER NOT NULL,
					local_version INTEGER NOT NULL,
					server_version INTEGER NOT NULL,
					local_data BLOB NOT NULL,
					server_data BLOB NOT NULL,
					local_updated_at TIMESTAMP NOT NULL,
					server_updated_at TIMESTAMP NOT NULL,
					detected_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
					resolved BOOLEAN NOT NULL DEFAULT 0,
					resolved_at TIMESTAMP,
					resolution_strategy TEXT
				)`,
				`INSERT INTO conflicts_new (id, secret_id, conflict_type, local_version, server_version, local_data, server_data, local_updated_at, server_updated_at, detected_at, resolved, resolved_at, resolution_strategy)
				 SELECT id, secret_id, conflict_type, local_version, server_version, local_data, server_data, local_updated_at, server_updated_at, detected_at, resolved, resolved_at, resolution_strategy FROM conflicts`,
				`DROP TABLE conflicts`,
				`ALTER TABLE conflicts_new RENAME TO conflicts`,
				createConflictsSecretIDIndexSQL,
				createConflictsResolvedIndexSQL,
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

// Create creates a new secret.
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

// Get retrieves a secret by ID.
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
		return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	return secret, nil
}

// GetByName retrieves a secret by name.
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
		return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, name)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get secret by name: %w", err)
	}

	return secret, nil
}

// Update updates an existing secret.
func (r *SQLiteRepository) Update(ctx context.Context, secret *LocalSecret) error {
	query := `
		UPDATE secrets
		SET name = ?, type = ?, encrypted_data = ?, nonce = ?, metadata = ?,
		    version = ?, is_deleted = ?, sync_status = ?, server_version = ?,
		    updated_at = ?, local_updated_at = ?
		WHERE id = ?
	`

	secret.LocalUpdatedAt = time.Now()

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
		return fmt.Errorf("%w: %s", ErrSecretNotFound, secret.ID)
	}

	return nil
}

// Delete soft-deletes a secret (sets is_deleted flag).
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
		return fmt.Errorf("%w: %s", ErrSecretNotFound, id)
	}

	return nil
}

// HardDelete permanently removes a secret from the database.
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
		return fmt.Errorf("%w: %s", ErrSecretNotFound, id)
	}

	return nil
}

// List retrieves all secrets with optional filters.
func (r *SQLiteRepository) List(ctx context.Context, filters ListFilters) ([]*LocalSecret, error) {
	query := `
		SELECT id, name, type, encrypted_data, nonce, metadata,
		       version, is_deleted, sync_status, server_version,
		       created_at, updated_at, local_updated_at
		FROM secrets
		WHERE 1=1
	`
	args := []any{}

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

// GetPendingSync retrieves all secrets that need to be synced.
func (r *SQLiteRepository) GetPendingSync(ctx context.Context) ([]*LocalSecret, error) {
	syncStatus := SyncStatusPending
	return r.List(ctx, ListFilters{
		SyncStatus:     &syncStatus,
		IncludeDeleted: true, // Include deleted items for sync
	})
}

// UpdateSyncStatus updates the sync status of a secret.
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
		return fmt.Errorf("%w: %s", ErrSecretNotFound, id)
	}

	return nil
}

// Close closes the database connection.
func (r *SQLiteRepository) Close() error {
	if r.db != nil {
		return r.db.Close()
	}
	return nil
}

// BeginTx begins a new transaction.
func (r *SQLiteRepository) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return r.db.BeginTx(ctx, nil)
}

// CreateInTx creates a secret within a transaction.
func (r *SQLiteRepository) CreateInTx(ctx context.Context, tx *sql.Tx, secret *LocalSecret) error {
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

	_, err := tx.ExecContext(ctx, query,
		secret.ID, secret.Name, secret.Type, secret.EncryptedData, secret.Nonce,
		secret.Metadata, secret.Version, secret.IsDeleted, secret.SyncStatus,
		secret.ServerVersion, secret.CreatedAt, secret.UpdatedAt, secret.LocalUpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create secret in transaction: %w", err)
	}

	return nil
}

// GetInTx retrieves a secret by ID within a transaction.
func (r *SQLiteRepository) GetInTx(ctx context.Context, tx *sql.Tx, id string) (*LocalSecret, error) {
	query := `
		SELECT id, name, type, encrypted_data, nonce, metadata,
		       version, is_deleted, sync_status, server_version,
		       created_at, updated_at, local_updated_at
		FROM secrets
		WHERE id = ?
	`

	secret := &LocalSecret{}
	err := tx.QueryRowContext(ctx, query, id).Scan(
		&secret.ID, &secret.Name, &secret.Type, &secret.EncryptedData, &secret.Nonce,
		&secret.Metadata, &secret.Version, &secret.IsDeleted, &secret.SyncStatus,
		&secret.ServerVersion, &secret.CreatedAt, &secret.UpdatedAt, &secret.LocalUpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrSecretNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get secret in transaction: %w", err)
	}

	return secret, nil
}

// UpdateInTx updates a secret within a transaction.
func (r *SQLiteRepository) UpdateInTx(ctx context.Context, tx *sql.Tx, secret *LocalSecret) error {
	query := `
		UPDATE secrets
		SET name = ?, type = ?, encrypted_data = ?, nonce = ?, metadata = ?,
		    version = ?, is_deleted = ?, sync_status = ?, server_version = ?,
		    updated_at = ?, local_updated_at = ?
		WHERE id = ?
	`

	secret.LocalUpdatedAt = time.Now()

	result, err := tx.ExecContext(ctx, query,
		secret.Name, secret.Type, secret.EncryptedData, secret.Nonce, secret.Metadata,
		secret.Version, secret.IsDeleted, secret.SyncStatus, secret.ServerVersion,
		secret.UpdatedAt, secret.LocalUpdatedAt, secret.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update secret in transaction: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrSecretNotFound, secret.ID)
	}

	return nil
}

// HardDeleteInTx permanently removes a secret within a transaction.
func (r *SQLiteRepository) HardDeleteInTx(ctx context.Context, tx *sql.Tx, id string) error {
	query := `DELETE FROM secrets WHERE id = ?`

	result, err := tx.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to hard delete secret in transaction: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrSecretNotFound, id)
	}

	return nil
}

// CreateConflict stores a conflict for later resolution.
func (r *SQLiteRepository) CreateConflict(ctx context.Context, conflict *Conflict) error {
	tx, err := r.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		// nolint:errcheck // Rollback error is expected to fail after Commit
		_ = tx.Rollback()
	}()

	if err := r.CreateConflictInTx(ctx, tx, conflict); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetUnresolvedConflicts retrieves all unresolved conflicts.
func (r *SQLiteRepository) GetUnresolvedConflicts(ctx context.Context) ([]*Conflict, error) {
	query := `
		SELECT id, secret_id, conflict_type, local_version, server_version,
		       local_data, server_data, local_updated_at, server_updated_at,
		       detected_at, resolved, resolved_at, resolution_strategy
		FROM conflicts
		WHERE resolved = 0
		ORDER BY detected_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query unresolved conflicts: %w", err)
	}
	defer rows.Close()

	var conflicts []*Conflict
	for rows.Next() {
		conflict := &Conflict{}
		err := rows.Scan(
			&conflict.ID, &conflict.SecretID, &conflict.ConflictType,
			&conflict.LocalVersion, &conflict.ServerVersion,
			&conflict.LocalData, &conflict.ServerData,
			&conflict.LocalUpdatedAt, &conflict.ServerUpdatedAt,
			&conflict.DetectedAt, &conflict.Resolved,
			&conflict.ResolvedAt, &conflict.ResolutionStrategy,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan conflict: %w", err)
		}
		conflicts = append(conflicts, conflict)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating conflicts: %w", err)
	}

	return conflicts, nil
}

// ResolveConflict marks a conflict as resolved.
func (r *SQLiteRepository) ResolveConflict(ctx context.Context, id int64, strategy string) error {
	query := `
		UPDATE conflicts
		SET resolved = 1, resolved_at = ?, resolution_strategy = ?
		WHERE id = ?
	`

	result, err := r.db.ExecContext(ctx, query, time.Now(), strategy, id)
	if err != nil {
		return fmt.Errorf("failed to resolve conflict: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %d", ErrConflictNotFound, id)
	}

	return nil
}

// CreateConflictInTx stores a conflict within a transaction.
func (r *SQLiteRepository) CreateConflictInTx(ctx context.Context, tx *sql.Tx, conflict *Conflict) error {
	query := `
		INSERT INTO conflicts (
			secret_id, conflict_type, local_version, server_version,
			local_data, server_data, local_updated_at, server_updated_at,
			detected_at, resolved, resolution_strategy
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	if conflict.DetectedAt.IsZero() {
		conflict.DetectedAt = time.Now()
	}

	result, err := tx.ExecContext(ctx, query,
		conflict.SecretID, conflict.ConflictType, conflict.LocalVersion, conflict.ServerVersion,
		conflict.LocalData, conflict.ServerData, conflict.LocalUpdatedAt, conflict.ServerUpdatedAt,
		conflict.DetectedAt, conflict.Resolved, conflict.ResolutionStrategy,
	)
	if err != nil {
		return fmt.Errorf("failed to create conflict in transaction: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get conflict ID: %w", err)
	}

	conflict.ID = id
	return nil
}

package storage

// Schema definitions for the SQLite database

const (
	// CurrentSchemaVersion is the schema version for migrations.
	CurrentSchemaVersion = 3

	// createSecretsTableSQL contains the table creation SQL statement.
	//nolint:gosec // G101: False positive - SQL schema definition, not hardcoded credentials
	createSecretsTableSQL = `
		CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type INTEGER NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL,
			metadata TEXT,
			version INTEGER NOT NULL DEFAULT 1,
			is_deleted BOOLEAN NOT NULL DEFAULT 0,
			sync_status TEXT NOT NULL DEFAULT 'pending',
			server_version INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			local_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`

	createConflictsTableSQL = `
		CREATE TABLE IF NOT EXISTS conflicts (
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
		);
	`

	createSchemaMigrationsTableSQL = `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`

	// createSecretsTypeIndexSQL contains the index creation SQL statement.
	//nolint:gosec // G101: False positive - SQL index definition, not hardcoded credentials
	createSecretsTypeIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(type);
	`

	//nolint:gosec // G101: False positive - SQL index definition, not hardcoded credentials
	createSecretsSyncStatusIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_secrets_sync_status ON secrets(sync_status);
	`

	//nolint:gosec // G101: False positive - SQL index definition, not hardcoded credentials
	createSecretsUpdatedAtIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_secrets_updated_at ON secrets(updated_at);
	`

	//nolint:gosec // G101: False positive - SQL index definition, not hardcoded credentials
	createSecretsNameIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
	`

	//nolint:gosec // G101: False positive - SQL index definition, not hardcoded credentials
	createConflictsSecretIDIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_conflicts_secret_id ON conflicts(secret_id);
	`

	createConflictsResolvedIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_conflicts_resolved ON conflicts(resolved);
	`

	// insertMigrationSQL contains the schema migration query.
	insertMigrationSQL = `
		INSERT INTO schema_migrations (version) VALUES (?);
	`

	getCurrentVersionSQL = `
		SELECT COALESCE(MAX(version), 0) FROM schema_migrations;
	`
)

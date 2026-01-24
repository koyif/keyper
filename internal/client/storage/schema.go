package storage

// Schema definitions for the SQLite database

const (
	// Schema version for migrations
	CurrentSchemaVersion = 1

	// Table creation SQL statements
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

	createSchemaMigrationsTableSQL = `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`

	// Index creation SQL statements
	createSecretsTypeIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_secrets_type ON secrets(type);
	`

	createSecretsSyncStatusIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_secrets_sync_status ON secrets(sync_status);
	`

	createSecretsUpdatedAtIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_secrets_updated_at ON secrets(updated_at);
	`

	createSecretsNameIndexSQL = `
		CREATE INDEX IF NOT EXISTS idx_secrets_name ON secrets(name);
	`

	// Schema migration queries
	insertMigrationSQL = `
		INSERT INTO schema_migrations (version) VALUES (?);
	`

	getCurrentVersionSQL = `
		SELECT COALESCE(MAX(version), 0) FROM schema_migrations;
	`
)

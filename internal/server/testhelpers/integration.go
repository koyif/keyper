package testhelpers

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	pg "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/koyif/keyper/internal/server/db"
)

const (
	postgresImage    = "postgres:16-alpine"
	postgresUser     = "testuser"
	postgresPassword = "testpass"
	postgresDatabase = "testdb"
)

// TestContainer wraps the PostgreSQL testcontainer with helper methods.
type TestContainer struct {
	container *pg.PostgresContainer
	connStr   string
	pool      *pgxpool.Pool
}

// NewTestContainer creates a new PostgreSQL test container with migrations applied.
// The container will be automatically cleaned up when the test completes.
func NewTestContainer(ctx context.Context, t *testing.T) *TestContainer {
	t.Helper()

	// Check if Docker is available before attempting to start container.
	container, err := pg.Run(
		ctx,
		postgresImage,
		pg.WithDatabase(postgresDatabase),
		pg.WithUsername(postgresUser),
		pg.WithPassword(postgresPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	require.NoError(t, err, "failed to start PostgreSQL container")

	// Ensure cleanup happens when test completes.
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	})

	// Get connection string with sslmode=disable.
	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "failed to get connection string")

	tc := &TestContainer{
		container: container,
		connStr:   connStr,
	}

	// Run migrations.
	tc.runMigrations(t)

	// Create connection pool.
	tc.pool = tc.createPool(ctx, t)

	return tc
}

// runMigrations executes database migrations from the migrations directory.
func (tc *TestContainer) runMigrations(t *testing.T) {
	t.Helper()

	// Open database connection using database/sql for migrations.
	sqlDB, err := sql.Open("pgx", tc.connStr)
	require.NoError(t, err, "failed to open database connection")

	defer sqlDB.Close()

	// Create migration driver.
	driver, err := postgres.WithInstance(sqlDB, &postgres.Config{})
	require.NoError(t, err, "failed to create migration driver")

	// Get absolute path to migrations directory.
	// We search upwards from current directory to find migrations folder.
	migrationsPath, err := findMigrationsDir()
	require.NoError(t, err, "failed to get migrations path")

	// Create migrate instance.
	m, err := migrate.NewWithDatabaseInstance(
		fmt.Sprintf("file://%s", migrationsPath),
		"postgres",
		driver,
	)
	require.NoError(t, err, "failed to create migrate instance")

	defer m.Close()

	// Run all migrations.
	err = m.Up()
	require.NoError(t, err, "failed to run migrations")

	// Verify migrations completed successfully.
	version, dirty, err := m.Version()
	require.NoError(t, err, "failed to get migration version")
	require.False(t, dirty, "database is in dirty state at version %d", version)

	t.Logf("Database migrations completed successfully (version: %d)", version)
}

// createPool creates a pgxpool connection pool for the test database.
func (tc *TestContainer) createPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()

	config, err := pgxpool.ParseConfig(tc.connStr)
	require.NoError(t, err, "failed to parse connection string")

	// Configure pool with test-appropriate settings.
	config.MaxConns = 10
	config.MinConns = 2
	config.MaxConnLifetime = time.Hour
	config.MaxConnIdleTime = 30 * time.Minute
	config.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err, "failed to create connection pool")

	// Verify connection works.
	require.NoError(t, pool.Ping(ctx), "failed to ping database")

	// Cleanup pool when test completes.
	t.Cleanup(func() {
		pool.Close()
	})

	return pool
}

// Pool returns the pgxpool connection pool.
func (tc *TestContainer) Pool() *pgxpool.Pool {
	return tc.pool
}

// ConnectionString returns the database connection string.
func (tc *TestContainer) ConnectionString() string {
	return tc.connStr
}

// Config returns a db.Config for the test database.
func (tc *TestContainer) Config(t *testing.T) *db.Config {
	t.Helper()

	ctx := context.Background()
	host, err := tc.container.Host(ctx)
	require.NoError(t, err, "failed to get container host")

	port, err := tc.container.MappedPort(ctx, "5432")
	require.NoError(t, err, "failed to get mapped port")

	return &db.Config{
		Host:              host,
		Port:              port.Int(),
		User:              postgresUser,
		Password:          postgresPassword,
		Database:          postgresDatabase,
		SSLMode:           "disable",
		MaxConns:          10,
		MinConns:          2,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
	}
}

// Exec executes a SQL statement and returns the result.
func (tc *TestContainer) Exec(ctx context.Context, t *testing.T, query string, args ...interface{}) {
	t.Helper()

	_, err := tc.pool.Exec(ctx, query, args...)
	require.NoError(t, err, "failed to execute query: %s", query)
}

// Query executes a query that returns rows.
func (tc *TestContainer) Query(ctx context.Context, t *testing.T, query string, args ...interface{}) *sql.Rows {
	t.Helper()

	// Get a database/sql connection from the pool for compatibility with sql.Rows.
	sqlDB := stdlib.OpenDB(*tc.pool.Config().ConnConfig)

	t.Cleanup(func() { sqlDB.Close() })

	rows, err := sqlDB.QueryContext(ctx, query, args...)
	require.NoError(t, err, "failed to execute query: %s", query)

	return rows
}

// Truncate truncates all tables in the database for test isolation.
// This is useful for running multiple tests against the same container.
func (tc *TestContainer) Truncate(ctx context.Context, t *testing.T, tables ...string) {
	t.Helper()

	for _, table := range tables {
		tc.Exec(ctx, t, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
	}
}

// findMigrationsDir searches for the migrations directory by walking up from the current directory.
// It looks for a "migrations" directory that contains .sql files.
func findMigrationsDir() (string, error) {
	// Start from current working directory.
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}

	// Walk up the directory tree looking for migrations folder.
	for {
		migrationsPath := filepath.Join(dir, "migrations")

		// Check if migrations directory exists.
		if info, err := os.Stat(migrationsPath); err == nil && info.IsDir() {
			// Verify it contains migration files.
			entries, err := os.ReadDir(migrationsPath)
			if err == nil && len(entries) > 0 {
				// Check for .sql files.
				for _, entry := range entries {
					if filepath.Ext(entry.Name()) == ".sql" {
						return migrationsPath, nil
					}
				}
			}
		}

		// Move up one directory.
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached root without finding migrations.
			return "", fmt.Errorf("migrations directory not found")
		}

		dir = parent
	}
}

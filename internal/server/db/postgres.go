package db

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	// Import file driver for migration source
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// Config holds PostgreSQL database configuration.
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string

	// Connection pool settings
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration

	// Migration settings
	SkipMigrations bool   // Skip running migrations (useful for tests)
	MigrationsPath string // Path to migrations directory (defaults to "migrations" if empty)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Host:              "localhost",
		Port:              5432,
		SSLMode:           "disable",
		MaxConns:          25,
		MinConns:          5,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
	}
}

// Pool wraps pgxpool.Pool with additional functionality.
type Pool struct {
	*pgxpool.Pool
	config *Config
}

// NewPool creates a new database connection pool with the given configuration.
// It implements connection retry with exponential backoff and runs health checks.
// If cfg is nil, DefaultConfig() is used (note: default config lacks credentials and will fail to connect).
func NewPool(ctx context.Context, cfg *Config) (*Pool, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Database, cfg.SSLMode,
	)

	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	// Configure pool settings
	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MinConns = cfg.MinConns
	poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolConfig.HealthCheckPeriod = cfg.HealthCheckPeriod

	// Set up connection initialization hook
	poolConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		// Set timezone to UTC for consistency
		_, err := conn.Exec(ctx, "SET timezone = 'UTC'")
		return err
	}

	// Attempt to create pool with retry logic
	const maxRetries = 5
	var pool *pgxpool.Pool
	backoff := time.Second

	for i := range maxRetries {
		pool, err = pgxpool.NewWithConfig(ctx, poolConfig)
		if err == nil {
			// Test the connection
			if err = pool.Ping(ctx); err == nil {
				break
			}
			pool.Close()
			err = fmt.Errorf("ping failed: %w", err)
		}

		if i < maxRetries-1 {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database after %d retries: %w", maxRetries, err)
	}

	p := &Pool{
		Pool:   pool,
		config: cfg,
	}

	// Run migrations unless skipped.
	if !cfg.SkipMigrations {
		if err := p.runMigrations(ctx); err != nil {
			pool.Close()
			return nil, fmt.Errorf("failed to run migrations: %w", err)
		}
	}

	return p, nil
}

// Health performs a health check on the database connection.
func (p *Pool) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := p.Ping(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	return nil
}

// Stats returns connection pool statistics.
func (p *Pool) Stats() *pgxpool.Stat {
	return p.Stat()
}

// Close closes all connections in the pool.
func (p *Pool) Close() {
	p.Pool.Close()
}

// runMigrations executes database migrations.
// Note: ctx parameter is reserved for future use (e.g., cancellation support).
func (p *Pool) runMigrations(_ context.Context) error {
	// Register pgx driver with database/sql.
	db := stdlib.OpenDB(*p.Pool.Config().ConnConfig)
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	// Use configured migrations path or default to "migrations".
	migrationsPath := "migrations"
	if p.config.MigrationsPath != "" {
		migrationsPath = p.config.MigrationsPath
	}

	// Migrations are expected to be in the migrations/ directory.
	m, err := migrate.NewWithDatabaseInstance(
		"file://"+migrationsPath,
		"postgres",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get migration version: %w", err)
	}

	if dirty {
		return fmt.Errorf("database is in dirty state at version %d", version)
	}

	if err == migrate.ErrNilVersion {
		fmt.Println("Database migrations completed successfully (no migrations found)")
	} else {
		fmt.Printf("Database migrations completed successfully (version: %d)\n", version)
	}

	return nil
}

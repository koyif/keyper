package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	// Import file driver for migration source
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"go.uber.org/zap"
)

type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string

	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration

	SkipMigrations bool
	MigrationsPath string
}

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

type Pool struct {
	*pgxpool.Pool
	config *Config
}

// Implements connection retry with exponential backoff and runs health checks.
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
		if err != nil {
			return fmt.Errorf("failed to set timezone: %w", err) //nolint:wrapcheck // pgx error wrapped
		}

		return nil
	}

	// Attempt to create pool with retry logic
	var pool *pgxpool.Pool
	retryCfg := DefaultRetryConfig()

	err = Retry(ctx, retryCfg, func() error {
		var err error
		pool, err = pgxpool.NewWithConfig(ctx, poolConfig)
		if err != nil {
			return fmt.Errorf("failed to create pool: %w", err)
		}

		// Test the connection
		if err = pool.Ping(ctx); err != nil {
			pool.Close()
			return fmt.Errorf("ping failed: %w", err)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
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

func (p *Pool) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := p.Ping(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}

	return nil
}

func (p *Pool) Stats() *pgxpool.Stat {
	return p.Stat()
}

func (p *Pool) Close() {
	p.Pool.Close()
}

// Note: ctx parameter is reserved for future use (e.g., cancellation support).
func (p *Pool) runMigrations(_ context.Context) error {
	// Register pgx driver with database/sql.
	db := stdlib.OpenDB(*p.Pool.Config().ConnConfig)
	defer db.Close()

	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	migrationsPath := "migrations"
	if p.config.MigrationsPath != "" {
		migrationsPath = p.config.MigrationsPath
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://"+migrationsPath,
		"postgres",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	version, dirty, err := m.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return fmt.Errorf("failed to get migration version: %w", err)
	}

	if dirty {
		return fmt.Errorf("database is in dirty state at version %d", version)
	}

	if errors.Is(err, migrate.ErrNilVersion) {
		zap.L().Info("Database migrations completed successfully (no migrations found)")
	} else {
		zap.L().Info("Database migrations completed successfully", zap.Uint("version", version))
	}

	return nil
}

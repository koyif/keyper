package postgres

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koyif/keyper/internal/server/db"
	"github.com/koyif/keyper/internal/server/repository"
)

// setupTestDB creates a test database connection pool.
// It uses environment variables for configuration:
// - TEST_POSTGRES_HOST (default: localhost).
// - TEST_POSTGRES_PORT (default: 5432).
// - TEST_POSTGRES_USER (default: keyper).
// - TEST_POSTGRES_PASSWORD (default: keyper_dev_password).
// - TEST_POSTGRES_DB (default: keyper_test).
// - TEST_POSTGRES_SSL_MODE (default: disable).
func setupTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	// Get configuration from environment
	host := getEnvOrDefault("TEST_POSTGRES_HOST", "localhost")
	port := getEnvOrDefault("TEST_POSTGRES_PORT", "5432")
	user := getEnvOrDefault("TEST_POSTGRES_USER", "keyper")
	password := getEnvOrDefault("TEST_POSTGRES_PASSWORD", "keyper_dev_password")
	database := getEnvOrDefault("TEST_POSTGRES_DB", "keyper_test")
	sslMode := getEnvOrDefault("TEST_POSTGRES_SSL_MODE", "disable")

	// Build connection string
	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		user, password, host, port, database, sslMode,
	)

	// Parse config
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		t.Fatalf("failed to parse test database config: %v", err)
	}

	// Configure pool settings for tests
	poolConfig.MaxConns = 5
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 10 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute

	// Create pool
	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("failed to create test database pool: %v", err)
	}

	// Ping to verify connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("failed to ping test database: %v", err)
	}

	// Clean up test data before each test
	cleanupTestData(t, pool)

	return pool
}

// cleanupTestData removes all test data from the database.
// This ensures each test starts with a clean slate.
func cleanupTestData(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx := context.Background()

	// Delete in order to respect foreign key constraints
	queries := []string{
		"DELETE FROM refresh_tokens",
		"DELETE FROM secrets",
		"DELETE FROM users",
	}

	for _, query := range queries {
		if _, err := pool.Exec(ctx, query); err != nil {
			t.Fatalf("failed to clean test data: %v", err)
		}
	}
}

// getEnvOrDefault returns the value of an environment variable or a default value.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// createTestUser is a helper function to create a test user in the database.
// It generates a unique email address and uses default test values for other fields.
//
//nolint:revive // t *testing.T conventionally comes first in test helpers
func createTestUser(t *testing.T, ctx context.Context, repo *UserRepository) *repository.User {
	t.Helper()

	email := uuid.New().String() + "@example.com"
	user, err := repo.CreateUser(ctx, repository.CreateUserParams{
		Email:                 email,
		PasswordHash:          []byte("hash"),
		EncryptionKeyVerifier: []byte("verifier"),
		Salt:                  []byte("salt"),
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	return user
}

// createTestSecret is a helper function to create a test secret in the database.
// It generates unique test data for the secret.
//
//nolint:revive // t *testing.T conventionally comes first in test helpers
func createTestSecret(t *testing.T, ctx context.Context, repo *SecretRepository, userID uuid.UUID) *repository.Secret {
	t.Helper()

	secret := &repository.Secret{
		UserID:        userID,
		Name:          "Test Secret " + uuid.New().String(),
		Type:          1,
		EncryptedData: []byte("encrypted_data"),
		Nonce:         []byte("nonce"),
		Metadata:      []byte(`{}`),
	}

	created, err := repo.Create(ctx, secret)
	if err != nil {
		t.Fatalf("failed to create test secret: %v", err)
	}

	return created
}

// setupTestDBWithDB creates a test database connection using the db.Pool wrapper.
// This is useful for testing the db.Pool functionality itself.
//
//nolint:unused // kept for future use in db.Pool integration tests
func setupTestDBWithDB(t *testing.T) *db.Pool {
	t.Helper()

	cfg := &db.Config{
		Host:              getEnvOrDefault("TEST_POSTGRES_HOST", "localhost"),
		Port:              5432,
		User:              getEnvOrDefault("TEST_POSTGRES_USER", "keyper"),
		Password:          getEnvOrDefault("TEST_POSTGRES_PASSWORD", "keyper_dev_password"),
		Database:          getEnvOrDefault("TEST_POSTGRES_DB", "keyper_test"),
		SSLMode:           getEnvOrDefault("TEST_POSTGRES_SSL_MODE", "disable"),
		MaxConns:          5,
		MinConns:          1,
		MaxConnLifetime:   10 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: time.Minute,
	}

	ctx := context.Background()
	pool, err := db.NewPool(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create test db pool: %v", err)
	}

	// Clean up test data
	cleanupTestData(t, pool.Pool)

	return pool
}

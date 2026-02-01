package db

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testCfg *Config

func init() {
	host := getEnvOrDefault("TEST_POSTGRES_HOST", "localhost")
	port := getEnvOrDefault("TEST_POSTGRES_PORT", "5432")
	user := getEnvOrDefault("TEST_POSTGRES_USER", "keyper")
	password := getEnvOrDefault("TEST_POSTGRES_PASSWORD", "keyper_dev_password")
	database := getEnvOrDefault("TEST_POSTGRES_DB", "keyper_test")
	sslMode := getEnvOrDefault("TEST_POSTGRES_SSL_MODE", "disable")
	portNum, _ := strconv.Atoi(port)

	testCfg = &Config{
		Host:              host,
		Port:              portNum,
		User:              user,
		Password:          password,
		Database:          database,
		SSLMode:           sslMode,
		MaxConns:          5,
		MinConns:          1,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
		SkipMigrations:    true,
	}
}

// testConfig returns a copy of the standard test database configuration.
// Returns a copy to avoid tests mutating shared state.
func testConfig() *Config {
	// Return a copy to avoid tests mutating the global config
	cfg := *testCfg
	return &cfg
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func TestNewPool_Success(t *testing.T) {
	cfg := testConfig()

	ctx := context.Background()
	pool, err := NewPool(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, pool)
	defer pool.Close()

	// Verify connection works
	err = pool.Ping(ctx)
	require.NoError(t, err)
}

func TestNewPool_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.User = "keyper"
	cfg.Password = "keyper_dev_password"
	cfg.Database = "keyper_test"
	cfg.SkipMigrations = true

	ctx := context.Background()
	pool, err := NewPool(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, pool)
	defer pool.Close()

	// Verify default settings
	assert.Equal(t, int32(25), cfg.MaxConns)
	assert.Equal(t, int32(5), cfg.MinConns)
	assert.Equal(t, time.Hour, cfg.MaxConnLifetime)
}

func TestNewPool_NilConfig(t *testing.T) {
	ctx := context.Background()
	pool, err := NewPool(ctx, nil)
	// This should fail because default config doesn't have credentials
	assert.Error(t, err)
	assert.Nil(t, pool)
}

func TestNewPool_InvalidConfig(t *testing.T) {
	cfg := testConfig()
	cfg.Host = "invalid_host"
	cfg.Port = 9999
	cfg.User = "invalid_user"
	cfg.Password = "invalid_password"
	cfg.Database = "invalid_db"
	cfg.MaxConns = 1
	cfg.MinConns = 1

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := NewPool(ctx, cfg)
	assert.Error(t, err)
	assert.Nil(t, pool)
}

func TestPool_Health(t *testing.T) {
	cfg := testConfig()

	ctx := context.Background()
	pool, err := NewPool(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, pool)
	defer pool.Close()

	// Health check should succeed
	err = pool.Health(ctx)
	require.NoError(t, err)
}

func TestPool_Stats(t *testing.T) {
	cfg := testConfig()

	ctx := context.Background()
	pool, err := NewPool(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, pool)
	defer pool.Close()

	stats := pool.Stats()
	require.NotNil(t, stats)

	// We should have at least minimum connections
	assert.GreaterOrEqual(t, stats.TotalConns(), int32(1))
}

func TestPool_Close(t *testing.T) {
	cfg := testConfig()

	ctx := context.Background()
	pool, err := NewPool(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, pool)

	// Close the pool
	pool.Close()

	// Ping should fail after close
	err = pool.Ping(ctx)
	assert.Error(t, err)
}

package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPool_Success(t *testing.T) {
	cfg := &Config{
		Host:              "localhost",
		Port:              5432,
		User:              "keyper",
		Password:          "keyper_dev_password",
		Database:          "keyper_test",
		SSLMode:           "disable",
		MaxConns:          5,
		MinConns:          1,
		MaxConnLifetime:   time.Hour,
		MaxConnIdleTime:   30 * time.Minute,
		HealthCheckPeriod: time.Minute,
	}

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
	cfg := &Config{
		Host:              "invalid_host",
		Port:              9999,
		User:              "invalid_user",
		Password:          "invalid_password",
		Database:          "invalid_db",
		SSLMode:           "disable",
		MaxConns:          1,
		MinConns:          1,
		HealthCheckPeriod: time.Minute,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := NewPool(ctx, cfg)
	assert.Error(t, err)
	assert.Nil(t, pool)
}

func TestPool_Health(t *testing.T) {
	cfg := &Config{
		Host:     "localhost",
		Port:     5432,
		User:     "keyper",
		Password: "keyper_dev_password",
		Database: "keyper_test",
		SSLMode:  "disable",
		MaxConns: 5,
		MinConns: 1,
	}

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
	cfg := &Config{
		Host:     "localhost",
		Port:     5432,
		User:     "keyper",
		Password: "keyper_dev_password",
		Database: "keyper_test",
		SSLMode:  "disable",
		MaxConns: 5,
		MinConns: 1,
	}

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
	cfg := &Config{
		Host:     "localhost",
		Port:     5432,
		User:     "keyper",
		Password: "keyper_dev_password",
		Database: "keyper_test",
		SSLMode:  "disable",
		MaxConns: 5,
		MinConns: 1,
	}

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

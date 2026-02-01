package testhelpers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPostgresContainerSetup verifies the testcontainer infrastructure works correctly.
func TestPostgresContainerSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()

	// Create test container.
	tc := NewTestContainer(ctx, t)

	// Verify connection pool is healthy.
	err := tc.Pool().Ping(ctx)
	require.NoError(t, err, "database should be reachable")

	// Verify migrations were applied by checking tables exist.
	t.Run("VerifyTablesExist", func(t *testing.T) {
		tables := []string{"users", "secrets", "refresh_tokens"}

		for _, table := range tables {
			var exists bool
			query := `
				SELECT EXISTS (
					SELECT FROM information_schema.tables
					WHERE table_schema = 'public'
					AND table_name = $1
				)
			`
			err := tc.Pool().QueryRow(ctx, query, table).Scan(&exists)
			require.NoError(t, err, "failed to check if table %s exists", table)
			assert.True(t, exists, "table %s should exist after migrations", table)
		}
	})

	// Verify UUID extension is enabled.
	t.Run("VerifyUUIDExtension", func(t *testing.T) {
		var exists bool
		query := `
			SELECT EXISTS (
				SELECT FROM pg_extension
				WHERE extname = 'uuid-ossp'
			)
		`
		err := tc.Pool().QueryRow(ctx, query).Scan(&exists)
		require.NoError(t, err, "failed to check UUID extension")
		assert.True(t, exists, "uuid-ossp extension should be enabled")
	})

	// Verify we can insert and query data.
	t.Run("VerifyBasicOperations", func(t *testing.T) {
		// Insert a test user.
		insertQuery := `
			INSERT INTO users (email, password_hash, encryption_key_verifier, salt)
			VALUES ($1, $2, $3, $4)
			RETURNING id, email, created_at
		`
		var userID string
		var email string
		var createdAt interface{}

		err := tc.Pool().QueryRow(
			ctx,
			insertQuery,
			"test@example.com",
			[]byte("password_hash"),
			[]byte("key_verifier"),
			[]byte("salt"),
		).Scan(&userID, &email, &createdAt)
		require.NoError(t, err, "should be able to insert user")
		assert.NotEmpty(t, userID, "user ID should be generated")
		assert.Equal(t, "test@example.com", email)
		assert.NotNil(t, createdAt, "created_at should be set")

		// Query the user back.
		selectQuery := `SELECT email FROM users WHERE id = $1`
		var retrievedEmail string
		err = tc.Pool().QueryRow(ctx, selectQuery, userID).Scan(&retrievedEmail)
		require.NoError(t, err, "should be able to query user")
		assert.Equal(t, "test@example.com", retrievedEmail)

		// Clean up.
		tc.Exec(ctx, t, "DELETE FROM users WHERE id = $1", userID)
	})
}

// TestParallelContainers verifies that multiple tests can run with isolated containers.
func TestParallelContainers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Run subtests in parallel to verify container isolation.
	t.Run("Container1", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		tc := NewTestContainer(ctx, t)

		var count int
		err := tc.Pool().QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, "new container should have empty users table")
	})

	t.Run("Container2", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		tc := NewTestContainer(ctx, t)

		var count int
		err := tc.Pool().QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 0, count, "new container should have empty users table")
	})
}

// TestContainerCleanup verifies that containers are properly cleaned up.
func TestContainerCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()

	// Create and immediately let test end to trigger cleanup.
	tc := NewTestContainer(ctx, t)

	// Verify container is running.
	state, err := tc.container.State(ctx)
	require.NoError(t, err)
	assert.True(t, state.Running, "container should be running")

	// Note: actual cleanup verification happens via t.Cleanup() when test completes.
	// If cleanup fails, it will be logged by the cleanup function.
}

// TestTruncateHelper verifies the truncate helper method works correctly.
func TestTruncateHelper(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	tc := NewTestContainer(ctx, t)

	// Insert test data.
	tc.Exec(ctx, t,
		`INSERT INTO users (email, password_hash, encryption_key_verifier, salt)
		 VALUES ($1, $2, $3, $4)`,
		"user1@example.com", []byte("hash1"), []byte("verifier1"), []byte("salt1"),
	)
	tc.Exec(ctx, t,
		`INSERT INTO users (email, password_hash, encryption_key_verifier, salt)
		 VALUES ($1, $2, $3, $4)`,
		"user2@example.com", []byte("hash2"), []byte("verifier2"), []byte("salt2"),
	)

	// Verify data exists.
	var count int
	err := tc.Pool().QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "should have 2 users")

	// Truncate table.
	tc.Truncate(ctx, t, "users")

	// Verify table is empty.
	err = tc.Pool().QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "users table should be empty after truncate")
}

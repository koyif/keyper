package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koyif/keyper/internal/server/repository"
	"github.com/koyif/keyper/internal/server/testhelpers"
)

// TestUserRepositoryIntegration demonstrates how to use the testcontainer infrastructure
// to test repository functions with a real PostgreSQL database.
func TestUserRepositoryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()

	// Create test container with migrations applied.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Create repository instance with the test database pool.
	repo := NewUserRepository(tc.Pool())

	t.Run("CreateAndGetUser", func(t *testing.T) {
		// Clean up after this subtest.
		defer tc.Truncate(ctx, t, "users")

		// Test data.
		email := "integration@example.com"
		passwordHash := []byte("hashed_password_123")
		keyVerifier := []byte("encryption_key_verifier")
		salt := []byte("random_salt_bytes")

		// Create user.
		user, err := repo.CreateUser(ctx, repository.CreateUserParams{
			Email:                 email,
			PasswordHash:          passwordHash,
			EncryptionKeyVerifier: keyVerifier,
			Salt:                  salt,
		})
		require.NoError(t, err, "should create user successfully")
		assert.NotEmpty(t, user.ID, "user ID should be generated")
		assert.Equal(t, email, user.Email)
		assert.Equal(t, passwordHash, user.PasswordHash)

		// Get user by ID.
		retrievedUser, err := repo.GetUserByID(ctx, user.ID)
		require.NoError(t, err, "should retrieve user by ID")
		assert.Equal(t, email, retrievedUser.Email)
		assert.Equal(t, passwordHash, retrievedUser.PasswordHash)
		assert.Equal(t, keyVerifier, retrievedUser.EncryptionKeyVerifier)
		assert.Equal(t, salt, retrievedUser.Salt)
		assert.NotZero(t, retrievedUser.CreatedAt)
		assert.NotZero(t, retrievedUser.UpdatedAt)

		// Get user by email.
		userByEmail, err := repo.GetUserByEmail(ctx, email)
		require.NoError(t, err, "should retrieve user by email")
		assert.Equal(t, user.ID, userByEmail.ID)
		assert.Equal(t, email, userByEmail.Email)
	})

	t.Run("DuplicateEmail", func(t *testing.T) {
		// Clean up after this subtest.
		defer tc.Truncate(ctx, t, "users")

		email := "duplicate@example.com"

		// Create first user.
		_, err := repo.CreateUser(ctx, repository.CreateUserParams{
			Email:                 email,
			PasswordHash:          []byte("hash1"),
			EncryptionKeyVerifier: []byte("verifier1"),
			Salt:                  []byte("salt1"),
		})
		require.NoError(t, err, "first user creation should succeed")

		// Attempt to create user with same email.
		_, err = repo.CreateUser(ctx, repository.CreateUserParams{
			Email:                 email,
			PasswordHash:          []byte("hash2"),
			EncryptionKeyVerifier: []byte("verifier2"),
			Salt:                  []byte("salt2"),
		})
		assert.Error(t, err, "should fail to create user with duplicate email")
		assert.ErrorIs(t, err, repository.ErrDuplicate, "error should be ErrDuplicate")
	})

	t.Run("NonExistentUser", func(t *testing.T) {
		// Try to get a user that doesn't exist.
		user, err := repo.GetUserByID(ctx, uuid.MustParse("00000000-0000-0000-0000-000000000000"))
		assert.Error(t, err, "should return error for non-existent user")
		assert.ErrorIs(t, err, repository.ErrNotFound, "error should be ErrNotFound")
		assert.Nil(t, user, "user should be nil when not found")

		// Try to get by non-existent email.
		user, err = repo.GetUserByEmail(ctx, "nonexistent@example.com")
		assert.Error(t, err, "should return error for non-existent email")
		assert.ErrorIs(t, err, repository.ErrNotFound, "error should be ErrNotFound")
		assert.Nil(t, user, "user should be nil when not found")
	})
}

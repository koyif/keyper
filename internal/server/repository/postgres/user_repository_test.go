package postgres

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koyif/keyper/internal/server/repository"
)

func TestUserRepository_CreateUser(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	repo := NewUserRepository(pool)
	ctx := context.Background()

	email := "test@example.com"
	passwordHash := []byte("hashed_password")
	encryptionKeyVerifier := []byte("verifier")
	salt := []byte("salt")

	user, err := repo.CreateUser(ctx, repository.CreateUserParams{
		Email:                 email,
		PasswordHash:          passwordHash,
		EncryptionKeyVerifier: encryptionKeyVerifier,
		Salt:                  salt,
	})
	require.NoError(t, err)
	require.NotNil(t, user)

	assert.NotEqual(t, uuid.Nil, user.ID)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, passwordHash, user.PasswordHash)
	assert.Equal(t, encryptionKeyVerifier, user.EncryptionKeyVerifier)
	assert.Equal(t, salt, user.Salt)
	assert.False(t, user.CreatedAt.IsZero())
	assert.False(t, user.UpdatedAt.IsZero())
}

func TestUserRepository_CreateUser_DuplicateEmail(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	repo := NewUserRepository(pool)
	ctx := context.Background()

	email := "duplicate@example.com"
	passwordHash := []byte("hashed_password")
	encryptionKeyVerifier := []byte("verifier")
	salt := []byte("salt")

	// Create first user
	_, err := repo.CreateUser(ctx, repository.CreateUserParams{
		Email:                 email,
		PasswordHash:          passwordHash,
		EncryptionKeyVerifier: encryptionKeyVerifier,
		Salt:                  salt,
	})
	require.NoError(t, err)

	// Attempt to create duplicate
	_, err = repo.CreateUser(ctx, repository.CreateUserParams{
		Email:                 email,
		PasswordHash:          passwordHash,
		EncryptionKeyVerifier: encryptionKeyVerifier,
		Salt:                  salt,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrDuplicate)
}

func TestUserRepository_GetUserByEmail(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	repo := NewUserRepository(pool)
	ctx := context.Background()

	// Create a user first
	email := "get@example.com"
	passwordHash := []byte("hashed_password")
	encryptionKeyVerifier := []byte("verifier")
	salt := []byte("salt")

	created, err := repo.CreateUser(ctx, repository.CreateUserParams{
		Email:                 email,
		PasswordHash:          passwordHash,
		EncryptionKeyVerifier: encryptionKeyVerifier,
		Salt:                  salt,
	})
	require.NoError(t, err)

	// Retrieve by email
	retrieved, err := repo.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, created.ID, retrieved.ID)
	assert.Equal(t, created.Email, retrieved.Email)
	assert.Equal(t, created.PasswordHash, retrieved.PasswordHash)
}

func TestUserRepository_GetUserByEmail_NotFound(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	repo := NewUserRepository(pool)
	ctx := context.Background()

	_, err := repo.GetUserByEmail(ctx, "nonexistent@example.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestUserRepository_GetUserByID(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	repo := NewUserRepository(pool)
	ctx := context.Background()

	// Create a user first
	email := "getbyid@example.com"
	passwordHash := []byte("hashed_password")
	encryptionKeyVerifier := []byte("verifier")
	salt := []byte("salt")

	created, err := repo.CreateUser(ctx, repository.CreateUserParams{
		Email:                 email,
		PasswordHash:          passwordHash,
		EncryptionKeyVerifier: encryptionKeyVerifier,
		Salt:                  salt,
	})
	require.NoError(t, err)

	// Retrieve by ID
	retrieved, err := repo.GetUserByID(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, created.ID, retrieved.ID)
	assert.Equal(t, created.Email, retrieved.Email)
	assert.Equal(t, created.PasswordHash, retrieved.PasswordHash)
}

func TestUserRepository_GetUserByID_NotFound(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	repo := NewUserRepository(pool)
	ctx := context.Background()

	_, err := repo.GetUserByID(ctx, uuid.New())
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

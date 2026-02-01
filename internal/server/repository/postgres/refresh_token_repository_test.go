package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koyif/keyper/internal/server/repository"
)

func TestRefreshTokenRepository_Create(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	tokenRepo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	tokenHash := []byte("token_hash")
	deviceID := "device_123"
	expiresAt := time.Now().Add(24 * time.Hour)

	token, err := tokenRepo.Create(ctx, user.ID, tokenHash, &deviceID, expiresAt)
	require.NoError(t, err)
	require.NotNil(t, token)

	assert.NotEqual(t, uuid.Nil, token.ID)
	assert.Equal(t, user.ID, token.UserID)
	assert.Equal(t, tokenHash, token.TokenHash)
	assert.Equal(t, &deviceID, token.DeviceID)
	assert.WithinDuration(t, expiresAt, token.ExpiresAt, time.Second)
	assert.False(t, token.CreatedAt.IsZero())
}

func TestRefreshTokenRepository_Create_NullDeviceID(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	tokenRepo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	tokenHash := []byte("token_hash")
	expiresAt := time.Now().Add(24 * time.Hour)

	token, err := tokenRepo.Create(ctx, user.ID, tokenHash, nil, expiresAt)
	require.NoError(t, err)
	require.NotNil(t, token)

	assert.Nil(t, token.DeviceID)
}

func TestRefreshTokenRepository_GetByTokenHash(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	tokenRepo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	tokenHash := []byte("unique_token_hash")
	deviceID := "device_123"
	expiresAt := time.Now().Add(24 * time.Hour)

	created, err := tokenRepo.Create(ctx, user.ID, tokenHash, &deviceID, expiresAt)
	require.NoError(t, err)

	retrieved, err := tokenRepo.GetByTokenHash(ctx, tokenHash)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, created.ID, retrieved.ID)
	assert.Equal(t, created.UserID, retrieved.UserID)
	assert.Equal(t, created.TokenHash, retrieved.TokenHash)
}

func TestRefreshTokenRepository_GetByTokenHash_NotFound(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	tokenRepo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	_, err := tokenRepo.GetByTokenHash(ctx, []byte("nonexistent_token"))
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestRefreshTokenRepository_GetByTokenHash_Expired(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	tokenRepo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	tokenHash := []byte("expired_token_hash")
	expiresAt := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago

	_, err := tokenRepo.Create(ctx, user.ID, tokenHash, nil, expiresAt)
	require.NoError(t, err)

	// Attempt to get expired token
	_, err = tokenRepo.GetByTokenHash(ctx, tokenHash)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestRefreshTokenRepository_DeleteByID(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	tokenRepo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	tokenHash := []byte("to_delete_token")
	expiresAt := time.Now().Add(24 * time.Hour)

	token, err := tokenRepo.Create(ctx, user.ID, tokenHash, nil, expiresAt)
	require.NoError(t, err)

	// Delete the token
	err = tokenRepo.DeleteByID(ctx, token.ID)
	require.NoError(t, err)

	// Verify it's deleted
	_, err = tokenRepo.GetByTokenHash(ctx, tokenHash)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestRefreshTokenRepository_DeleteByID_NotFound(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	tokenRepo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	err := tokenRepo.DeleteByID(ctx, uuid.New())
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestRefreshTokenRepository_DeleteExpired(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	tokenRepo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)

	// Create expired tokens
	for i := 0; i < 3; i++ {
		tokenHash := []byte("expired_" + uuid.New().String())
		expiresAt := time.Now().Add(-1 * time.Hour)
		_, err := tokenRepo.Create(ctx, user.ID, tokenHash, nil, expiresAt)
		require.NoError(t, err)
	}

	// Create valid token
	validTokenHash := []byte("valid_token")
	expiresAt := time.Now().Add(24 * time.Hour)
	validToken, err := tokenRepo.Create(ctx, user.ID, validTokenHash, nil, expiresAt)
	require.NoError(t, err)

	// Delete expired tokens
	count, err := tokenRepo.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)

	// Verify valid token still exists
	retrieved, err := tokenRepo.GetByTokenHash(ctx, validTokenHash)
	require.NoError(t, err)
	assert.Equal(t, validToken.ID, retrieved.ID)
}

func TestRefreshTokenRepository_DeleteExpired_None(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	tokenRepo := NewRefreshTokenRepository(pool)
	ctx := context.Background()

	// No expired tokens
	count, err := tokenRepo.DeleteExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

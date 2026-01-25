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

func TestSecretRepository_Create(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	// Create a user first
	user := createTestUser(t, ctx, userRepo)

	secret := &repository.Secret{
		UserID:        user.ID,
		Name:          "Test Secret",
		Type:          1,
		EncryptedData: []byte("encrypted_data"),
		Nonce:         []byte("nonce"),
		Metadata:      []byte(`{"category":"work"}`),
	}

	created, err := secretRepo.Create(ctx, secret)
	require.NoError(t, err)
	require.NotNil(t, created)

	assert.NotEqual(t, uuid.Nil, created.ID)
	assert.Equal(t, user.ID, created.UserID)
	assert.Equal(t, "Test Secret", created.Name)
	assert.Equal(t, int32(1), created.Type)
	assert.Equal(t, int64(1), created.Version)
	assert.False(t, created.IsDeleted)
	assert.False(t, created.CreatedAt.IsZero())
	assert.False(t, created.UpdatedAt.IsZero())
}

func TestSecretRepository_Get(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	created := createTestSecret(t, ctx, secretRepo, user.ID)

	retrieved, err := secretRepo.Get(ctx, created.ID)
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, created.ID, retrieved.ID)
	assert.Equal(t, created.Name, retrieved.Name)
	assert.Equal(t, created.Version, retrieved.Version)
}

func TestSecretRepository_Get_NotFound(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	_, err := secretRepo.Get(ctx, uuid.New())
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestSecretRepository_Get_SoftDeleted(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	created := createTestSecret(t, ctx, secretRepo, user.ID)

	// Delete the secret
	err := secretRepo.Delete(ctx, created.ID, created.Version)
	require.NoError(t, err)

	// Attempt to get deleted secret
	_, err = secretRepo.Get(ctx, created.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestSecretRepository_Update(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	created := createTestSecret(t, ctx, secretRepo, user.ID)

	// Update the secret
	created.Name = "Updated Secret"
	created.EncryptedData = []byte("updated_encrypted_data")

	updated, err := secretRepo.Update(ctx, created)
	require.NoError(t, err)
	require.NotNil(t, updated)

	assert.Equal(t, created.ID, updated.ID)
	assert.Equal(t, "Updated Secret", updated.Name)
	assert.Equal(t, int64(2), updated.Version) // Version incremented
	assert.True(t, updated.UpdatedAt.After(created.UpdatedAt))
}

func TestSecretRepository_Update_VersionConflict(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	created := createTestSecret(t, ctx, secretRepo, user.ID)

	// Simulate concurrent update by using wrong version
	created.Version = 999
	created.Name = "Updated Secret"

	_, err := secretRepo.Update(ctx, created)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrVersionConflict)
}

func TestSecretRepository_Update_NotFound(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	secret := &repository.Secret{
		ID:            uuid.New(),
		UserID:        uuid.New(),
		Name:          "Nonexistent",
		Type:          1,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
		Version:       1,
	}

	_, err := secretRepo.Update(ctx, secret)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestSecretRepository_Delete(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	created := createTestSecret(t, ctx, secretRepo, user.ID)

	err := secretRepo.Delete(ctx, created.ID, created.Version)
	require.NoError(t, err)

	// Verify it's soft deleted
	_, err = secretRepo.Get(ctx, created.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestSecretRepository_Delete_VersionConflict(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)
	created := createTestSecret(t, ctx, secretRepo, user.ID)

	// Use wrong version
	err := secretRepo.Delete(ctx, created.ID, 999)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrVersionConflict)
}

func TestSecretRepository_ListByUser(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)

	// Create multiple secrets
	for i := 0; i < 3; i++ {
		createTestSecret(t, ctx, secretRepo, user.ID)
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	secrets, err := secretRepo.ListByUser(ctx, user.ID, 10, 0)
	require.NoError(t, err)
	assert.Len(t, secrets, 3)

	// Verify ordering (DESC by updated_at)
	for i := 0; i < len(secrets)-1; i++ {
		assert.True(t, secrets[i].UpdatedAt.After(secrets[i+1].UpdatedAt) || secrets[i].UpdatedAt.Equal(secrets[i+1].UpdatedAt))
	}
}

func TestSecretRepository_ListByUser_Pagination(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)

	// Create 5 secrets
	for i := 0; i < 5; i++ {
		createTestSecret(t, ctx, secretRepo, user.ID)
		time.Sleep(10 * time.Millisecond)
	}

	// Get first page
	page1, err := secretRepo.ListByUser(ctx, user.ID, 2, 0)
	require.NoError(t, err)
	assert.Len(t, page1, 2)

	// Get second page
	page2, err := secretRepo.ListByUser(ctx, user.ID, 2, 2)
	require.NoError(t, err)
	assert.Len(t, page2, 2)

	// Ensure different results
	assert.NotEqual(t, page1[0].ID, page2[0].ID)
}

func TestSecretRepository_ListByUser_ExcludesDeleted(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)

	// Create and delete a secret
	secret := createTestSecret(t, ctx, secretRepo, user.ID)
	err := secretRepo.Delete(ctx, secret.ID, secret.Version)
	require.NoError(t, err)

	// Create another active secret
	createTestSecret(t, ctx, secretRepo, user.ID)

	secrets, err := secretRepo.ListByUser(ctx, user.ID, 10, 0)
	require.NoError(t, err)
	assert.Len(t, secrets, 1) // Only the non-deleted secret
}

func TestSecretRepository_ListModifiedSince(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)

	// Create initial secret
	secret1 := createTestSecret(t, ctx, secretRepo, user.ID)
	time.Sleep(100 * time.Millisecond)

	// Record time
	since := time.Now()
	time.Sleep(100 * time.Millisecond)

	// Create new secret after timestamp
	createTestSecret(t, ctx, secretRepo, user.ID)

	// Update first secret
	secret1.Name = "Updated"
	_, err := secretRepo.Update(ctx, secret1)
	require.NoError(t, err)

	// List modified since
	secrets, err := secretRepo.ListModifiedSince(ctx, user.ID, since, 10)
	require.NoError(t, err)
	assert.Len(t, secrets, 2) // Both the new secret and updated secret

	// Verify ordering (ASC by updated_at)
	for i := 0; i < len(secrets)-1; i++ {
		assert.True(t, secrets[i].UpdatedAt.Before(secrets[i+1].UpdatedAt) || secrets[i].UpdatedAt.Equal(secrets[i+1].UpdatedAt))
	}
}

func TestSecretRepository_ListModifiedSince_IncludesDeleted(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	ctx := context.Background()

	user := createTestUser(t, ctx, userRepo)

	since := time.Now()
	time.Sleep(100 * time.Millisecond)

	// Create and immediately delete a secret
	secret := createTestSecret(t, ctx, secretRepo, user.ID)
	time.Sleep(10 * time.Millisecond)
	err := secretRepo.Delete(ctx, secret.ID, secret.Version)
	require.NoError(t, err)

	// List modified since should include deleted
	secrets, err := secretRepo.ListModifiedSince(ctx, user.ID, since, 10)
	require.NoError(t, err)
	assert.Len(t, secrets, 1)
	assert.True(t, secrets[0].IsDeleted)
}

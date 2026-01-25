package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/koyif/keyper/pkg/api/proto"
)

// Compile-time check to ensure SQLiteRepository implements Repository interface
var _ Repository = (*SQLiteRepository)(nil)

// TestErrSecretNotFound_Get verifies that Get returns ErrSecretNotFound using errors.Is.
func TestErrSecretNotFound_Get(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Try to get a non-existent secret
	_, err = repo.Get(ctx, "non-existent-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Expected ErrSecretNotFound, got: %v", err)
}

// TestErrSecretNotFound_GetByName verifies that GetByName returns ErrSecretNotFound.
func TestErrSecretNotFound_GetByName(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Try to get a non-existent secret by name
	_, err = repo.GetByName(ctx, "non-existent-name")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Expected ErrSecretNotFound, got: %v", err)
}

// TestErrSecretNotFound_Update verifies that Update returns ErrSecretNotFound.
func TestErrSecretNotFound_Update(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Try to update a non-existent secret
	secret := &LocalSecret{
		ID:   "non-existent-id",
		Name: "Test",
		Type: pb.SecretType_SECRET_TYPE_CREDENTIAL,
	}

	err = repo.Update(ctx, secret)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Expected ErrSecretNotFound, got: %v", err)
}

// TestErrSecretNotFound_Delete verifies that Delete returns ErrSecretNotFound.
func TestErrSecretNotFound_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Try to delete a non-existent secret
	err = repo.Delete(ctx, "non-existent-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Expected ErrSecretNotFound, got: %v", err)
}

// TestErrSecretNotFound_HardDelete verifies that HardDelete returns ErrSecretNotFound.
func TestErrSecretNotFound_HardDelete(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Try to hard delete a non-existent secret
	err = repo.HardDelete(ctx, "non-existent-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Expected ErrSecretNotFound, got: %v", err)
}

// TestErrSecretNotFound_UpdateSyncStatus verifies that UpdateSyncStatus returns ErrSecretNotFound.
func TestErrSecretNotFound_UpdateSyncStatus(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Try to update sync status of a non-existent secret
	err = repo.UpdateSyncStatus(ctx, "non-existent-id", SyncStatusSynced, 1)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Expected ErrSecretNotFound, got: %v", err)
}

// TestErrSecretNotFound_GetInTx verifies that GetInTx returns ErrSecretNotFound.
func TestErrSecretNotFound_GetInTx(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Begin transaction
	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	// Try to get a non-existent secret in transaction
	_, err = repo.GetInTx(ctx, tx, "non-existent-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Expected ErrSecretNotFound, got: %v", err)
}

// TestErrSecretNotFound_UpdateInTx verifies that UpdateInTx returns ErrSecretNotFound.
func TestErrSecretNotFound_UpdateInTx(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Begin transaction
	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	// Try to update a non-existent secret in transaction
	secret := &LocalSecret{
		ID:   "non-existent-id",
		Name: "Test",
		Type: pb.SecretType_SECRET_TYPE_CREDENTIAL,
	}

	err = repo.UpdateInTx(ctx, tx, secret)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Expected ErrSecretNotFound, got: %v", err)
}

// TestErrSecretNotFound_HardDeleteInTx verifies that HardDeleteInTx returns ErrSecretNotFound.
// This is the CRITICAL issue #2 - HardDeleteInTx now returns ErrSecretNotFound consistently.
func TestErrSecretNotFound_HardDeleteInTx(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Begin transaction
	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	// Try to hard delete a non-existent secret in transaction
	err = repo.HardDeleteInTx(ctx, tx, "non-existent-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Expected ErrSecretNotFound, got: %v", err)
}

// TestHardDeleteInTx_ConsistentWithHardDelete verifies the behavior is now consistent.
func TestHardDeleteInTx_ConsistentWithHardDelete(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Test HardDelete behavior
	err1 := repo.HardDelete(ctx, "non-existent-id")
	assert.Error(t, err1)
	assert.True(t, errors.Is(err1, ErrSecretNotFound))

	// Test HardDeleteInTx behavior
	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	err2 := repo.HardDeleteInTx(ctx, tx, "non-existent-id")
	assert.Error(t, err2)
	assert.True(t, errors.Is(err2, ErrSecretNotFound))

	// Both should return the same sentinel error
	assert.True(t, errors.Is(err1, ErrSecretNotFound), "HardDelete should return ErrSecretNotFound")
	assert.True(t, errors.Is(err2, ErrSecretNotFound), "HardDeleteInTx should return ErrSecretNotFound")
}

// TestNoStringBasedErrorChecking verifies that string-based error checking is not possible.
func TestNoStringBasedErrorChecking(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	_, err = repo.Get(ctx, "non-existent-id")
	assert.Error(t, err)

	// String-based checking is fragile and should not be used
	// This test verifies that errors.Is is the correct approach
	assert.False(t, err.Error() == "secret not found", "Should not use exact string matching")

	// The correct way is to use errors.Is
	assert.True(t, errors.Is(err, ErrSecretNotFound), "Should use errors.Is for sentinel errors")
}

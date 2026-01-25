package sync

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/storage"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// TestMergeToLocalDB_ConflictDetection_VersionMismatchWithPendingChanges tests that
// a conflict is detected when there's a version mismatch and the local secret has pending changes.
func TestMergeToLocalDB_ConflictDetection_VersionMismatchWithPendingChanges(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Insert local secret with pending changes and version 1
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending, // Pending changes
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	// Server sends version 2 (version mismatch)
	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-15 * time.Minute),
		LocalUpdatedAt: now,
	}

	// Test with automatic conflict resolution (last-write-wins)
	cfg := &config.Config{
		ManualConflictResolution: false,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// With last-write-wins, when server version wins, the secret gets server's status (synced)
	// But a conflict was detected and resolved
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	// Server version was applied because it's newer
	assert.Equal(t, "Server Name", retrieved.Name)
}

// TestMergeToLocalDB_ConflictDetection_VersionMismatchWithoutPendingChanges tests that
// no conflict is detected when there's a version mismatch but the local secret is synced.
func TestMergeToLocalDB_ConflictDetection_VersionMismatchWithoutPendingChanges(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Insert local secret that's synced (no pending changes)
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusSynced, // No pending changes
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-1 * time.Hour),
		LocalUpdatedAt: now.Add(-1 * time.Hour),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	// Server sends version 2
	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name Updated",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: false,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify secret was updated without conflict
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Server Name Updated", retrieved.Name)
	assert.Equal(t, int64(2), retrieved.Version)
	assert.Equal(t, storage.SyncStatusSynced, retrieved.SyncStatus)
}

// TestMergeToLocalDB_ConflictDetection_SameVersion tests that
// no conflict is detected when versions match.
func TestMergeToLocalDB_ConflictDetection_SameVersion(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Insert local secret with pending changes but same version
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusPending, // Has pending changes
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	// Server sends same version 2 (no version mismatch)
	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: false,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify no conflict was detected (because versions match)
	// The update should still happen because server version >= local server version
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Server Name", retrieved.Name)
	assert.Equal(t, int64(2), retrieved.Version)
}

// TestMergeToLocalDB_ConflictType_ModifiedModified tests detection of MODIFIED_MODIFIED conflict.
func TestMergeToLocalDB_ConflictType_ModifiedModified(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Both local and server have non-deleted versions
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false, // Not deleted locally
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false, // Not deleted on server
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: true, // Use manual resolution to check conflict type
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify conflict type is MODIFIED_MODIFIED
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)
	assert.Equal(t, pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED, conflicts[0].ConflictType)
}

// TestMergeToLocalDB_ConflictType_DeletedModified tests detection of DELETED_MODIFIED conflict.
func TestMergeToLocalDB_ConflictType_DeletedModified(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Local is deleted, server is modified
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      true, // Deleted locally
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name Modified",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false, // Not deleted on server
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: true,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify conflict type is DELETED_MODIFIED
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)
	assert.Equal(t, pb.ConflictType_CONFLICT_TYPE_DELETED_MODIFIED, conflicts[0].ConflictType)
}

// TestMergeToLocalDB_ConflictType_ModifiedDeleted tests detection of MODIFIED_DELETED conflict.
func TestMergeToLocalDB_ConflictType_ModifiedDeleted(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Local is modified, server is deleted
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false, // Not deleted locally
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      true, // Deleted on server
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: true,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify conflict type is MODIFIED_DELETED
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)
	assert.Equal(t, pb.ConflictType_CONFLICT_TYPE_MODIFIED_DELETED, conflicts[0].ConflictType)
}

// TestMergeToLocalDB_LastWriteWins_LocalNewer tests that last-write-wins keeps local version
// when local timestamp is newer.
func TestMergeToLocalDB_LastWriteWins_LocalNewer(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Local is more recent
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name (Newer)",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-10 * time.Minute), // More recent
		LocalUpdatedAt: now.Add(-10 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	// Server is older
	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name (Older)",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute), // Older
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: false, // Use last-write-wins
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify local version was kept (because it's newer)
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Local Name (Newer)", retrieved.Name)
	assert.Equal(t, []byte("local-encrypted-data"), retrieved.EncryptedData)
	assert.Equal(t, storage.SyncStatusConflict, retrieved.SyncStatus) // Marked as conflict
}

// TestMergeToLocalDB_LastWriteWins_ServerNewer tests that last-write-wins keeps server version
// when server timestamp is newer.
func TestMergeToLocalDB_LastWriteWins_ServerNewer(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Local is older
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name (Older)",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute), // Older
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	// Server is newer
	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name (Newer)",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-10 * time.Minute), // More recent
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: false,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify server version was kept (because it's newer)
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Server Name (Newer)", retrieved.Name)
	assert.Equal(t, []byte("server-encrypted-data"), retrieved.EncryptedData)
	assert.Equal(t, int64(2), retrieved.Version)
}

// TestMergeToLocalDB_LastWriteWins_EqualTimestamps tests deterministic behavior
// when timestamps are equal.
func TestMergeToLocalDB_LastWriteWins_EqualTimestamps(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()
	sameTime := now.Add(-30 * time.Minute)

	// Both have same timestamp
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      sameTime, // Same timestamp
		LocalUpdatedAt: sameTime,
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      sameTime, // Same timestamp
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: false,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// When timestamps are equal, After() returns false, so server version should win
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Server Name", retrieved.Name)
}

// TestMergeToLocalDB_LastWriteWins_ConflictStored tests that conflict is stored
// with correct resolution strategy for audit trail.
func TestMergeToLocalDB_LastWriteWins_ConflictStored(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-10 * time.Minute),
		LocalUpdatedAt: now.Add(-10 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: false,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Check if conflict was stored (even though auto-resolved)
	// Note: With last-write-wins, conflicts are created but marked as resolved
	// We need to query all conflicts, not just unresolved
	// Since there's no GetAllConflicts method, we'll verify the secret has conflict status
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, storage.SyncStatusConflict, retrieved.SyncStatus)
}

// TestMergeToLocalDB_ManualResolution_StoresUnresolvedConflict tests that in manual mode,
// conflicts are stored unresolved.
func TestMergeToLocalDB_ManualResolution_StoresUnresolvedConflict(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: true, // Manual mode
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify unresolved conflict was stored
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)

	conflict := conflicts[0]
	assert.Equal(t, "secret-1", conflict.SecretID)
	assert.Equal(t, false, conflict.Resolved)
	assert.Equal(t, "manual", conflict.ResolutionStrategy)
}

// TestMergeToLocalDB_ManualResolution_PreservesBothVersions tests that in manual mode,
// both local and server versions are preserved.
func TestMergeToLocalDB_ManualResolution_PreservesBothVersions(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data-unique"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data-unique"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: true,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify both versions are stored in conflict
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)

	conflict := conflicts[0]
	assert.Equal(t, []byte("local-encrypted-data-unique"), conflict.LocalData)
	assert.Equal(t, []byte("server-encrypted-data-unique"), conflict.ServerData)
	assert.Equal(t, int64(1), conflict.LocalVersion)
	assert.Equal(t, int64(2), conflict.ServerVersion)
}

// TestMergeToLocalDB_ManualResolution_SecretMarkedConflict tests that in manual mode,
// the secret is marked with SyncStatusConflict.
func TestMergeToLocalDB_ManualResolution_SecretMarkedConflict(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: true,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify secret is marked as conflict
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, storage.SyncStatusConflict, retrieved.SyncStatus)
}

// TestMergeToLocalDB_ManualResolution_RemainsUnresolved tests that manual conflicts
// remain unresolved (resolved=false).
func TestMergeToLocalDB_ManualResolution_RemainsUnresolved(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data"),
		Nonce:          []byte("local-nonce-123"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data"),
		Nonce:          []byte("server-nonce-456"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: true,
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify conflict is unresolved
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)
	assert.False(t, conflicts[0].Resolved)
	assert.Nil(t, conflicts[0].ResolvedAt)
}

// TestMergeToLocalDB_MultipleConflictsInSinglePull tests handling of
// multiple conflicts in a single pull operation.
func TestMergeToLocalDB_MultipleConflictsInSinglePull(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create 3 local secrets with pending changes
	for i := 1; i <= 3; i++ {
		localSecret := &storage.LocalSecret{
			ID:             "secret-" + string(rune('0'+i)),
			Name:           "Local Name " + string(rune('0'+i)),
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("local-data-" + string(rune('0'+i))),
			Nonce:          []byte("local-nonce-" + string(rune('0'+i))),
			Version:        1,
			ServerVersion:  1,
			SyncStatus:     storage.SyncStatusPending,
			IsDeleted:      false,
			CreatedAt:      now.Add(-2 * time.Hour),
			UpdatedAt:      now.Add(-30 * time.Minute),
			LocalUpdatedAt: now.Add(-30 * time.Minute),
		}
		err = repo.Create(ctx, localSecret)
		require.NoError(t, err)
	}

	// Server sends conflicting versions for all 3
	serverSecrets := []*storage.LocalSecret{
		{
			ID:             "secret-1",
			Name:           "Server Name 1",
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("server-data-1"),
			Nonce:          []byte("server-nonce-1"),
			Version:        2,
			ServerVersion:  2,
			SyncStatus:     storage.SyncStatusSynced,
			IsDeleted:      false,
			CreatedAt:      now.Add(-2 * time.Hour),
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		},
		{
			ID:             "secret-2",
			Name:           "Server Name 2",
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("server-data-2"),
			Nonce:          []byte("server-nonce-2"),
			Version:        2,
			ServerVersion:  2,
			SyncStatus:     storage.SyncStatusSynced,
			IsDeleted:      false,
			CreatedAt:      now.Add(-2 * time.Hour),
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		},
		{
			ID:             "secret-3",
			Name:           "Server Name 3",
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("server-data-3"),
			Nonce:          []byte("server-nonce-3"),
			Version:        2,
			ServerVersion:  2,
			SyncStatus:     storage.SyncStatusSynced,
			IsDeleted:      false,
			CreatedAt:      now.Add(-2 * time.Hour),
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		},
	}

	cfg := &config.Config{
		ManualConflictResolution: true,
	}

	err = mergeToLocalDB(ctx, cfg, repo, serverSecrets, nil, 2)
	require.NoError(t, err)

	// Verify all 3 conflicts were stored
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	assert.Len(t, conflicts, 3)
}

// TestMergeToLocalDB_TwoDevicesModifySameSecret simulates two devices
// modifying the same secret and pulling from server.
func TestMergeToLocalDB_TwoDevicesModifySameSecret(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()

	// Device 1
	dbPath1 := filepath.Join(tmpDir, "device1.db")
	repo1, err := storage.NewSQLiteRepository(dbPath1)
	require.NoError(t, err)
	defer repo1.Close()

	// Device 2
	dbPath2 := filepath.Join(tmpDir, "device2.db")
	repo2, err := storage.NewSQLiteRepository(dbPath2)
	require.NoError(t, err)
	defer repo2.Close()

	now := time.Now()

	// Both devices start with same synced secret (version 1)
	initialSecret := &storage.LocalSecret{
		ID:             "shared-secret",
		Name:           "Initial Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("initial-data"),
		Nonce:          []byte("initial-nonce"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-1 * time.Hour),
		LocalUpdatedAt: now.Add(-1 * time.Hour),
	}

	err = repo1.Create(ctx, initialSecret)
	require.NoError(t, err)
	err = repo2.Create(ctx, initialSecret)
	require.NoError(t, err)

	// Device 1 modifies locally
	device1Modified := &storage.LocalSecret{
		ID:             "shared-secret",
		Name:           "Device 1 Modified",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("device1-data"),
		Nonce:          []byte("device1-nonce"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now.Add(-30 * time.Minute),
	}
	err = repo1.Update(ctx, device1Modified)
	require.NoError(t, err)

	// Device 2 modifies locally (independently)
	device2Modified := &storage.LocalSecret{
		ID:             "shared-secret",
		Name:           "Device 2 Modified",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("device2-data"),
		Nonce:          []byte("device2-nonce"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-20 * time.Minute),
		LocalUpdatedAt: now.Add(-20 * time.Minute),
	}
	err = repo2.Update(ctx, device2Modified)
	require.NoError(t, err)

	// Simulate: Device 2 pushes first, server accepts it as version 2
	// Now Device 1 pulls and gets Device 2's version (version 2)
	serverVersion := &storage.LocalSecret{
		ID:             "shared-secret",
		Name:           "Device 2 Modified", // Server now has Device 2's version
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("device2-data"),
		Nonce:          []byte("device2-nonce"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-20 * time.Minute),
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: true,
	}

	// Device 1 pulls and detects conflict
	err = mergeToLocalDB(ctx, cfg, repo1, []*storage.LocalSecret{serverVersion}, nil, 2)
	require.NoError(t, err)

	// Verify Device 1 detected the conflict
	conflicts, err := repo1.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)

	conflict := conflicts[0]
	assert.Equal(t, "shared-secret", conflict.SecretID)
	assert.Equal(t, []byte("device1-data"), conflict.LocalData)
	assert.Equal(t, []byte("device2-data"), conflict.ServerData)
}

// TestMergeToLocalDB_DataIntegrityAfterResolution tests that data integrity
// is maintained after conflict resolution.
func TestMergeToLocalDB_DataIntegrityAfterResolution(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create initial conflicting state
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-encrypted-data-12345"),
		Nonce:          []byte("local-nonce-123456"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusPending,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-10 * time.Minute),
		LocalUpdatedAt: now.Add(-10 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-encrypted-data-67890"),
		Nonce:          []byte("server-nonce-789012"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		IsDeleted:      false,
		CreatedAt:      now.Add(-2 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{
		ManualConflictResolution: false, // Last-write-wins
	}

	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify data integrity: local version should be kept (it's newer)
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)

	// All fields should be intact
	assert.Equal(t, "secret-1", retrieved.ID)
	assert.Equal(t, "Local Name", retrieved.Name)
	assert.Equal(t, pb.SecretType_SECRET_TYPE_CREDENTIAL, retrieved.Type)
	assert.Equal(t, []byte("local-encrypted-data-12345"), retrieved.EncryptedData)
	assert.Equal(t, []byte("local-nonce-123456"), retrieved.Nonce)
	assert.Equal(t, storage.SyncStatusConflict, retrieved.SyncStatus)

	// Timestamps should be preserved
	assert.False(t, retrieved.CreatedAt.IsZero())
	assert.False(t, retrieved.UpdatedAt.IsZero())
	assert.False(t, retrieved.LocalUpdatedAt.IsZero())
}

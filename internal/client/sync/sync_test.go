package sync

import (
	"context"
	"testing"
	"time"

	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/crypto"
	pb "github.com/koy/keyper/pkg/api/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetSyncStatusInfo_BasicFields tests that GetSyncStatusInfo returns correct basic information.
func TestGetSyncStatusInfo_BasicFields(t *testing.T) {
	// Setup
	tmpDB := t.TempDir() + "/test.db"
	repo, err := storage.NewSQLiteRepository(tmpDB)
	require.NoError(t, err)
	defer repo.Close()

	tmpCfg := t.TempDir() + "/config.yaml"
	cfg := &config.Config{
		ConfigPath: tmpCfg,
		DeviceID:   "test-device-123",
		LastSyncAt: time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
	}

	ctx := context.Background()

	// Add some pending secrets
	encKey := crypto.DeriveKey("test-password", []byte("test-salt-16byte"))
	encrypted, err := crypto.Encrypt([]byte("test-data"), encKey)
	require.NoError(t, err)

	// Extract nonce from encrypted data (first 12 bytes)
	nonce := []byte(encrypted)[:crypto.NonceSize]

	secret1 := &storage.LocalSecret{
		ID:            "secret-1",
		Name:          "Test Secret",
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData: []byte(encrypted),
		Nonce:         nonce,
		SyncStatus:    storage.SyncStatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	require.NoError(t, repo.Create(ctx, secret1))

	// Get sync status
	status, err := GetSyncStatusInfo(ctx, cfg, repo)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, "test-device-123", status.DeviceID)
	assert.Equal(t, 1, status.PendingChanges)
	assert.Equal(t, 0, status.ConflictCount)
	assert.NotNil(t, status.LastSyncTime)
	assert.Contains(t, status.NeedsSyncReason, "pending change")
}

// TestGetSyncStatusInfo_WithConflicts tests status with unresolved conflicts.
func TestGetSyncStatusInfo_WithConflicts(t *testing.T) {
	// Setup
	tmpDB := t.TempDir() + "/test.db"
	repo, err := storage.NewSQLiteRepository(tmpDB)
	require.NoError(t, err)
	defer repo.Close()

	tmpCfg := t.TempDir() + "/config.yaml"
	cfg := &config.Config{
		ConfigPath: tmpCfg,
		DeviceID:   "test-device-123",
	}

	ctx := context.Background()

	// Add a conflict
	conflict := &storage.Conflict{
		SecretID:           "secret-1",
		ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		LocalVersion:       1,
		ServerVersion:      2,
		LocalData:          []byte("local-data"),
		ServerData:         []byte("server-data"),
		LocalUpdatedAt:     time.Now(),
		ServerUpdatedAt:    time.Now(),
		Resolved:           false,
		ResolutionStrategy: "manual",
	}
	require.NoError(t, repo.CreateConflict(ctx, conflict))

	// Get sync status
	status, err := GetSyncStatusInfo(ctx, cfg, repo)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, 0, status.PendingChanges)
	assert.Equal(t, 1, status.ConflictCount)
	assert.Contains(t, status.NeedsSyncReason, "conflict")
}

// TestGetSyncStatusInfo_NeverSynced tests status when no sync has occurred.
func TestGetSyncStatusInfo_NeverSynced(t *testing.T) {
	// Setup
	tmpDB := t.TempDir() + "/test.db"
	repo, err := storage.NewSQLiteRepository(tmpDB)
	require.NoError(t, err)
	defer repo.Close()

	tmpCfg := t.TempDir() + "/config.yaml"
	cfg := &config.Config{
		ConfigPath: tmpCfg,
		DeviceID:   "test-device-123",
		LastSyncAt: "", // Never synced
	}

	ctx := context.Background()

	// Get sync status
	status, err := GetSyncStatusInfo(ctx, cfg, repo)
	require.NoError(t, err)

	// Verify
	assert.Nil(t, status.LastSyncTime)
	assert.Contains(t, status.NeedsSyncReason, "never synced")
}

// TestGetSyncStatusInfo_AllSynced tests status when everything is synced.
func TestGetSyncStatusInfo_AllSynced(t *testing.T) {
	// Setup
	tmpDB := t.TempDir() + "/test.db"
	repo, err := storage.NewSQLiteRepository(tmpDB)
	require.NoError(t, err)
	defer repo.Close()

	tmpCfg := t.TempDir() + "/config.yaml"
	cfg := &config.Config{
		ConfigPath: tmpCfg,
		DeviceID:   "test-device-123",
		LastSyncAt: time.Now().Add(-30 * time.Minute).Format(time.RFC3339),
	}

	ctx := context.Background()

	// Get sync status
	status, err := GetSyncStatusInfo(ctx, cfg, repo)
	require.NoError(t, err)

	// Verify - no pending changes, no conflicts, recent sync
	assert.Equal(t, 0, status.PendingChanges)
	assert.Equal(t, 0, status.ConflictCount)
	assert.Empty(t, status.NeedsSyncReason)
}

// TestGetSyncStatusInfo_OldSync tests status when last sync was long ago.
func TestGetSyncStatusInfo_OldSync(t *testing.T) {
	// Setup
	tmpDB := t.TempDir() + "/test.db"
	repo, err := storage.NewSQLiteRepository(tmpDB)
	require.NoError(t, err)
	defer repo.Close()

	tmpCfg := t.TempDir() + "/config.yaml"
	cfg := &config.Config{
		ConfigPath: tmpCfg,
		DeviceID:   "test-device-123",
		LastSyncAt: time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
	}

	ctx := context.Background()

	// Get sync status
	status, err := GetSyncStatusInfo(ctx, cfg, repo)
	require.NoError(t, err)

	// Verify
	assert.NotNil(t, status.LastSyncTime)
	assert.Contains(t, status.NeedsSyncReason, "more than 1 hour ago")
}

// TestSyncResult_BasicStructure tests that SyncResult contains expected fields.
func TestSyncResult_BasicStructure(t *testing.T) {
	result := &SyncResult{
		PulledSecrets:       5,
		PushedSecrets:       3,
		ConflictCount:       2,
		InitialPendingCount: 3,
		FinalPendingCount:   0,
		Success:             true,
		TotalDuration:       2 * time.Second,
		PullDuration:        1 * time.Second,
		PushDuration:        1 * time.Second,
	}

	assert.Equal(t, 5, result.PulledSecrets)
	assert.Equal(t, 3, result.PushedSecrets)
	assert.Equal(t, 2, result.ConflictCount)
	assert.True(t, result.Success)
	assert.Equal(t, 2*time.Second, result.TotalDuration)
}

// TestSyncOptions_DefaultValues tests default SyncOptions behavior.
func TestSyncOptions_DefaultValues(t *testing.T) {
	opts := &SyncOptions{}
	assert.False(t, opts.ForceServerWins)
	assert.Nil(t, opts.ProgressCallback)
}

// TestSyncOptions_ForceServerWins tests ForceServerWins flag.
func TestSyncOptions_ForceServerWins(t *testing.T) {
	opts := &SyncOptions{
		ForceServerWins: true,
	}
	assert.True(t, opts.ForceServerWins)
}

// TestSyncOptions_ProgressCallback tests progress callback functionality.
func TestSyncOptions_ProgressCallback(t *testing.T) {
	var messages []string
	opts := &SyncOptions{
		ProgressCallback: func(msg string) {
			messages = append(messages, msg)
		},
	}

	opts.ProgressCallback("test message 1")
	opts.ProgressCallback("test message 2")

	assert.Len(t, messages, 2)
	assert.Equal(t, "test message 1", messages[0])
	assert.Equal(t, "test message 2", messages[1])
}

// TestSync_NotAuthenticated tests that Sync returns error when not authenticated.
func TestSync_NotAuthenticated(t *testing.T) {
	// Setup
	tmpDB := t.TempDir() + "/test.db"
	repo, err := storage.NewSQLiteRepository(tmpDB)
	require.NoError(t, err)
	defer repo.Close()

	tmpCfg := t.TempDir() + "/config.yaml"
	cfg := &config.Config{
		ConfigPath: tmpCfg,
		DeviceID:   "test-device-123",
	}

	sess := &session.Session{
		// Not authenticated
		AccessToken: "",
	}

	ctx := context.Background()

	// Attempt sync
	result, err := Sync(ctx, cfg, sess, repo, nil)

	// Verify
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not authenticated")
	assert.False(t, result.Success)
}

// TestSync_WithNilOptions tests that Sync handles nil options gracefully.
func TestSync_WithNilOptions(t *testing.T) {
	// Setup
	tmpDB := t.TempDir() + "/test.db"
	repo, err := storage.NewSQLiteRepository(tmpDB)
	require.NoError(t, err)
	defer repo.Close()

	tmpCfg := t.TempDir() + "/config.yaml"
	cfg := &config.Config{
		ConfigPath: tmpCfg,
		DeviceID:   "test-device-123",
	}

	// Create authenticated session
	sess := &session.Session{
		AccessToken:  "test-token",
		RefreshToken: "test-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	encKey := crypto.DeriveKey("test-password", []byte("test-salt-16byte"))
	sess.SetEncryptionKey(encKey)

	ctx := context.Background()

	// Attempt sync with nil options (will fail due to no server, but should handle nil options)
	result, err := Sync(ctx, cfg, sess, repo, nil)

	// Verify - should fail on network call, not on nil options
	require.Error(t, err)
	assert.False(t, result.Success)
	// Should not panic on nil options
}

// TestInterruptedSyncRecovery_RequiresSQLiteRepository tests repository type checking.
func TestInterruptedSyncRecovery_RequiresSQLiteRepository(t *testing.T) {
	ctx := context.Background()

	// Mock repository that's not SQLiteRepository
	type mockRepo struct {
		storage.Repository
	}
	repo := &mockRepo{}

	err := InterruptedSyncRecovery(ctx, repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be a SQLiteRepository")
}

// TestInterruptedSyncRecovery_BasicFunctionality tests successful recovery.
func TestInterruptedSyncRecovery_BasicFunctionality(t *testing.T) {
	// Setup
	tmpDB := t.TempDir() + "/test.db"
	repo, err := storage.NewSQLiteRepository(tmpDB)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()

	// Run recovery
	err = InterruptedSyncRecovery(ctx, repo)
	require.NoError(t, err)
}

// TestSync_CollectsStatistics tests that sync operation collects proper statistics.
func TestSync_CollectsStatistics(t *testing.T) {
	// Setup
	tmpDB := t.TempDir() + "/test.db"
	repo, err := storage.NewSQLiteRepository(tmpDB)
	require.NoError(t, err)
	defer repo.Close()

	tmpCfg := t.TempDir() + "/config.yaml"
	cfg := &config.Config{
		ConfigPath: tmpCfg,
		DeviceID:   "test-device-123",
	}

	// Create authenticated session
	sess := &session.Session{
		AccessToken:  "test-token",
		RefreshToken: "test-refresh",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	encKey := crypto.DeriveKey("test-password", []byte("test-salt-16byte"))
	sess.SetEncryptionKey(encKey)

	ctx := context.Background()

	// Add some test data
	encrypted, err := crypto.Encrypt([]byte("test-data"), encKey)
	require.NoError(t, err)

	// Extract nonce from encrypted data (first 12 bytes)
	nonce := []byte(encrypted)[:crypto.NonceSize]

	secret := &storage.LocalSecret{
		ID:            "secret-1",
		Name:          "Test Secret",
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData: []byte(encrypted),
		Nonce:         nonce,
		SyncStatus:    storage.SyncStatusPending,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	require.NoError(t, repo.Create(ctx, secret))

	// Attempt sync (will fail due to no server, but should collect initial stats)
	result, err := Sync(ctx, cfg, sess, repo, nil)

	// Verify initial stats were collected
	assert.NotNil(t, result)
	assert.Equal(t, 1, result.InitialPendingCount)
	assert.Error(t, err) // Will fail on network call
}

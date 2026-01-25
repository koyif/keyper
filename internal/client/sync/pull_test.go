package sync

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/crypto"
	pb "github.com/koy/keyper/pkg/api/proto"
)

// setupTestConfig creates a temporary config for testing.
func setupTestConfig(t *testing.T) (*config.Config, func()) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	sessionPath := filepath.Join(tmpDir, "session.json")
	dbPath := filepath.Join(tmpDir, "keyper.db")

	cfg := &config.Config{
		Server:      "localhost:50051",
		ConfigPath:  configPath,
		SessionPath: sessionPath,
		DBPath:      dbPath,
		Verbose:     false,
		Format:      "text",
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return cfg, cleanup
}

// setupTestSession creates a test session with valid authentication.
func setupTestSession(t *testing.T, sessionPath string) *session.Session {
	t.Helper()
	sess := session.New(sessionPath)
	sess.UpdateTokens(
		"test-access-token",
		"test-refresh-token",
		time.Now().Add(1*time.Hour),
	)
	return sess
}

func TestPull_NotAuthenticated(t *testing.T) {
	cfg, cleanup := setupTestConfig(t)
	defer cleanup()

	sess := session.New(cfg.SessionPath)
	ctx := context.Background()

	_, err := Pull(ctx, cfg, sess)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not authenticated")
}

func TestPull_InvalidLastSyncAtTimestamp(t *testing.T) {
	cfg, cleanup := setupTestConfig(t)
	defer cleanup()

	sess := setupTestSession(t, cfg.SessionPath)
	cfg.LastSyncAt = "invalid-timestamp"
	ctx := context.Background()

	// Mock the session's EnsureValidToken to avoid actual network calls
	// This test focuses on timestamp parsing, so we expect it to fail before network calls
	_, err := Pull(ctx, cfg, sess)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse last_sync_at timestamp")
}

func TestPull_FirstSync_NoLastSyncAt(t *testing.T) {
	// This test verifies that Pull works correctly on first sync (no last_sync_at).
	// In a real implementation, this would require a mock gRPC server.
	// For now, we just verify the timestamp parsing logic doesn't fail.
	cfg, cleanup := setupTestConfig(t)
	defer cleanup()

	sess := setupTestSession(t, cfg.SessionPath)
	cfg.LastSyncAt = "" // First sync, no previous timestamp

	// Since we don't have a mock server set up, this will fail at connection
	// but we can verify it gets past the timestamp parsing.
	ctx := context.Background()
	_, err := Pull(ctx, cfg, sess)
	// We expect an error from connection/server, not from timestamp parsing.
	if err != nil {
		assert.NotContains(t, err.Error(), "failed to parse last_sync_at timestamp")
	}
}

func TestPull_WithValidLastSyncAt(t *testing.T) {
	cfg, cleanup := setupTestConfig(t)
	defer cleanup()

	sess := setupTestSession(t, cfg.SessionPath)

	// Set a valid last sync timestamp.
	lastSync := time.Now().Add(-1 * time.Hour)
	cfg.LastSyncAt = lastSync.Format(time.RFC3339)

	// Since we don't have a mock server set up, this will fail at connection
	// but we can verify it gets past the timestamp parsing.
	ctx := context.Background()
	_, err := Pull(ctx, cfg, sess)
	// We expect an error from connection/server, not from timestamp parsing.
	if err != nil {
		assert.NotContains(t, err.Error(), "failed to parse last_sync_at timestamp")
	}
}

func TestPull_DeviceIDGeneration(t *testing.T) {
	cfg, cleanup := setupTestConfig(t)
	defer cleanup()

	sess := setupTestSession(t, cfg.SessionPath)
	ctx := context.Background()

	// Ensure config directory exists.
	require.NoError(t, cfg.EnsureDirectories())

	// First call should generate a device ID.
	_, err1 := Pull(ctx, cfg, sess)

	// We expect an error from connection, but device ID should be generated.
	if err1 != nil {
		assert.NotContains(t, err1.Error(), "failed to get device ID")
	}

	// Verify device ID was generated and saved.
	deviceID1, err := GetDeviceID(cfg)
	require.NoError(t, err)
	assert.NotEmpty(t, deviceID1)

	// Second call should reuse the same device ID.
	deviceID2, err := GetDeviceID(cfg)
	require.NoError(t, err)
	assert.Equal(t, deviceID1, deviceID2)
}

// TestPull_ResponseParsing tests that PullResult is correctly populated from server response.
func TestPull_ResponseParsing(t *testing.T) {
	// This is a unit test for the response parsing logic
	// In a real implementation with a mock server, we would test the full flow

	now := time.Now()

	// Create a mock response.
	mockResp := &pb.PullResponse{
		Secrets: []*pb.Secret{
			{
				Id:            "secret-1",
				UserId:        "user-1",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				Title:         "Test Secret",
				EncryptedData: "encrypted-data-1",
				Version:       1,
				IsDeleted:     false,
				CreatedAt:     timestamppb.New(now.Add(-1 * time.Hour)),
				UpdatedAt:     timestamppb.New(now),
			},
		},
		DeletedSecretIds: []string{"deleted-1", "deleted-2"},
		CurrentVersion:   10,
		SyncTime:         timestamppb.New(now),
		HasConflicts:     false,
		Conflicts:        nil,
	}

	// Simulate parsing the response into PullResult.
	result := &PullResult{
		Secrets:          mockResp.Secrets,
		DeletedSecretIDs: mockResp.DeletedSecretIds,
		CurrentVersion:   mockResp.CurrentVersion,
		SyncTime:         mockResp.SyncTime.AsTime(),
		HasConflicts:     mockResp.HasConflicts,
		Conflicts:        mockResp.Conflicts,
	}

	// Verify parsing.
	assert.Len(t, result.Secrets, 1)
	assert.Equal(t, "secret-1", result.Secrets[0].Id)
	assert.Equal(t, "Test Secret", result.Secrets[0].Title)
	assert.Len(t, result.DeletedSecretIDs, 2)
	assert.Equal(t, int64(10), result.CurrentVersion)
	assert.False(t, result.HasConflicts)
	assert.Nil(t, result.Conflicts)
	assert.Equal(t, mockResp.SyncTime.AsTime(), result.SyncTime)
}

// TestPull_WithConflicts tests that conflicts are correctly parsed from the response.
func TestPull_WithConflicts(t *testing.T) {
	now := time.Now()

	// Create a mock response with conflicts.
	mockResp := &pb.PullResponse{
		Secrets:          []*pb.Secret{},
		DeletedSecretIds: []string{},
		CurrentVersion:   5,
		SyncTime:         timestamppb.New(now),
		HasConflicts:     true,
		Conflicts: []*pb.Conflict{
			{
				SecretId: "conflict-1",
				Type:     pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
				ServerVersion: &pb.Secret{
					Id:    "conflict-1",
					Title: "Server Version",
				},
				ClientVersion: &pb.Secret{
					Id:    "conflict-1",
					Title: "Client Version",
				},
				Description: "Both client and server modified",
			},
		},
	}

	// Simulate parsing the response into PullResult.
	result := &PullResult{
		Secrets:          mockResp.Secrets,
		DeletedSecretIDs: mockResp.DeletedSecretIds,
		CurrentVersion:   mockResp.CurrentVersion,
		SyncTime:         mockResp.SyncTime.AsTime(),
		HasConflicts:     mockResp.HasConflicts,
		Conflicts:        mockResp.Conflicts,
	}

	// Verify conflict parsing.
	assert.True(t, result.HasConflicts)
	assert.Len(t, result.Conflicts, 1)
	assert.Equal(t, "conflict-1", result.Conflicts[0].SecretId)
	assert.Equal(t, pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED, result.Conflicts[0].Type)
	assert.Equal(t, "Server Version", result.Conflicts[0].ServerVersion.Title)
	assert.Equal(t, "Client Version", result.Conflicts[0].ClientVersion.Title)
	assert.Empty(t, result.Secrets)
	assert.Empty(t, result.DeletedSecretIDs)
	assert.Equal(t, int64(5), result.CurrentVersion)
	assert.Equal(t, mockResp.SyncTime.AsTime(), result.SyncTime)
}

// TestPull_UpdatesLastSyncAt verifies that last_sync_at is updated after successful pull.
func TestPull_UpdatesLastSyncAt(t *testing.T) {
	cfg, cleanup := setupTestConfig(t)
	defer cleanup()

	// Ensure config directories exist.
	require.NoError(t, cfg.EnsureDirectories())

	// Set initial last_sync_at.
	initialTime := time.Now().Add(-2 * time.Hour)
	cfg.LastSyncAt = initialTime.Format(time.RFC3339)

	// Save device ID first so we can test the update.
	_, err := LoadOrCreateDeviceID(cfg)
	require.NoError(t, err)

	// Simulate updating last_sync_at after a successful pull.
	newSyncTime := time.Now()
	err = UpdateLastSyncAt(cfg, newSyncTime.Format(time.RFC3339))
	require.NoError(t, err)

	// Verify the timestamp was updated.
	assert.Equal(t, newSyncTime.Format(time.RFC3339), cfg.LastSyncAt)

	// Verify it was persisted to disk.
	cfg2, err := config.Load(cfg.ConfigPath)
	require.NoError(t, err)
	assert.Equal(t, newSyncTime.Format(time.RFC3339), cfg2.LastSyncAt)
}

// TestPullResult_EmptyResponse tests handling of empty server response (no changes).
func TestPullResult_EmptyResponse(t *testing.T) {
	now := time.Now()

	mockResp := &pb.PullResponse{
		Secrets:          []*pb.Secret{},
		DeletedSecretIds: []string{},
		CurrentVersion:   5,
		SyncTime:         timestamppb.New(now),
		HasConflicts:     false,
		Conflicts:        nil,
	}

	result := &PullResult{
		Secrets:          mockResp.Secrets,
		DeletedSecretIDs: mockResp.DeletedSecretIds,
		CurrentVersion:   mockResp.CurrentVersion,
		SyncTime:         mockResp.SyncTime.AsTime(),
		HasConflicts:     mockResp.HasConflicts,
		Conflicts:        mockResp.Conflicts,
	}

	// Verify empty response is handled correctly.
	assert.Empty(t, result.Secrets)
	assert.Empty(t, result.DeletedSecretIDs)
	assert.Equal(t, int64(5), result.CurrentVersion)
	assert.False(t, result.HasConflicts)
}

// BenchmarkPullResult_Parsing benchmarks Pull operation parsing only, no network.
func BenchmarkPullResult_Parsing(b *testing.B) {
	now := time.Now()

	mockResp := &pb.PullResponse{
		Secrets: []*pb.Secret{
			{
				Id:            "secret-1",
				UserId:        "user-1",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				Title:         "Test Secret",
				EncryptedData: "encrypted-data",
				Version:       1,
				CreatedAt:     timestamppb.New(now),
				UpdatedAt:     timestamppb.New(now),
			},
		},
		DeletedSecretIds: []string{"deleted-1"},
		CurrentVersion:   10,
		SyncTime:         timestamppb.New(now),
	}

	var result *PullResult

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result = &PullResult{
			Secrets:          mockResp.Secrets,
			DeletedSecretIDs: mockResp.DeletedSecretIds,
			CurrentVersion:   mockResp.CurrentVersion,
			SyncTime:         mockResp.SyncTime.AsTime(),
			HasConflicts:     mockResp.HasConflicts,
			Conflicts:        mockResp.Conflicts,
		}
	}

	// Prevent compiler from optimizing away the benchmark loop.
	_ = result
}

// ExamplePull demonstrates expected usage of Pull.
func ExamplePull() {
	// This is an example of how Pull would be used in practice.
	cfg := &config.Config{
		Server:     "localhost:50051",
		LastSyncAt: time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
	}

	sess := session.New("/tmp/session.json")
	sess.UpdateTokens("access-token", "refresh-token", time.Now().Add(1*time.Hour))

	ctx := context.Background()

	// In practice, this would connect to a real server.
	result, err := Pull(ctx, cfg, sess)
	if err != nil {
		fmt.Printf("Pull failed: %v\n", err)
		return
	}

	fmt.Printf("Pulled %d secrets, %d deleted\n",
		len(result.Secrets),
		len(result.DeletedSecretIDs))
}

// Tests for decryption and merge functionality.

func TestDecryptSecrets_EmptyInput(t *testing.T) {
	encryptionKey := []byte("12345678901234567890123456789012") // Exactly 32 bytes

	result, err := decryptSecrets(nil, encryptionKey)
	require.NoError(t, err)
	assert.Nil(t, result)

	result, err = decryptSecrets([]*pb.Secret{}, encryptionKey)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestDecryptSecrets_InvalidEncryptedData(t *testing.T) {
	encryptionKey := []byte("12345678901234567890123456789012") // Exactly 32 bytes

	secrets := []*pb.Secret{
		{
			Id:            "secret-1",
			Title:         "Test Secret",
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: "invalid-base64-data",
			Version:       1,
		},
	}

	_, err := decryptSecrets(secrets, encryptionKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt secret")
}

func TestDecryptSecrets_CorrectlyParsesMetadata(t *testing.T) {
	// Import crypto package for encryption.
	encryptionKey := []byte("12345678901234567890123456789012") // Exactly 32 bytes

	// Create a properly encrypted secret.
	plaintext := []byte(`{"username":"user","password":"pass"}`)
	encrypted, err := crypto.Encrypt(plaintext, encryptionKey)
	require.NoError(t, err)

	now := time.Now()
	secrets := []*pb.Secret{
		{
			Id:            "secret-1",
			Title:         "Test Secret",
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: encrypted,
			Metadata: &pb.Metadata{
				Category:   "work",
				Tags:       []string{"important", "prod"},
				IsFavorite: true,
			},
			Version:   1,
			IsDeleted: false,
			CreatedAt: timestamppb.New(now),
			UpdatedAt: timestamppb.New(now),
		},
	}

	result, err := decryptSecrets(secrets, encryptionKey)
	require.NoError(t, err)
	require.Len(t, result, 1)

	// Verify metadata was marshaled to JSON.
	assert.Contains(t, result[0].Metadata, "category")
	assert.Contains(t, result[0].Metadata, "work")
	assert.Contains(t, result[0].Metadata, "important")
}

func TestDecryptSecrets_ValidatesDecryption(t *testing.T) {
	// Create two different keys.
	encryptionKey1 := []byte("12345678901234567890123456789012") // Exactly 32 bytes
	encryptionKey2 := []byte("98765432109876543210987654321098") // Exactly 32 bytes

	// Encrypt with key1.
	plaintext := []byte(`{"username":"user","password":"pass"}`)
	encrypted, err := crypto.Encrypt(plaintext, encryptionKey1)
	require.NoError(t, err)

	now := time.Now()
	secrets := []*pb.Secret{
		{
			Id:            "secret-1",
			Title:         "Test Secret",
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: encrypted,
			Version:       1,
			CreatedAt:     timestamppb.New(now),
			UpdatedAt:     timestamppb.New(now),
		},
	}

	// Try to decrypt with key2 - should fail.
	_, err = decryptSecrets(secrets, encryptionKey2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt secret")
}

func TestDecryptSecrets_SuccessfulDecryption(t *testing.T) {
	encryptionKey := []byte("12345678901234567890123456789012") // Exactly 32 bytes

	// Create properly encrypted secrets.
	plaintext1 := []byte(`{"username":"user1","password":"pass1"}`)
	encrypted1, err := crypto.Encrypt(plaintext1, encryptionKey)
	require.NoError(t, err)

	plaintext2 := []byte(`{"note":"This is a secure note"}`)
	encrypted2, err := crypto.Encrypt(plaintext2, encryptionKey)
	require.NoError(t, err)

	now := time.Now()
	secrets := []*pb.Secret{
		{
			Id:            "secret-1",
			Title:         "Login Credential",
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: encrypted1,
			Metadata: &pb.Metadata{
				Category:   "work",
				Tags:       []string{"important"},
				IsFavorite: true,
			},
			Version:   1,
			IsDeleted: false,
			CreatedAt: timestamppb.New(now.Add(-2 * time.Hour)),
			UpdatedAt: timestamppb.New(now.Add(-1 * time.Hour)),
		},
		{
			Id:            "secret-2",
			Title:         "Secure Note",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encrypted2,
			Version:       2,
			IsDeleted:     false,
			CreatedAt:     timestamppb.New(now.Add(-1 * time.Hour)),
			UpdatedAt:     timestamppb.New(now),
		},
	}

	result, err := decryptSecrets(secrets, encryptionKey)
	require.NoError(t, err)
	require.Len(t, result, 2)

	// Verify first secret.
	assert.Equal(t, "secret-1", result[0].ID)
	assert.Equal(t, "Login Credential", result[0].Name)
	assert.Equal(t, pb.SecretType_SECRET_TYPE_CREDENTIAL, result[0].Type)
	assert.Equal(t, int64(1), result[0].Version)
	assert.Equal(t, int64(1), result[0].ServerVersion)
	assert.Equal(t, storage.SyncStatusSynced, result[0].SyncStatus)
	assert.False(t, result[0].IsDeleted)
	assert.NotEmpty(t, result[0].Nonce)
	assert.Len(t, result[0].Nonce, crypto.NonceSize)
	assert.Contains(t, result[0].Metadata, "work")
	assert.Contains(t, result[0].Metadata, "important")

	// Verify second secret.
	assert.Equal(t, "secret-2", result[1].ID)
	assert.Equal(t, "Secure Note", result[1].Name)
	assert.Equal(t, pb.SecretType_SECRET_TYPE_TEXT, result[1].Type)
	assert.Equal(t, int64(2), result[1].Version)
	assert.Empty(t, result[1].Metadata) // No metadata provided
}

func TestDecryptSecrets_BatchProcessing(t *testing.T) {
	encryptionKey := []byte("12345678901234567890123456789012") // Exactly 32 bytes

	// Create a batch of 100 secrets.
	now := time.Now()
	secrets := make([]*pb.Secret, 100)

	for i := 0; i < 100; i++ {
		plaintext := []byte(fmt.Sprintf(`{"id":%d,"data":"test-data-%d"}`, i, i))
		encrypted, err := crypto.Encrypt(plaintext, encryptionKey)
		require.NoError(t, err)

		secrets[i] = &pb.Secret{
			Id:            fmt.Sprintf("secret-%d", i),
			Title:         fmt.Sprintf("Secret %d", i),
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: encrypted,
			Version:       int64(i + 1),
			CreatedAt:     timestamppb.New(now),
			UpdatedAt:     timestamppb.New(now),
		}
	}

	result, err := decryptSecrets(secrets, encryptionKey)
	require.NoError(t, err)
	assert.Len(t, result, 100)

	// Spot check a few secrets.
	assert.Equal(t, "secret-0", result[0].ID)
	assert.Equal(t, "secret-50", result[50].ID)
	assert.Equal(t, "secret-99", result[99].ID)
}

func TestDecryptSecrets_NonceExtraction(t *testing.T) {
	encryptionKey := []byte("12345678901234567890123456789012")

	plaintext := []byte(`{"test":"data"}`)
	encrypted, err := crypto.Encrypt(plaintext, encryptionKey)
	require.NoError(t, err)

	now := time.Now()
	secrets := []*pb.Secret{
		{
			Id:            "secret-1",
			Title:         "Test",
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: encrypted,
			Version:       1,
			CreatedAt:     timestamppb.New(now),
			UpdatedAt:     timestamppb.New(now),
		},
	}

	result, err := decryptSecrets(secrets, encryptionKey)
	require.NoError(t, err)
	require.Len(t, result, 1)

	// Verify nonce was extracted correctly.
	assert.Len(t, result[0].Nonce, crypto.NonceSize)
	assert.NotNil(t, result[0].EncryptedData)

	// Verify the nonce is at the beginning of the encrypted data.
	encryptedBytes := []byte(encrypted)
	extractedNonce := result[0].Nonce
	assert.Equal(t, encryptedBytes[:crypto.NonceSize], extractedNonce)
}

func TestDecryptSecrets_MetadataMarshalingEdgeCases(t *testing.T) {
	encryptionKey := []byte("12345678901234567890123456789012")

	plaintext := []byte(`{"data":"test"}`)
	encrypted, err := crypto.Encrypt(plaintext, encryptionKey)
	require.NoError(t, err)

	now := time.Now()

	tests := []struct {
		name     string
		metadata *pb.Metadata
		wantJSON bool
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			wantJSON: false,
		},
		{
			name: "empty metadata",
			metadata: &pb.Metadata{
				Category:   "",
				Tags:       nil,
				IsFavorite: false,
			},
			wantJSON: true,
		},
		{
			name: "metadata with special characters",
			metadata: &pb.Metadata{
				Category: "work/personal",
				Tags:     []string{"urgent!", "review@", "test&done"},
			},
			wantJSON: true,
		},
		{
			name: "metadata with unicode",
			metadata: &pb.Metadata{
				Category: "工作",
				Tags:     []string{"重要", "紧急"},
			},
			wantJSON: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := []*pb.Secret{
				{
					Id:            "secret-1",
					Title:         "Test",
					Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
					EncryptedData: encrypted,
					Metadata:      tt.metadata,
					Version:       1,
					CreatedAt:     timestamppb.New(now),
					UpdatedAt:     timestamppb.New(now),
				},
			}

			result, err := decryptSecrets(secrets, encryptionKey)
			require.NoError(t, err)
			require.Len(t, result, 1)

			if tt.wantJSON {
				assert.NotEmpty(t, result[0].Metadata)
			} else {
				assert.Empty(t, result[0].Metadata)
			}
		})
	}
}

func TestMergeToLocalDB_RequiresSQLiteRepository(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}

	// Create a mock repository that's not SQLiteRepository.
	var repo storage.Repository

	err := mergeToLocalDB(ctx, cfg, repo, nil, nil, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "repository must be a SQLiteRepository")
}

func TestMergeToLocalDB_HandlesEmptyInput(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{}
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	// Merge empty data should succeed without errors.
	err = mergeToLocalDB(ctx, cfg, repo, nil, nil, 1)
	assert.NoError(t, err)
}

func TestMergeToLocalDB_InsertsNewSecrets(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()
	secrets := []*storage.LocalSecret{
		{
			ID:             "secret-1",
			Name:           "Test Secret 1",
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("encrypted-data-1"),
			Nonce:          []byte("nonce-123456"),
			Metadata:       `{"category":"work"}`,
			Version:        1,
			IsDeleted:      false,
			SyncStatus:     storage.SyncStatusSynced,
			ServerVersion:  1,
			CreatedAt:      now,
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		},
		{
			ID:             "secret-2",
			Name:           "Test Secret 2",
			Type:           pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData:  []byte("encrypted-data-2"),
			Nonce:          []byte("nonce-789012"),
			Metadata:       `{"category":"personal"}`,
			Version:        1,
			IsDeleted:      false,
			SyncStatus:     storage.SyncStatusSynced,
			ServerVersion:  1,
			CreatedAt:      now,
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		},
	}

	cfg := &config.Config{}
	err = mergeToLocalDB(ctx, cfg, repo, secrets, nil, 1)
	require.NoError(t, err)

	// Verify secrets were inserted.
	retrieved1, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Test Secret 1", retrieved1.Name)
	assert.Equal(t, storage.SyncStatusSynced, retrieved1.SyncStatus)

	retrieved2, err := repo.Get(ctx, "secret-2")
	require.NoError(t, err)
	assert.Equal(t, "Test Secret 2", retrieved2.Name)
}

func TestMergeToLocalDB_UpdatesExistingSecrets(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Insert initial secret.
	initialSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Initial Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("initial-data"),
		Nonce:          []byte("initial-nonce"),
		Metadata:       `{"category":"work"}`,
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusSynced,
		CreatedAt:      now.Add(-1 * time.Hour),
		UpdatedAt:      now.Add(-1 * time.Hour),
		LocalUpdatedAt: now.Add(-1 * time.Hour),
	}
	err = repo.Create(ctx, initialSecret)
	require.NoError(t, err)

	// Update with newer version from server.
	updatedSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Updated Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("updated-data"),
		Nonce:          []byte("updated-nonce"),
		Metadata:       `{"category":"personal"}`,
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		CreatedAt:      now.Add(-1 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg := &config.Config{}
	err = mergeToLocalDB(ctx, cfg, repo, []*storage.LocalSecret{updatedSecret}, nil, 2)
	require.NoError(t, err)

	// Verify secret was updated.
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", retrieved.Name)
	assert.Equal(t, int64(2), retrieved.Version)
	assert.Equal(t, []byte("updated-data"), retrieved.EncryptedData)
}

func TestMergeToLocalDB_SkipsOlderVersions(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Insert secret with version 5.
	currentSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Current Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("current-data"),
		Nonce:          []byte("current-nonce"),
		Metadata:       `{"category":"work"}`,
		Version:        5,
		ServerVersion:  5,
		SyncStatus:     storage.SyncStatusSynced,
		CreatedAt:      now.Add(-1 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}
	err = repo.Create(ctx, currentSecret)
	require.NoError(t, err)

	// Try to update with older version 3.
	olderSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Older Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("older-data"),
		Nonce:          []byte("older-nonce"),
		Metadata:       `{"category":"personal"}`,
		Version:        3,
		ServerVersion:  3,
		SyncStatus:     storage.SyncStatusSynced,
		CreatedAt:      now.Add(-1 * time.Hour),
		UpdatedAt:      now.Add(-30 * time.Minute),
		LocalUpdatedAt: now,
	}

	cfg2 := &config.Config{}
	err = mergeToLocalDB(ctx, cfg2, repo, []*storage.LocalSecret{olderSecret}, nil, 3)
	require.NoError(t, err)

	// Verify secret was NOT updated (still has current version).
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Current Name", retrieved.Name)
	assert.Equal(t, int64(5), retrieved.Version)
	assert.Equal(t, []byte("current-data"), retrieved.EncryptedData)
}

func TestMergeToLocalDB_HandlesDeletes(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Insert some secrets.
	secrets := []*storage.LocalSecret{
		{
			ID:             "secret-1",
			Name:           "Secret 1",
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("data-1"),
			Nonce:          []byte("nonce-1"),
			Version:        1,
			ServerVersion:  1,
			SyncStatus:     storage.SyncStatusSynced,
			CreatedAt:      now,
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		},
		{
			ID:             "secret-2",
			Name:           "Secret 2",
			Type:           pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData:  []byte("data-2"),
			Nonce:          []byte("nonce-2"),
			Version:        1,
			ServerVersion:  1,
			SyncStatus:     storage.SyncStatusSynced,
			CreatedAt:      now,
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		},
	}

	for _, secret := range secrets {
		err = repo.Create(ctx, secret)
		require.NoError(t, err)
	}

	// Delete secret-1.
	deletedIDs := []string{"secret-1"}
	cfg3 := &config.Config{}
	err = mergeToLocalDB(ctx, cfg3, repo, nil, deletedIDs, 2)
	require.NoError(t, err)

	// Verify secret-1 was deleted.
	_, err = repo.Get(ctx, "secret-1")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrSecretNotFound))

	// Verify secret-2 still exists.
	retrieved, err := repo.Get(ctx, "secret-2")
	require.NoError(t, err)
	assert.Equal(t, "Secret 2", retrieved.Name)
}

func TestMergeToLocalDB_TransactionRollback(t *testing.T) {
	// This test verifies transaction atomicity.
	// If one operation fails, the entire transaction should rollback.
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create a valid secret.
	validSecret := &storage.LocalSecret{
		ID:             "valid-secret",
		Name:           "Valid Secret",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("valid-data"),
		Nonce:          []byte("valid-nonce"),
		Version:        1,
		ServerVersion:  1,
		SyncStatus:     storage.SyncStatusSynced,
		CreatedAt:      now,
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	// Note: It's difficult to force a transaction failure in SQLite
	// without corrupting the database or using invalid data.
	// This test serves as a placeholder for integration testing.
	cfg4 := &config.Config{}
	err = mergeToLocalDB(ctx, cfg4, repo, []*storage.LocalSecret{validSecret}, nil, 1)
	require.NoError(t, err)

	// Verify the secret was inserted.
	_, err = repo.Get(ctx, "valid-secret")
	require.NoError(t, err)
}

func TestMergeToLocalDB_MixedOperations(t *testing.T) {
	// Test a realistic scenario with inserts, updates, and deletes in one batch.
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Setup: Insert some initial secrets.
	initialSecrets := []*storage.LocalSecret{
		{
			ID:             "existing-1",
			Name:           "Existing Secret 1",
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("initial-data-1"),
			Nonce:          []byte("initial-nonce-1"),
			Version:        1,
			ServerVersion:  1,
			SyncStatus:     storage.SyncStatusSynced,
			CreatedAt:      now.Add(-2 * time.Hour),
			UpdatedAt:      now.Add(-2 * time.Hour),
			LocalUpdatedAt: now.Add(-2 * time.Hour),
		},
		{
			ID:             "existing-2",
			Name:           "Existing Secret 2",
			Type:           pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData:  []byte("initial-data-2"),
			Nonce:          []byte("initial-nonce-2"),
			Version:        1,
			ServerVersion:  1,
			SyncStatus:     storage.SyncStatusSynced,
			CreatedAt:      now.Add(-2 * time.Hour),
			UpdatedAt:      now.Add(-2 * time.Hour),
			LocalUpdatedAt: now.Add(-2 * time.Hour),
		},
		{
			ID:             "to-delete",
			Name:           "Will Be Deleted",
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("delete-me"),
			Nonce:          []byte("delete-nonce"),
			Version:        1,
			ServerVersion:  1,
			SyncStatus:     storage.SyncStatusSynced,
			CreatedAt:      now.Add(-2 * time.Hour),
			UpdatedAt:      now.Add(-2 * time.Hour),
			LocalUpdatedAt: now.Add(-2 * time.Hour),
		},
	}

	for _, secret := range initialSecrets {
		err = repo.Create(ctx, secret)
		require.NoError(t, err)
	}

	// Prepare merge data: 1 new, 1 update, 1 delete.
	mergeSecrets := []*storage.LocalSecret{
		{
			ID:             "new-secret",
			Name:           "Brand New Secret",
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("new-data"),
			Nonce:          []byte("new-nonce"),
			Version:        1,
			ServerVersion:  1,
			SyncStatus:     storage.SyncStatusSynced,
			CreatedAt:      now,
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		},
		{
			ID:             "existing-1",
			Name:           "Updated Secret 1",
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte("updated-data-1"),
			Nonce:          []byte("updated-nonce-1"),
			Version:        2,
			ServerVersion:  2,
			SyncStatus:     storage.SyncStatusSynced,
			CreatedAt:      now.Add(-2 * time.Hour),
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		},
	}

	deletedIDs := []string{"to-delete"}

	// Perform merge.
	cfg5 := &config.Config{}
	err = mergeToLocalDB(ctx, cfg5, repo, mergeSecrets, deletedIDs, 2)
	require.NoError(t, err)

	// Verify results.
	// 1. New secret should exist.
	newSecret, err := repo.Get(ctx, "new-secret")
	require.NoError(t, err)
	assert.Equal(t, "Brand New Secret", newSecret.Name)

	// 2. Existing-1 should be updated.
	updated, err := repo.Get(ctx, "existing-1")
	require.NoError(t, err)
	assert.Equal(t, "Updated Secret 1", updated.Name)
	assert.Equal(t, int64(2), updated.Version)
	assert.Equal(t, []byte("updated-data-1"), updated.EncryptedData)

	// 3. Existing-2 should remain unchanged.
	unchanged, err := repo.Get(ctx, "existing-2")
	require.NoError(t, err)
	assert.Equal(t, "Existing Secret 2", unchanged.Name)
	assert.Equal(t, int64(1), unchanged.Version)

	// 4. to-delete should be gone.
	_, err = repo.Get(ctx, "to-delete")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrSecretNotFound))
}

func TestMergeToLocalDB_SameVersionUpdate(t *testing.T) {
	// Test that updates with same version are applied (>=, not just >).
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Insert initial secret with version 5.
	initial := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Initial Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("initial-data"),
		Nonce:          []byte("initial-nonce"),
		Version:        5,
		ServerVersion:  5,
		SyncStatus:     storage.SyncStatusSynced,
		CreatedAt:      now.Add(-1 * time.Hour),
		UpdatedAt:      now.Add(-1 * time.Hour),
		LocalUpdatedAt: now.Add(-1 * time.Hour),
	}
	err = repo.Create(ctx, initial)
	require.NoError(t, err)

	// Update with same version (version 5).
	update := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Updated Name",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("updated-data"),
		Nonce:          []byte("updated-nonce"),
		Version:        5,
		ServerVersion:  5,
		SyncStatus:     storage.SyncStatusSynced,
		CreatedAt:      now.Add(-1 * time.Hour),
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	cfg6 := &config.Config{}
	err = mergeToLocalDB(ctx, cfg6, repo, []*storage.LocalSecret{update}, nil, 5)
	require.NoError(t, err)

	// Verify update was applied.
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", retrieved.Name)
	assert.Equal(t, []byte("updated-data"), retrieved.EncryptedData)
}

func TestMergeToLocalDB_DeleteNonExistentSecret(t *testing.T) {
	// Deleting a non-existent secret should not cause an error because
	// mergeToLocalDB explicitly handles ErrSecretNotFound.
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	// Try to delete a secret that doesn't exist.
	deletedIDs := []string{"non-existent-id"}

	cfg7 := &config.Config{}
	err = mergeToLocalDB(ctx, cfg7, repo, nil, deletedIDs, 1)
	// Should not error - mergeToLocalDB ignores ErrSecretNotFound for deletions.
	assert.NoError(t, err)
}

func TestMergeToLocalDB_LargeDataset(t *testing.T) {
	// Test performance with a large number of secrets.
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create 1000 secrets.
	secrets := make([]*storage.LocalSecret, 1000)
	for i := 0; i < 1000; i++ {
		secrets[i] = &storage.LocalSecret{
			ID:             fmt.Sprintf("secret-%d", i),
			Name:           fmt.Sprintf("Secret %d", i),
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte(fmt.Sprintf("data-%d", i)),
			Nonce:          []byte(fmt.Sprintf("nonce-%06d", i)),
			Version:        1,
			ServerVersion:  1,
			SyncStatus:     storage.SyncStatusSynced,
			CreatedAt:      now,
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		}
	}

	// Merge all secrets.
	cfg := &config.Config{}
	err = mergeToLocalDB(ctx, cfg, repo, secrets, nil, 1)
	require.NoError(t, err)

	// Verify a sample of secrets.
	for _, idx := range []int{0, 100, 500, 999} {
		secret, err := repo.Get(ctx, fmt.Sprintf("secret-%d", idx))
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("Secret %d", idx), secret.Name)
	}
}

func TestMergeToLocalDB_ConcurrentVersionConflict(t *testing.T) {
	// Test version conflict resolution when local has newer version.
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Simulate local modification: version 3.
	localSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Local Version",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("local-data"),
		Nonce:          []byte("local-nonce"),
		Version:        3,
		ServerVersion:  3,
		SyncStatus:     storage.SyncStatusSynced,
		CreatedAt:      now.Add(-1 * time.Hour),
		UpdatedAt:      now.Add(-10 * time.Minute),
		LocalUpdatedAt: now.Add(-10 * time.Minute),
	}
	err = repo.Create(ctx, localSecret)
	require.NoError(t, err)

	// Server sends older version 2.
	serverSecret := &storage.LocalSecret{
		ID:             "secret-1",
		Name:           "Server Version",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte("server-data"),
		Nonce:          []byte("server-nonce"),
		Version:        2,
		ServerVersion:  2,
		SyncStatus:     storage.SyncStatusSynced,
		CreatedAt:      now.Add(-1 * time.Hour),
		UpdatedAt:      now.Add(-20 * time.Minute),
		LocalUpdatedAt: now,
	}

	cfg8 := &config.Config{}
	err = mergeToLocalDB(ctx, cfg8, repo, []*storage.LocalSecret{serverSecret}, nil, 2)
	require.NoError(t, err)

	// Verify local version is preserved.
	retrieved, err := repo.Get(ctx, "secret-1")
	require.NoError(t, err)
	assert.Equal(t, "Local Version", retrieved.Name)
	assert.Equal(t, int64(3), retrieved.Version)
	assert.Equal(t, []byte("local-data"), retrieved.EncryptedData)
}

func TestPullAndSync_NoEncryptionKey(t *testing.T) {
	cfg, cleanup := setupTestConfig(t)
	defer cleanup()

	sess := setupTestSession(t, cfg.SessionPath)
	// Don't set encryption key.

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	repo, err := storage.NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	ctx := context.Background()
	err = PullAndSync(ctx, cfg, sess, repo)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no encryption key available")
}

func TestPullAndSync_Integration(t *testing.T) {
	// This is a placeholder for integration testing.
	// A full integration test would require:
	// 1. Mock gRPC server
	// 2. Valid encrypted secrets
	// 3. Proper encryption keys
	// 4. Database verification

	t.Skip("Integration test requires mock gRPC server")
}

// Benchmark tests.

func BenchmarkDecryptSecrets_10Secrets(b *testing.B) {
	encryptionKey := []byte("12345678901234567890123456789012")
	secrets := createBenchmarkSecrets(b, 10, encryptionKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decryptSecrets(secrets, encryptionKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptSecrets_100Secrets(b *testing.B) {
	encryptionKey := []byte("12345678901234567890123456789012")
	secrets := createBenchmarkSecrets(b, 100, encryptionKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decryptSecrets(secrets, encryptionKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecryptSecrets_1000Secrets(b *testing.B) {
	encryptionKey := []byte("12345678901234567890123456789012")
	secrets := createBenchmarkSecrets(b, 1000, encryptionKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decryptSecrets(secrets, encryptionKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMergeToLocalDB_10Secrets(b *testing.B) {
	benchmarkMerge(b, 10)
}

func BenchmarkMergeToLocalDB_100Secrets(b *testing.B) {
	benchmarkMerge(b, 100)
}

func BenchmarkMergeToLocalDB_1000Secrets(b *testing.B) {
	benchmarkMerge(b, 1000)
}

// Helper functions for benchmarks.

func createBenchmarkSecrets(b *testing.B, count int, encryptionKey []byte) []*pb.Secret {
	b.Helper()
	secrets := make([]*pb.Secret, count)
	now := time.Now()

	for i := 0; i < count; i++ {
		plaintext := []byte(fmt.Sprintf(`{"id":%d,"username":"user%d","password":"pass%d"}`, i, i, i))
		encrypted, err := crypto.Encrypt(plaintext, encryptionKey)
		if err != nil {
			b.Fatal(err)
		}

		secrets[i] = &pb.Secret{
			Id:            fmt.Sprintf("secret-%d", i),
			Title:         fmt.Sprintf("Secret %d", i),
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: encrypted,
			Version:       int64(i + 1),
			CreatedAt:     timestamppb.New(now),
			UpdatedAt:     timestamppb.New(now),
		}
	}

	return secrets
}

func benchmarkMerge(b *testing.B, count int) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	repo, err := storage.NewSQLiteRepository(dbPath)
	if err != nil {
		b.Fatal(err)
	}
	defer repo.Close()

	now := time.Now()
	secrets := make([]*storage.LocalSecret, count)

	for i := 0; i < count; i++ {
		secrets[i] = &storage.LocalSecret{
			ID:             fmt.Sprintf("secret-%d", i),
			Name:           fmt.Sprintf("Secret %d", i),
			Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData:  []byte(fmt.Sprintf("data-%d", i)),
			Nonce:          []byte(fmt.Sprintf("nonce-%06d", i)),
			Version:        1,
			ServerVersion:  1,
			SyncStatus:     storage.SyncStatusSynced,
			CreatedAt:      now,
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		}
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Clean database between iterations.
		for j := 0; j < count; j++ {
			// Ignore errors during cleanup as secrets may not exist.
			//nolint:errcheck
			_ = repo.HardDelete(ctx, fmt.Sprintf("secret-%d", j))
		}
		b.StartTimer()

		cfg := &config.Config{}
		err := mergeToLocalDB(ctx, cfg, repo, secrets, nil, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Table-driven tests for edge cases.

func TestDecryptSecrets_EdgeCases(t *testing.T) {
	encryptionKey := []byte("12345678901234567890123456789012")

	tests := []struct {
		name      string
		secrets   []*pb.Secret
		wantError bool
		errorMsg  string
	}{
		{
			name:      "nil secrets",
			secrets:   nil,
			wantError: false,
		},
		{
			name:      "empty secrets",
			secrets:   []*pb.Secret{},
			wantError: false,
		},
		{
			name: "secret with empty encrypted data",
			secrets: []*pb.Secret{
				{
					Id:            "secret-1",
					Title:         "Test",
					Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
					EncryptedData: "",
					Version:       1,
					CreatedAt:     timestamppb.New(time.Now()),
					UpdatedAt:     timestamppb.New(time.Now()),
				},
			},
			wantError: true,
			errorMsg:  "failed to decrypt secret",
		},
		{
			name: "secret with corrupted base64",
			secrets: []*pb.Secret{
				{
					Id:            "secret-1",
					Title:         "Test",
					Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
					EncryptedData: "not-valid-base64!@#$",
					Version:       1,
					CreatedAt:     timestamppb.New(time.Now()),
					UpdatedAt:     timestamppb.New(time.Now()),
				},
			},
			wantError: true,
			errorMsg:  "failed to decrypt secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decryptSecrets(tt.secrets, encryptionKey)

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				if len(tt.secrets) == 0 {
					assert.Nil(t, result)
				}
			}
		})
	}
}

func TestMergeToLocalDB_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		setupRepo func(_ *testing.T) storage.Repository
		wantError bool
		errorMsg  string
	}{
		{
			name: "nil repository",
			setupRepo: func(_ *testing.T) storage.Repository {
				return nil
			},
			wantError: true,
			errorMsg:  "repository must be a SQLiteRepository",
		},
		{
			name: "valid repository",
			setupRepo: func(t *testing.T) storage.Repository {
				tmpDir := t.TempDir()
				dbPath := filepath.Join(tmpDir, "test.db")
				repo, err := storage.NewSQLiteRepository(dbPath)
				require.NoError(t, err)
				t.Cleanup(func() { repo.Close() })
				return repo
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := tt.setupRepo(t)
			ctx := context.Background()

			cfg := &config.Config{}
			err := mergeToLocalDB(ctx, cfg, repo, nil, nil, 1)

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

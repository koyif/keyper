package sync

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	pb "github.com/koy/keyper/pkg/api/proto"
)

// mockRepository implements the storage.Repository interface for testing
type mockPushRepository struct {
	pendingSecrets []*storage.LocalSecret
	syncUpdates    map[string]storage.SyncStatus
}

func (m *mockPushRepository) Create(ctx context.Context, secret *storage.LocalSecret) error {
	return nil
}

func (m *mockPushRepository) Get(ctx context.Context, id string) (*storage.LocalSecret, error) {
	return nil, storage.ErrSecretNotFound
}

func (m *mockPushRepository) GetByName(ctx context.Context, name string) (*storage.LocalSecret, error) {
	return nil, storage.ErrSecretNotFound
}

func (m *mockPushRepository) Update(ctx context.Context, secret *storage.LocalSecret) error {
	return nil
}

func (m *mockPushRepository) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *mockPushRepository) HardDelete(ctx context.Context, id string) error {
	return nil
}

func (m *mockPushRepository) List(ctx context.Context, filters storage.ListFilters) ([]*storage.LocalSecret, error) {
	return nil, nil
}

func (m *mockPushRepository) GetPendingSync(ctx context.Context) ([]*storage.LocalSecret, error) {
	return m.pendingSecrets, nil
}

func (m *mockPushRepository) UpdateSyncStatus(ctx context.Context, id string, status storage.SyncStatus, serverVersion int64) error {
	if m.syncUpdates == nil {
		m.syncUpdates = make(map[string]storage.SyncStatus)
	}
	m.syncUpdates[id] = status
	return nil
}

func (m *mockPushRepository) CreateConflict(ctx context.Context, conflict *storage.Conflict) error {
	return nil
}

func (m *mockPushRepository) GetUnresolvedConflicts(ctx context.Context) ([]*storage.Conflict, error) {
	return nil, nil
}

func (m *mockPushRepository) ResolveConflict(ctx context.Context, id int64, strategy string) error {
	return nil
}

func (m *mockPushRepository) Close() error {
	return nil
}

func TestConvertToProtoSecret(t *testing.T) {
	tests := []struct {
		name      string
		input     *storage.LocalSecret
		wantError bool
	}{
		{
			name: "valid secret without metadata",
			input: &storage.LocalSecret{
				ID:            "test-id-1",
				Name:          "Test Secret",
				Type:          pb.SecretType_SECRET_TYPE_TEXT,
				EncryptedData: []byte("encrypted-data"),
				Nonce:         []byte("nonce"),
				Version:       1,
				IsDeleted:     false,
				SyncStatus:    storage.SyncStatusPending,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			wantError: false,
		},
		{
			name: "valid secret with metadata",
			input: &storage.LocalSecret{
				ID:            "test-id-2",
				Name:          "Test Secret 2",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				EncryptedData: []byte("encrypted-data-2"),
				Nonce:         []byte("nonce-2"),
				Metadata:      `{"tags":["test"],"category":"work","favorite":true}`,
				Version:       2,
				IsDeleted:     false,
				SyncStatus:    storage.SyncStatusPending,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			wantError: false,
		},
		{
			name: "deleted secret",
			input: &storage.LocalSecret{
				ID:            "test-id-3",
				Name:          "Deleted Secret",
				Type:          pb.SecretType_SECRET_TYPE_TEXT,
				EncryptedData: []byte("encrypted-data-3"),
				Nonce:         []byte("nonce-3"),
				Version:       3,
				IsDeleted:     true,
				SyncStatus:    storage.SyncStatusPending,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			wantError: false,
		},
		{
			name: "invalid metadata JSON",
			input: &storage.LocalSecret{
				ID:            "test-id-4",
				Name:          "Invalid Metadata",
				Type:          pb.SecretType_SECRET_TYPE_TEXT,
				EncryptedData: []byte("encrypted-data-4"),
				Nonce:         []byte("nonce-4"),
				Metadata:      `{invalid json}`,
				Version:       1,
				IsDeleted:     false,
				SyncStatus:    storage.SyncStatusPending,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := convertToProtoSecret(tt.input)

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Id != tt.input.ID {
				t.Errorf("ID mismatch: got %s, want %s", result.Id, tt.input.ID)
			}

			if result.Title != tt.input.Name {
				t.Errorf("Title mismatch: got %s, want %s", result.Title, tt.input.Name)
			}

			if result.Type != tt.input.Type {
				t.Errorf("Type mismatch: got %v, want %v", result.Type, tt.input.Type)
			}

			// Verify encrypted data is base64 encoded
			decoded, err := base64.StdEncoding.DecodeString(result.EncryptedData)
			if err != nil {
				t.Errorf("Failed to decode encrypted data: %v", err)
			}
			if string(decoded) != string(tt.input.EncryptedData) {
				t.Errorf("Encrypted data mismatch: got %s, want %s", decoded, tt.input.EncryptedData)
			}

			if result.Version != tt.input.Version {
				t.Errorf("Version mismatch: got %d, want %d", result.Version, tt.input.Version)
			}

			if result.IsDeleted != tt.input.IsDeleted {
				t.Errorf("IsDeleted mismatch: got %v, want %v", result.IsDeleted, tt.input.IsDeleted)
			}
		})
	}
}

func TestUpdateSyncStatusAfterPush(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		acceptedIDs []string
		newVersion  int64
	}{
		{
			name:        "single secret",
			acceptedIDs: []string{"test-id-1"},
			newVersion:  10,
		},
		{
			name:        "multiple secrets",
			acceptedIDs: []string{"test-id-1", "test-id-2", "test-id-3"},
			newVersion:  20,
		},
		{
			name:        "no secrets",
			acceptedIDs: []string{},
			newVersion:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockPushRepository{
				syncUpdates: make(map[string]storage.SyncStatus),
			}

			err := updateSyncStatusAfterPush(ctx, repo, tt.acceptedIDs, tt.newVersion)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify all IDs were updated
			for _, id := range tt.acceptedIDs {
				status, ok := repo.syncUpdates[id]
				if !ok {
					t.Errorf("ID %s was not updated", id)
					continue
				}
				if status != storage.SyncStatusSynced {
					t.Errorf("ID %s has wrong status: got %s, want %s", id, status, storage.SyncStatusSynced)
				}
			}

			if len(repo.syncUpdates) != len(tt.acceptedIDs) {
				t.Errorf("Wrong number of updates: got %d, want %d", len(repo.syncUpdates), len(tt.acceptedIDs))
			}
		})
	}
}

func TestPushNoPendingSecrets(t *testing.T) {
	ctx := context.Background()

	// Setup
	cfg := &config.Config{
		Server:   "localhost:50051",
		DeviceID: "test-device-id",
	}

	sess := &session.Session{}
	sess.UpdateTokens("access-token", "refresh-token", time.Now().Add(time.Hour))

	repo := &mockPushRepository{
		pendingSecrets: []*storage.LocalSecret{}, // No pending secrets
	}

	// This test will fail to connect to server, but we're testing the early return path
	// We can't easily test the full flow without a mock gRPC server
	// So we just verify the logic works with no pending secrets
	result, err := Push(ctx, cfg, sess, repo)

	// Should not error due to empty pending list
	if err != nil {
		t.Fatalf("Unexpected error with no pending secrets: %v", err)
	}

	if result.Message != "No changes to push" {
		t.Errorf("Expected 'No changes to push', got %s", result.Message)
	}

	if len(result.AcceptedSecretIDs) != 0 {
		t.Errorf("Expected 0 accepted secrets, got %d", len(result.AcceptedSecretIDs))
	}
}

func TestPushSeparatesDeletedSecrets(t *testing.T) {
	// This test verifies the logic for separating deleted vs non-deleted secrets
	// We can't test the full Push function without a mock gRPC server,
	// but we can verify the conversion logic

	pendingSecrets := []*storage.LocalSecret{
		{
			ID:            "test-id-1",
			Name:          "Active Secret",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: []byte("encrypted-1"),
			IsDeleted:     false,
			SyncStatus:    storage.SyncStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
		{
			ID:            "test-id-2",
			Name:          "Deleted Secret",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: []byte("encrypted-2"),
			IsDeleted:     true,
			SyncStatus:    storage.SyncStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
		{
			ID:            "test-id-3",
			Name:          "Another Active Secret",
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: []byte("encrypted-3"),
			IsDeleted:     false,
			SyncStatus:    storage.SyncStatusPending,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		},
	}

	var secretsToSend []*pb.Secret
	var deletedIDs []string

	for _, local := range pendingSecrets {
		if local.IsDeleted {
			deletedIDs = append(deletedIDs, local.ID)
		} else {
			protoSecret, err := convertToProtoSecret(local)
			if err != nil {
				t.Fatalf("Failed to convert secret: %v", err)
			}
			secretsToSend = append(secretsToSend, protoSecret)
		}
	}

	// Verify separation
	if len(deletedIDs) != 1 {
		t.Errorf("Expected 1 deleted secret, got %d", len(deletedIDs))
	}

	if len(secretsToSend) != 2 {
		t.Errorf("Expected 2 active secrets, got %d", len(secretsToSend))
	}

	if deletedIDs[0] != "test-id-2" {
		t.Errorf("Expected deleted ID 'test-id-2', got %s", deletedIDs[0])
	}
}

func TestPushResultPartialSuccess(t *testing.T) {
	// Test the logic for determining partial success

	allSecrets := []string{"id-1", "id-2", "id-3", "id-4"}
	acceptedIDs := []string{"id-1", "id-3"}

	acceptedSet := make(map[string]bool)
	for _, id := range acceptedIDs {
		acceptedSet[id] = true
	}

	var failedIDs []string
	for _, id := range allSecrets {
		if !acceptedSet[id] {
			failedIDs = append(failedIDs, id)
		}
	}

	if len(failedIDs) != 2 {
		t.Errorf("Expected 2 failed IDs, got %d", len(failedIDs))
	}

	expectedFailed := map[string]bool{"id-2": true, "id-4": true}
	for _, id := range failedIDs {
		if !expectedFailed[id] {
			t.Errorf("Unexpected failed ID: %s", id)
		}
	}
}

func TestConvertToProtoSecretTimestamps(t *testing.T) {
	// Test that timestamps are correctly converted

	createdAt := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
	updatedAt := time.Date(2024, 1, 16, 14, 45, 0, 0, time.UTC)

	input := &storage.LocalSecret{
		ID:            "test-id",
		Name:          "Test Secret",
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("encrypted"),
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}

	result, err := convertToProtoSecret(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.CreatedAt.AsTime().Equal(createdAt) {
		t.Errorf("CreatedAt mismatch: got %v, want %v", result.CreatedAt.AsTime(), createdAt)
	}

	if !result.UpdatedAt.AsTime().Equal(updatedAt) {
		t.Errorf("UpdatedAt mismatch: got %v, want %v", result.UpdatedAt.AsTime(), updatedAt)
	}
}

func TestPushResultStructure(t *testing.T) {
	// Test PushResult structure

	now := time.Now()
	result := &PushResult{
		NewVersion:        100,
		SyncTime:          now,
		AcceptedSecretIDs: []string{"id-1", "id-2"},
		Conflicts: []*pb.Conflict{
			{
				SecretId: "conflict-id",
				Type:     pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
			},
		},
		Message:         "Push completed",
		PartialSuccess:  true,
		FailedSecretIDs: []string{"id-3"},
	}

	if result.NewVersion != 100 {
		t.Errorf("NewVersion mismatch: got %d, want 100", result.NewVersion)
	}

	if !result.SyncTime.Equal(now) {
		t.Errorf("SyncTime mismatch: got %v, want %v", result.SyncTime, now)
	}

	if len(result.AcceptedSecretIDs) != 2 {
		t.Errorf("AcceptedSecretIDs count mismatch: got %d, want 2", len(result.AcceptedSecretIDs))
	}

	if len(result.Conflicts) != 1 {
		t.Errorf("Conflicts count mismatch: got %d, want 1", len(result.Conflicts))
	}

	if !result.PartialSuccess {
		t.Error("Expected PartialSuccess to be true")
	}

	if len(result.FailedSecretIDs) != 1 {
		t.Errorf("FailedSecretIDs count mismatch: got %d, want 1", len(result.FailedSecretIDs))
	}

	if result.Message != "Push completed" {
		t.Errorf("Message mismatch: got %s, want 'Push completed'", result.Message)
	}
}

// Note: Full integration tests for PushWithRetry require a mock gRPC server
// which is complex to set up. The tests below verify the basic structure
// and logic, but real-world testing should include end-to-end scenarios.

func TestPushWithRetryNoPendingSecrets(t *testing.T) {
	// Test that PushWithRetry works when there are no pending secrets
	ctx := context.Background()

	cfg := &config.Config{
		Server:   "localhost:50051",
		DeviceID: "test-device-id",
	}

	sess := &session.Session{}
	sess.UpdateTokens("access-token", "refresh-token", time.Now().Add(time.Hour))

	repo := &mockPushRepository{
		pendingSecrets: []*storage.LocalSecret{}, // No pending secrets
	}

	result, err := PushWithRetry(ctx, cfg, sess, repo)

	// Should not error due to empty pending list
	if err != nil {
		t.Fatalf("Unexpected error with no pending secrets: %v", err)
	}

	if result.Message != "No changes to push" {
		t.Errorf("Expected 'No changes to push', got %s", result.Message)
	}
}

func TestPushWithRetryStructure(t *testing.T) {
	// This test verifies that PushWithRetry function exists and has the right signature
	// We can't easily test the full retry logic without mocking the gRPC server and PullAndSync

	ctx := context.Background()
	cfg := &config.Config{
		Server:   "localhost:50051",
		DeviceID: "test-device-id",
	}

	sess := &session.Session{}
	sess.UpdateTokens("access-token", "refresh-token", time.Now().Add(time.Hour))

	repo := &mockPushRepository{
		pendingSecrets: []*storage.LocalSecret{},
	}

	// Just verify the function can be called
	result, err := PushWithRetry(ctx, cfg, sess, repo)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

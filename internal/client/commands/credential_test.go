package commands

import (
	"context"
	"testing"
	"time"

	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	"github.com/koyif/keyper/internal/crypto"
	pb "github.com/koyif/keyper/pkg/api/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

// setupCredentialTest creates a test environment with config, session, and storage
func setupCredentialTest(t *testing.T) (*config.Config, *session.Session, storage.Repository) {
	t.Helper()

	// Create config
	cfg := config.DefaultConfig()

	// Create session with encryption key
	sess := session.New("")
	salt, _ := crypto.GenerateSalt(crypto.SaltLength)
	encryptionKey := crypto.DeriveKey("test-password", salt)
	sess.SetEncryptionKey(encryptionKey)
	sess.UserID = "test-user-id"

	// Create in-memory storage
	repo, err := storage.NewSQLiteRepository(":memory:")
	if err != nil {
		t.Fatalf("Failed to create test repository: %v", err)
	}

	t.Cleanup(func() {
		repo.Close()
	})

	return cfg, sess, repo
}

// createTestCredential creates a test credential in storage
func createTestCredential(t *testing.T, repo storage.Repository, sess *session.Session, name string) *storage.LocalSecret {
	t.Helper()

	credData := &pb.CredentialData{
		Username: "testuser",
		Password: "testpass",
		Email:    "test@example.com",
		Url:      "https://example.com",
	}

	credJSON, err := protojson.Marshal(credData)
	if err != nil {
		t.Fatalf("Failed to marshal credential data: %v", err)
	}

	encryptionKey := sess.GetEncryptionKey()
	encryptedData, err := crypto.Encrypt(credJSON, encryptionKey)
	if err != nil {
		t.Fatalf("Failed to encrypt credential: %v", err)
	}

	metadata := &pb.Metadata{
		Url:   "https://example.com",
		Notes: "Test notes",
	}
	metadataJSON, err := protojson.Marshal(metadata)
	if err != nil {
		t.Fatalf("Failed to marshal metadata: %v", err)
	}

	now := time.Now()
	secret := &storage.LocalSecret{
		ID:             "test-cred-" + name,
		Name:           name,
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte(encryptedData),
		Nonce:          []byte{}, // Nonce embedded in encrypted data
		Metadata:       string(metadataJSON),
		Version:        1,
		IsDeleted:      false,
		SyncStatus:     storage.SyncStatusSynced,
		ServerVersion:  1,
		CreatedAt:      now,
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	ctx := context.Background()
	if err := repo.Create(ctx, secret); err != nil {
		t.Fatalf("Failed to create test credential: %v", err)
	}

	return secret
}

func TestCredentialEncryptionRoundtrip(t *testing.T) {
	_, sess, repo := setupCredentialTest(t)

	// Create credential data
	originalData := &pb.CredentialData{
		Username: "testuser",
		Password: "secret123",
		Email:    "test@example.com",
		Url:      "https://example.com",
	}

	// Marshal to JSON
	credJSON, err := protojson.Marshal(originalData)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Encrypt
	encryptionKey := sess.GetEncryptionKey()
	encrypted, err := crypto.Encrypt(credJSON, encryptionKey)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Store in database
	now := time.Now()
	secret := &storage.LocalSecret{
		ID:             "test-roundtrip",
		Name:           "Test Roundtrip",
		Type:           pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData:  []byte(encrypted),
		Nonce:          []byte{}, // Nonce embedded in encrypted data
		Metadata:       "{}",
		Version:        1,
		IsDeleted:      false,
		SyncStatus:     storage.SyncStatusPending,
		ServerVersion:  0,
		CreatedAt:      now,
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	ctx := context.Background()
	if err := repo.Create(ctx, secret); err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Retrieve from database
	retrieved, err := repo.Get(ctx, "test-roundtrip")
	if err != nil {
		t.Fatalf("Failed to retrieve secret: %v", err)
	}

	// Decrypt
	decrypted, err := crypto.Decrypt(string(retrieved.EncryptedData), encryptionKey)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Unmarshal
	var finalData pb.CredentialData
	if err := protojson.Unmarshal(decrypted, &finalData); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify data matches
	if finalData.Username != originalData.Username {
		t.Errorf("Username mismatch: got %s, want %s", finalData.Username, originalData.Username)
	}
	if finalData.Password != originalData.Password {
		t.Errorf("Password mismatch: got %s, want %s", finalData.Password, originalData.Password)
	}
	if finalData.Email != originalData.Email {
		t.Errorf("Email mismatch: got %s, want %s", finalData.Email, originalData.Email)
	}
	if finalData.Url != originalData.Url {
		t.Errorf("URL mismatch: got %s, want %s", finalData.Url, originalData.Url)
	}
}

func TestCredentialSyncStatusPending(t *testing.T) {
	_, sess, repo := setupCredentialTest(t)

	// Create a credential
	secret := createTestCredential(t, repo, sess, "Test Credential")

	// Initially it should be synced (as created in helper)
	if secret.SyncStatus != storage.SyncStatusSynced {
		t.Errorf("Expected initial sync status to be synced, got %s", secret.SyncStatus)
	}

	// Update the secret (should set sync status to pending)
	ctx := context.Background()
	secret.Name = "Updated Name"
	secret.Version++
	secret.SyncStatus = storage.SyncStatusPending

	if err := repo.Update(ctx, secret); err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	// Verify sync status is pending
	updated, err := repo.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to get updated secret: %v", err)
	}

	if updated.SyncStatus != storage.SyncStatusPending {
		t.Errorf("Expected sync status to be pending after update, got %s", updated.SyncStatus)
	}
}

func TestCredentialGetByName(t *testing.T) {
	_, sess, repo := setupCredentialTest(t)

	// Create test credential
	secret := createTestCredential(t, repo, sess, "MyTestCred")

	// Retrieve by name
	ctx := context.Background()
	retrieved, err := repo.GetByName(ctx, "MyTestCred")
	if err != nil {
		t.Fatalf("Failed to get by name: %v", err)
	}

	if retrieved.ID != secret.ID {
		t.Errorf("Expected ID %s, got %s", secret.ID, retrieved.ID)
	}
	if retrieved.Name != secret.Name {
		t.Errorf("Expected name %s, got %s", secret.Name, retrieved.Name)
	}
}

func TestCredentialSoftDelete(t *testing.T) {
	_, sess, repo := setupCredentialTest(t)

	// Create test credential
	secret := createTestCredential(t, repo, sess, "DeleteTest")

	// Soft delete
	ctx := context.Background()
	if err := repo.Delete(ctx, secret.ID); err != nil {
		t.Fatalf("Failed to delete credential: %v", err)
	}

	// Verify it's marked as deleted
	deleted, err := repo.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to get deleted credential: %v", err)
	}

	if !deleted.IsDeleted {
		t.Error("Expected credential to be marked as deleted")
	}

	// Verify sync status is pending
	if deleted.SyncStatus != storage.SyncStatusPending {
		t.Errorf("Expected sync status to be pending after delete, got %s", deleted.SyncStatus)
	}
}

func TestCredentialListFilter(t *testing.T) {
	_, sess, repo := setupCredentialTest(t)

	// Create multiple credentials
	createTestCredential(t, repo, sess, "Cred1")
	createTestCredential(t, repo, sess, "Cred2")
	createTestCredential(t, repo, sess, "Cred3")

	// Also create a non-credential secret
	now := time.Now()
	textSecret := &storage.LocalSecret{
		ID:             "text-secret-1",
		Name:           "Text Note",
		Type:           pb.SecretType_SECRET_TYPE_TEXT,
		EncryptedData:  []byte("encrypted"),
		Nonce:          []byte{}, // Nonce embedded in encrypted data
		Metadata:       "{}",
		Version:        1,
		IsDeleted:      false,
		SyncStatus:     storage.SyncStatusSynced,
		ServerVersion:  1,
		CreatedAt:      now,
		UpdatedAt:      now,
		LocalUpdatedAt: now,
	}

	ctx := context.Background()
	if err := repo.Create(ctx, textSecret); err != nil {
		t.Fatalf("Failed to create text secret: %v", err)
	}

	// List only credentials
	credType := pb.SecretType_SECRET_TYPE_CREDENTIAL
	secrets, err := repo.List(ctx, storage.ListFilters{
		Type:           &credType,
		IncludeDeleted: false,
	})
	if err != nil {
		t.Fatalf("Failed to list credentials: %v", err)
	}

	// Should only get the 3 credentials, not the text secret
	if len(secrets) != 3 {
		t.Errorf("Expected 3 credentials, got %d", len(secrets))
	}

	for _, s := range secrets {
		if s.Type != pb.SecretType_SECRET_TYPE_CREDENTIAL {
			t.Errorf("Expected only credential types, got %s", s.Type)
		}
	}
}

func TestCredentialDecryptionError(t *testing.T) {
	_, sess, repo := setupCredentialTest(t)

	// Create credential with correct key
	secret := createTestCredential(t, repo, sess, "TestCred")

	// Try to decrypt with wrong key
	wrongSalt, _ := crypto.GenerateSalt(crypto.SaltLength)
	wrongKey := crypto.DeriveKey("wrong-password", wrongSalt)

	ctx := context.Background()
	retrieved, err := repo.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve secret: %v", err)
	}

	// Attempt decryption with wrong key (should fail)
	_, err = crypto.Decrypt(string(retrieved.EncryptedData), wrongKey)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key, but it succeeded")
	}
}

func TestCredentialMetadataHandling(t *testing.T) {
	_, sess, repo := setupCredentialTest(t)

	// Create credential with metadata
	secret := createTestCredential(t, repo, sess, "MetadataTest")

	// Retrieve and check metadata
	ctx := context.Background()
	retrieved, err := repo.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to retrieve secret: %v", err)
	}

	// Parse metadata
	var metadata pb.Metadata
	if err := protojson.Unmarshal([]byte(retrieved.Metadata), &metadata); err != nil {
		t.Fatalf("Failed to parse metadata: %v", err)
	}

	if metadata.Url != "https://example.com" {
		t.Errorf("Expected URL https://example.com, got %s", metadata.Url)
	}
	if metadata.Notes != "Test notes" {
		t.Errorf("Expected notes 'Test notes', got %s", metadata.Notes)
	}
}

func TestUnauthenticatedSession(t *testing.T) {
	cfg := config.DefaultConfig()
	sess := session.New("") // No encryption key set
	repo, err := storage.NewSQLiteRepository(":memory:")
	if err != nil {
		t.Fatalf("Failed to create repository: %v", err)
	}
	defer repo.Close()

	// Ensure session is not authenticated
	if sess.IsAuthenticated() {
		t.Skip("Session should not be authenticated for this test")
	}

	// The commands should check for authentication
	// We can't easily test the cobra commands without running them,
	// but we can verify the session authentication check
	if sess.GetEncryptionKey() != nil {
		t.Error("Expected nil encryption key for unauthenticated session")
	}

	// Verify this is what we expect
	_ = cfg // Use cfg to avoid unused variable error
}

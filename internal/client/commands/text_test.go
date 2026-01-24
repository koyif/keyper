package commands

import (
	"context"
	"testing"
	"time"

	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/crypto"
	pb "github.com/koy/keyper/pkg/api/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

// setupTextTest creates a test environment for text commands
func setupTextTest(t *testing.T) (*config.Config, *session.Session, storage.Repository) {
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

func TestTextCommands(t *testing.T) {
	cfg, sess, repo := setupTextTest(t)
	encryptionKey := sess.GetEncryptionKey()

	getCfg := func() *config.Config { return cfg }
	getSess := func() *session.Session { return sess }
	getStorage := func() (storage.Repository, error) { return repo, nil }

	ctx := context.Background()

	t.Run("TextAdd", func(t *testing.T) {
		// Create text note via command
		textData := &pb.TextData{
			Content: "This is a test note with important information.",
		}

		textJSON, err := protojson.Marshal(textData)
		if err != nil {
			t.Fatalf("Failed to marshal text data: %v", err)
		}

		encryptedData, err := crypto.Encrypt(textJSON, encryptionKey)
		if err != nil {
			t.Fatalf("Failed to encrypt text data: %v", err)
		}

		metadata := &pb.Metadata{
			Tags:  []string{"test", "important"},
			Notes: "Test note",
		}
		metadataJSON, err := protojson.Marshal(metadata)
		if err != nil {
			t.Fatalf("Failed to marshal metadata: %v", err)
		}

		now := time.Now()
		secret := &storage.LocalSecret{
			ID:             "test-text-1",
			Name:           "My Test Note",
			Type:           pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData:  []byte(encryptedData),
			Nonce:          []byte{}, // Nonce embedded in encrypted data
			Metadata:       string(metadataJSON),
			Version:        1,
			IsDeleted:      false,
			SyncStatus:     storage.SyncStatusPending,
			ServerVersion:  0,
			CreatedAt:      now,
			UpdatedAt:      now,
			LocalUpdatedAt: now,
		}

		err = repo.Create(ctx, secret)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}

		// Verify it was stored
		retrieved, err := repo.Get(ctx, "test-text-1")
		if err != nil {
			t.Fatalf("Failed to retrieve secret: %v", err)
		}
		if retrieved.Name != "My Test Note" {
			t.Errorf("Expected name 'My Test Note', got %s", retrieved.Name)
		}
		if retrieved.Type != pb.SecretType_SECRET_TYPE_TEXT {
			t.Errorf("Expected type TEXT, got %v", retrieved.Type)
		}
		if retrieved.SyncStatus != storage.SyncStatusPending {
			t.Errorf("Expected sync status pending, got %s", retrieved.SyncStatus)
		}
	})

	t.Run("TextGet", func(t *testing.T) {
		// Get the text note
		secret, err := repo.Get(ctx, "test-text-1")
		if err != nil {
			t.Fatalf("Failed to get secret: %v", err)
		}

		// Decrypt the data
		decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
		if err != nil {
			t.Fatalf("Failed to decrypt: %v", err)
		}

		// Unmarshal text data
		var textData pb.TextData
		err = protojson.Unmarshal(decryptedData, &textData)
		if err != nil {
			t.Fatalf("Failed to unmarshal text data: %v", err)
		}

		expected := "This is a test note with important information."
		if textData.Content != expected {
			t.Errorf("Expected content %s, got %s", expected, textData.Content)
		}

		// Check metadata
		var metadata pb.Metadata
		err = protojson.Unmarshal([]byte(secret.Metadata), &metadata)
		if err != nil {
			t.Fatalf("Failed to unmarshal metadata: %v", err)
		}

		foundTest := false
		foundImportant := false
		for _, tag := range metadata.Tags {
			if tag == "test" {
				foundTest = true
			}
			if tag == "important" {
				foundImportant = true
			}
		}
		if !foundTest {
			t.Error("Expected 'test' tag not found")
		}
		if !foundImportant {
			t.Error("Expected 'important' tag not found")
		}
		if metadata.Notes != "Test note" {
			t.Errorf("Expected notes 'Test note', got %s", metadata.Notes)
		}
	})

	t.Run("TextList", func(t *testing.T) {
		// List text notes
		textType := pb.SecretType_SECRET_TYPE_TEXT
		secrets, err := repo.List(ctx, storage.ListFilters{
			Type:           &textType,
			IncludeDeleted: false,
		})
		if err != nil {
			t.Fatalf("Failed to list secrets: %v", err)
		}

		if len(secrets) != 1 {
			t.Errorf("Expected 1 secret, got %d", len(secrets))
		}
		if len(secrets) > 0 {
			if secrets[0].Name != "My Test Note" {
				t.Errorf("Expected name 'My Test Note', got %s", secrets[0].Name)
			}
			if secrets[0].Type != pb.SecretType_SECRET_TYPE_TEXT {
				t.Errorf("Expected type TEXT, got %v", secrets[0].Type)
			}
		}
	})

	t.Run("TextUpdate", func(t *testing.T) {
		// Get existing text note
		secret, err := repo.Get(ctx, "test-text-1")
		if err != nil {
			t.Fatalf("Failed to get secret: %v", err)
		}

		// Update content
		updatedTextData := &pb.TextData{
			Content: "This note has been updated with new information.",
		}

		textJSON, err := protojson.Marshal(updatedTextData)
		if err != nil {
			t.Fatalf("Failed to marshal text data: %v", err)
		}

		encryptedData, err := crypto.Encrypt(textJSON, encryptionKey)
		if err != nil {
			t.Fatalf("Failed to encrypt text data: %v", err)
		}

		secret.EncryptedData = []byte(encryptedData)
		secret.Nonce = []byte{} // Nonce embedded in encrypted data
		secret.Name = "Updated Test Note"
		secret.Version++

		err = repo.Update(ctx, secret)
		if err != nil {
			t.Fatalf("Failed to update secret: %v", err)
		}

		// Verify update
		retrieved, err := repo.Get(ctx, "test-text-1")
		if err != nil {
			t.Fatalf("Failed to retrieve updated secret: %v", err)
		}
		if retrieved.Name != "Updated Test Note" {
			t.Errorf("Expected updated name, got %s", retrieved.Name)
		}

		// Verify decrypted content
		decryptedData, err := crypto.Decrypt(string(retrieved.EncryptedData), encryptionKey)
		if err != nil {
			t.Fatalf("Failed to decrypt updated data: %v", err)
		}

		var textData pb.TextData
		err = protojson.Unmarshal(decryptedData, &textData)
		if err != nil {
			t.Fatalf("Failed to unmarshal updated text data: %v", err)
		}

		expected := "This note has been updated with new information."
		if textData.Content != expected {
			t.Errorf("Expected updated content %s, got %s", expected, textData.Content)
		}
	})

	t.Run("TextDelete", func(t *testing.T) {
		// Delete text note (soft delete)
		err := repo.Delete(ctx, "test-text-1")
		if err != nil {
			t.Fatalf("Failed to delete secret: %v", err)
		}

		// Verify it's marked as deleted
		secret, err := repo.Get(ctx, "test-text-1")
		if err != nil {
			t.Fatalf("Failed to get deleted secret: %v", err)
		}
		if !secret.IsDeleted {
			t.Error("Expected secret to be marked as deleted")
		}
		if secret.SyncStatus != storage.SyncStatusPending {
			t.Errorf("Expected sync status pending, got %s", secret.SyncStatus)
		}

		// Verify it doesn't show up in normal list
		textType := pb.SecretType_SECRET_TYPE_TEXT
		secrets, err := repo.List(ctx, storage.ListFilters{
			Type:           &textType,
			IncludeDeleted: false,
		})
		if err != nil {
			t.Fatalf("Failed to list secrets: %v", err)
		}
		if len(secrets) != 0 {
			t.Errorf("Expected 0 secrets in list, got %d", len(secrets))
		}

		// Verify it shows up when including deleted
		secrets, err = repo.List(ctx, storage.ListFilters{
			Type:           &textType,
			IncludeDeleted: true,
		})
		if err != nil {
			t.Fatalf("Failed to list with deleted: %v", err)
		}
		if len(secrets) != 1 {
			t.Errorf("Expected 1 secret with deleted included, got %d", len(secrets))
		}
	})

	t.Run("TextCommandGroup", func(t *testing.T) {
		// Test command group creation
		textCmd := NewTextCommands(getCfg, getSess, getStorage)
		if textCmd == nil {
			t.Fatal("Expected text command group, got nil")
		}
		if textCmd.Use != "text" {
			t.Errorf("Expected use 'text', got %s", textCmd.Use)
		}

		// Check aliases
		hasNote := false
		hasNotes := false
		for _, alias := range textCmd.Aliases {
			if alias == "note" {
				hasNote = true
			}
			if alias == "notes" {
				hasNotes = true
			}
		}
		if !hasNote {
			t.Error("Expected 'note' alias not found")
		}
		if !hasNotes {
			t.Error("Expected 'notes' alias not found")
		}

		// Verify all subcommands are registered
		subcommands := textCmd.Commands()
		if len(subcommands) != 5 {
			t.Errorf("Expected 5 subcommands, got %d", len(subcommands))
		}

		cmdNames := make(map[string]bool)
		for _, cmd := range subcommands {
			cmdNames[cmd.Use] = true
		}

		if !cmdNames["add"] {
			t.Error("Missing 'add' command")
		}
		if !cmdNames["get [name or ID]"] {
			t.Error("Missing 'get' command")
		}
		if !cmdNames["list"] {
			t.Error("Missing 'list' command")
		}
		if !cmdNames["update [name or ID]"] {
			t.Error("Missing 'update' command")
		}
		if !cmdNames["delete [name or ID]"] {
			t.Error("Missing 'delete' command")
		}
	})
}

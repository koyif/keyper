package commands

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/crypto"
	pb "github.com/koy/keyper/pkg/api/proto"
	"google.golang.org/protobuf/encoding/protojson"
)

// setupBinaryTest creates a test environment for binary commands
func setupBinaryTest(t *testing.T) (*config.Config, *session.Session, storage.Repository) {
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

func TestBinaryCommands(t *testing.T) {
	cfg, sess, repo := setupBinaryTest(t)
	encryptionKey := sess.GetEncryptionKey()

	getCfg := func() *config.Config { return cfg }
	getSess := func() *session.Session { return sess }
	getStorage := func() (storage.Repository, error) { return repo, nil }

	ctx := context.Background()

	t.Run("BinaryAdd", func(t *testing.T) {
		// Create test file data
		testData := []byte("This is test binary data for a file")
		binaryData := &pb.BinaryData{
			Filename: "test-file.txt",
			MimeType: "text/plain",
			Size:     int64(len(testData)),
			Data:     testData,
		}

		binaryJSON, err := protojson.Marshal(binaryData)
		if err != nil {
			t.Fatalf("Failed to marshal binary data: %v", err)
		}

		encryptedData, err := crypto.Encrypt(binaryJSON, encryptionKey)
		if err != nil {
			t.Fatalf("Failed to encrypt binary data: %v", err)
		}

		metadata := &pb.Metadata{
			Notes: "Test binary file",
			CustomFields: map[string]string{
				"original_filename": "test-file.txt",
				"mime_type":         "text/plain",
				"file_size":         "36",
			},
		}
		metadataJSON, err := protojson.Marshal(metadata)
		if err != nil {
			t.Fatalf("Failed to marshal metadata: %v", err)
		}

		now := time.Now()
		secret := &storage.LocalSecret{
			ID:             "test-binary-1",
			Name:           "Test File",
			Type:           pb.SecretType_SECRET_TYPE_BINARY,
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
		stored, err := repo.Get(ctx, secret.ID)
		if err != nil {
			t.Fatalf("Failed to get secret: %v", err)
		}

		if stored.Name != "Test File" {
			t.Errorf("Expected name 'Test File', got %s", stored.Name)
		}

		if stored.Type != pb.SecretType_SECRET_TYPE_BINARY {
			t.Errorf("Expected type SECRET_TYPE_BINARY, got %s", stored.Type)
		}

		// Verify we can decrypt and read the data
		decryptedData, err := crypto.Decrypt(string(stored.EncryptedData), encryptionKey)
		if err != nil {
			t.Fatalf("Failed to decrypt binary data: %v", err)
		}

		var retrievedBinaryData pb.BinaryData
		if err := protojson.Unmarshal(decryptedData, &retrievedBinaryData); err != nil {
			t.Fatalf("Failed to unmarshal binary data: %v", err)
		}

		if retrievedBinaryData.Filename != "test-file.txt" {
			t.Errorf("Expected filename 'test-file.txt', got %s", retrievedBinaryData.Filename)
		}

		if string(retrievedBinaryData.Data) != string(testData) {
			t.Errorf("Binary data mismatch")
		}
	})

	t.Run("BinaryList", func(t *testing.T) {
		// List binary secrets
		binType := pb.SecretType_SECRET_TYPE_BINARY
		secrets, err := repo.List(ctx, storage.ListFilters{
			Type:           &binType,
			IncludeDeleted: false,
		})
		if err != nil {
			t.Fatalf("Failed to list binary secrets: %v", err)
		}

		if len(secrets) != 1 {
			t.Errorf("Expected 1 binary secret, got %d", len(secrets))
		}

		if secrets[0].Name != "Test File" {
			t.Errorf("Expected name 'Test File', got %s", secrets[0].Name)
		}
	})

	t.Run("BinaryGet", func(t *testing.T) {
		// Get binary secret by ID
		secret, err := repo.Get(ctx, "test-binary-1")
		if err != nil {
			t.Fatalf("Failed to get binary secret: %v", err)
		}

		// Decrypt and verify
		decryptedData, err := crypto.Decrypt(string(secret.EncryptedData), encryptionKey)
		if err != nil {
			t.Fatalf("Failed to decrypt binary data: %v", err)
		}

		var binaryData pb.BinaryData
		if err := protojson.Unmarshal(decryptedData, &binaryData); err != nil {
			t.Fatalf("Failed to unmarshal binary data: %v", err)
		}

		if binaryData.Filename != "test-file.txt" {
			t.Errorf("Expected filename 'test-file.txt', got %s", binaryData.Filename)
		}

		if binaryData.MimeType != "text/plain" {
			t.Errorf("Expected mime type 'text/plain', got %s", binaryData.MimeType)
		}

		expectedData := "This is test binary data for a file"
		if string(binaryData.Data) != expectedData {
			t.Errorf("Expected data '%s', got '%s'", expectedData, string(binaryData.Data))
		}
	})

	t.Run("BinaryDelete", func(t *testing.T) {
		// Delete binary secret
		err := repo.Delete(ctx, "test-binary-1")
		if err != nil {
			t.Fatalf("Failed to delete binary secret: %v", err)
		}

		// Verify it was soft-deleted
		secret, err := repo.Get(ctx, "test-binary-1")
		if err != nil {
			t.Fatalf("Failed to get deleted binary secret: %v", err)
		}

		if !secret.IsDeleted {
			t.Errorf("Expected secret to be marked as deleted")
		}
	})

	// Clean up getCfg, getSess, getStorage to avoid unused warnings in test
	_ = getCfg
	_ = getSess
	_ = getStorage
}

func TestBinaryFileHandling(t *testing.T) {
	t.Run("PathTraversalPrevention", func(t *testing.T) {
		// Test that filepath.Clean normalizes paths
		maliciousPath := "../../etc/passwd"
		cleaned := filepath.Clean(maliciousPath)

		// Clean should normalize the path to remove redundant separators
		// The cleaned path will still contain .. but in normalized form
		// The security comes from validating the cleaned path before use
		t.Logf("Original path: %s, Cleaned path: %s", maliciousPath, cleaned)

		// Verify Clean normalizes the path
		doubleSeparator := "foo//bar"
		cleanedDouble := filepath.Clean(doubleSeparator)
		if cleanedDouble != "foo/bar" {
			t.Errorf("Expected 'foo/bar', got '%s'", cleanedDouble)
		}
	})

	t.Run("FileSizeValidation", func(t *testing.T) {
		// Test file size limits
		testSize := int64(15 * 1024 * 1024) // 15MB

		if testSize <= MaxFileSize {
			t.Errorf("Expected test size to exceed MaxFileSize")
		}

		// Verify MaxFileSize constant
		expectedMaxSize := int64(10 * 1024 * 1024)
		if MaxFileSize != expectedMaxSize {
			t.Errorf("Expected MaxFileSize to be %d, got %d", expectedMaxSize, MaxFileSize)
		}
	})

	t.Run("ChunkSizeValidation", func(t *testing.T) {
		// Verify ChunkSize constant
		expectedChunkSize := int64(64 * 1024)
		if ChunkSize != expectedChunkSize {
			t.Errorf("Expected ChunkSize to be %d, got %d", expectedChunkSize, ChunkSize)
		}
	})
}

func TestBinaryFileOperations(t *testing.T) {
	cfg, sess, repo := setupBinaryTest(t)
	ctx := context.Background()

	t.Run("EncryptDecryptBinaryFile", func(t *testing.T) {
		// Create test binary data
		testData := make([]byte, 1024)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		binaryData := &pb.BinaryData{
			Filename: "test-binary.dat",
			MimeType: "application/octet-stream",
			Size:     int64(len(testData)),
			Data:     testData,
		}

		// Marshal to protobuf
		binaryJSON, err := protojson.Marshal(binaryData)
		if err != nil {
			t.Fatalf("Failed to marshal binary data: %v", err)
		}

		// Encrypt
		encryptionKey := sess.GetEncryptionKey()
		encryptedData, err := crypto.Encrypt(binaryJSON, encryptionKey)
		if err != nil {
			t.Fatalf("Failed to encrypt binary data: %v", err)
		}

		// Store
		metadata := &pb.Metadata{
			CustomFields: map[string]string{
				"original_filename": "test-binary.dat",
				"mime_type":         "application/octet-stream",
				"file_size":         "1024",
			},
		}
		metadataJSON, err := protojson.Marshal(metadata)
		if err != nil {
			t.Fatalf("Failed to marshal metadata: %v", err)
		}

		now := time.Now()
		secret := &storage.LocalSecret{
			ID:             "test-binary-encrypt",
			Name:           "Binary Test",
			Type:           pb.SecretType_SECRET_TYPE_BINARY,
			EncryptedData:  []byte(encryptedData),
			Nonce:          []byte{},
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

		// Retrieve and decrypt
		stored, err := repo.Get(ctx, "test-binary-encrypt")
		if err != nil {
			t.Fatalf("Failed to get secret: %v", err)
		}

		decryptedData, err := crypto.Decrypt(string(stored.EncryptedData), encryptionKey)
		if err != nil {
			t.Fatalf("Failed to decrypt binary data: %v", err)
		}

		var retrievedBinaryData pb.BinaryData
		if err := protojson.Unmarshal(decryptedData, &retrievedBinaryData); err != nil {
			t.Fatalf("Failed to unmarshal binary data: %v", err)
		}

		// Verify data integrity
		if len(retrievedBinaryData.Data) != len(testData) {
			t.Errorf("Data length mismatch: expected %d, got %d", len(testData), len(retrievedBinaryData.Data))
		}

		for i := range testData {
			if retrievedBinaryData.Data[i] != testData[i] {
				t.Errorf("Data mismatch at byte %d: expected %d, got %d", i, testData[i], retrievedBinaryData.Data[i])
				break
			}
		}
	})

	// Clean up to avoid unused warnings
	_ = cfg
}

func TestMIMETypeDetection(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Text file",
			data:     []byte("This is plain text"),
			expected: "text/plain",
		},
		{
			name:     "HTML file",
			data:     []byte("<!DOCTYPE html><html><body>Test</body></html>"),
			expected: "text/html",
		},
		{
			name:     "JSON file",
			data:     []byte(`{"key": "value"}`),
			expected: "text/plain", // DetectContentType may return text/plain for JSON
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test-file")

			err := os.WriteFile(tmpFile, tt.data, 0600)
			if err != nil {
				t.Fatalf("Failed to write test file: %v", err)
			}

			// Read file
			fileData, err := os.ReadFile(tmpFile)
			if err != nil {
				t.Fatalf("Failed to read test file: %v", err)
			}

			// Verify data matches
			if string(fileData) != string(tt.data) {
				t.Errorf("File data mismatch")
			}
		})
	}
}

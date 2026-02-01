// Package server_test contains E2E integration tests for the Keyper server.
// These tests validate the complete secrets CRUD flow with encryption verification.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/koyif/keyper/internal/crypto"
	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/config"
	"github.com/koyif/keyper/internal/server/handlers"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	"github.com/koyif/keyper/internal/server/testhelpers"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// testSecretServer holds the gRPC server and related resources for secrets E2E testing.
type testSecretServer struct {
	grpcServer     *grpc.Server
	authClient     pb.AuthServiceClient
	secretsClient  pb.SecretsServiceClient
	listener       net.Listener
	tokenBlacklist *auth.TokenBlacklist
	pool           *testhelpers.TestContainer
	cleanup        func()
}

// setupSecretTestServer creates a gRPC server with auth and secrets services.
func setupSecretTestServer(t *testing.T, tc *testhelpers.TestContainer) *testSecretServer {
	t.Helper()

	// Initialize repositories.
	userRepo := postgres.NewUserRepository(tc.Pool())
	refreshTokenRepo := postgres.NewRefreshTokenRepository(tc.Pool())
	secretRepo := postgres.NewSecretRepository(tc.Pool())

	// Initialize JWT manager with test secret.
	jwtManager := auth.NewJWTManager(testJWTSecret)

	// Initialize token blacklist with short cleanup interval for testing.
	tokenBlacklist := auth.NewTokenBlacklist(100 * time.Millisecond)

	// Create gRPC server with auth interceptor.
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(auth.UnaryAuthInterceptorWithBlacklist(jwtManager, tokenBlacklist)),
	)

	// Initialize and register services.
	authService := handlers.NewAuthService(userRepo, refreshTokenRepo, jwtManager, tokenBlacklist)
	pb.RegisterAuthServiceServer(grpcServer, authService)

	secretsService := handlers.NewSecretsService(secretRepo, config.DefaultLimits())
	pb.RegisterSecretsServiceServer(grpcServer, secretsService)

	// Listen on random available port.
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
	require.NoError(t, err, "failed to create listener")

	// Start server in background.
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("Server stopped: %v", err)
		}
	}()

	// Create client connection.
	addr := listener.Addr().String()
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err, "failed to create client connection")

	// Create clients.
	authClient := pb.NewAuthServiceClient(conn)
	secretsClient := pb.NewSecretsServiceClient(conn)

	t.Logf("Test gRPC server started on %s", addr)

	// Cleanup function.
	cleanup := func() {
		conn.Close()
		grpcServer.GracefulStop()
		listener.Close()
		tokenBlacklist.Stop()
	}

	t.Cleanup(cleanup)

	return &testSecretServer{
		grpcServer:     grpcServer,
		authClient:     authClient,
		secretsClient:  secretsClient,
		listener:       listener,
		tokenBlacklist: tokenBlacklist,
		pool:           tc,
		cleanup:        cleanup,
	}
}

// registerAndLogin creates a test user and returns an authenticated context.
func registerAndLogin(t *testing.T, server *testSecretServer, username, password string) (context.Context, string, []byte) {
	t.Helper()

	ctx := context.Background()

	// Register user.
	registerReq := &pb.RegisterRequest{
		Username:       username,
		MasterPassword: password,
		DeviceInfo:     "test-device",
	}

	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	registerResp, err := server.authClient.Register(ctx, registerReq)
	require.NoError(t, err, "register should succeed")
	require.NotNil(t, registerResp)

	// Create authenticated context with access token.
	authCtx := metadata.AppendToOutgoingContext(
		context.Background(),
		"authorization", "Bearer "+registerResp.AccessToken,
	)

	// Derive encryption key from master password (client-side operation).
	salt, err := crypto.GenerateSalt(crypto.SaltLength)
	require.NoError(t, err)
	encryptionKey := crypto.DeriveKey(password, salt)

	return authCtx, registerResp.UserId, encryptionKey
}

// encryptSecretData encrypts secret data using the provided key (client-side operation).
func encryptSecretData(t *testing.T, data interface{}, encryptionKey []byte) string {
	t.Helper()

	// Marshal data to JSON.
	plaintext, err := json.Marshal(data)
	require.NoError(t, err, "failed to marshal secret data")

	// Encrypt using client-side crypto.
	encrypted, err := crypto.Encrypt(plaintext, encryptionKey)
	require.NoError(t, err, "failed to encrypt secret data")

	return encrypted
}

// decryptSecretData decrypts secret data using the provided key (client-side operation).
func decryptSecretData(t *testing.T, encryptedB64 string, encryptionKey []byte, result interface{}) {
	t.Helper()

	// Decrypt using client-side crypto.
	plaintext, err := crypto.Decrypt(encryptedB64, encryptionKey)
	require.NoError(t, err, "failed to decrypt secret data")

	// Unmarshal JSON.
	err = json.Unmarshal(plaintext, result)
	require.NoError(t, err, "failed to unmarshal secret data")
}

// queryDatabaseEncryptedData directly queries the database to verify encryption at rest.
func queryDatabaseEncryptedData(t *testing.T, tc *testhelpers.TestContainer, secretID string) []byte {
	t.Helper()

	query := "SELECT encrypted_data FROM secrets WHERE id = $1"
	rows := tc.Query(context.Background(), t, query, secretID)
	defer rows.Close()

	require.True(t, rows.Next(), "secret should exist in database")

	var encryptedData []byte
	err := rows.Scan(&encryptedData)
	require.NoError(t, err, "failed to scan encrypted_data")

	return encryptedData
}

// TestSecretsFlow_CredentialType tests CRUD operations for CREDENTIAL type secrets.
func TestSecretsFlow_CredentialType(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login user.
	authCtx, userID, encryptionKey := registerAndLogin(t, server, "credential-test@example.com", "secure-password")

	// Test data.
	credentialData := &pb.CredentialData{
		Username: "testuser",
		Password: "super-secret-password",
		Email:    "test@example.com",
		Url:      "https://example.com",
		CustomFields: []*pb.CustomField{
			{Key: "security_question", Value: "What is your pet's name?", IsSensitive: false},
			{Key: "security_answer", Value: "Fluffy", IsSensitive: true},
		},
	}

	metadata := &pb.Metadata{
		Category:   "work",
		Tags:       []string{"important", "work-account"},
		Notes:      "Main work credentials",
		Url:        "https://example.com/login",
		IsFavorite: true,
	}

	var secretID string
	var version int64

	t.Run("Create credential secret", func(t *testing.T) {
		// Encrypt credential data.
		encryptedData := encryptSecretData(t, credentialData, encryptionKey)

		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			Title:         "Work Login",
			EncryptedData: encryptedData,
			Metadata:      metadata,
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.NoError(t, err, "create secret should succeed")
		require.NotNil(t, resp)

		assert.NotEmpty(t, resp.Secret.Id)
		assert.Equal(t, userID, resp.Secret.UserId)
		assert.Equal(t, pb.SecretType_SECRET_TYPE_CREDENTIAL, resp.Secret.Type)
		assert.Equal(t, "Work Login", resp.Secret.Title)
		assert.NotEmpty(t, resp.Secret.EncryptedData)
		assert.Equal(t, int64(1), resp.Secret.Version)
		assert.False(t, resp.Secret.IsDeleted)
		assert.Equal(t, "Secret created successfully", resp.Message)

		// Verify metadata.
		assert.Equal(t, metadata.Category, resp.Secret.Metadata.Category)
		assert.Equal(t, metadata.Tags, resp.Secret.Metadata.Tags)
		assert.Equal(t, metadata.Notes, resp.Secret.Metadata.Notes)
		assert.Equal(t, metadata.IsFavorite, resp.Secret.Metadata.IsFavorite)

		secretID = resp.Secret.Id
		version = resp.Secret.Version

		t.Logf("Created credential secret with ID: %s", secretID)
	})

	t.Run("Verify encryption at rest in database", func(t *testing.T) {
		// Query database directly to verify data is encrypted.
		dbEncryptedData := queryDatabaseEncryptedData(t, tc, secretID)

		// Verify the data is not plaintext.
		// Convert credential data to JSON to check it's not stored as plaintext.
		plaintextJSON, err := json.Marshal(credentialData)
		require.NoError(t, err)

		// The database should NOT contain the plaintext.
		assert.NotContains(t, string(dbEncryptedData), string(plaintextJSON))
		assert.NotContains(t, string(dbEncryptedData), credentialData.Username)
		assert.NotContains(t, string(dbEncryptedData), credentialData.Password)
		assert.NotContains(t, string(dbEncryptedData), credentialData.Email)

		t.Logf("Verified secret is encrypted at rest (database contains %d bytes of encrypted data)", len(dbEncryptedData))
	})

	t.Run("Retrieve and decrypt credential secret", func(t *testing.T) {
		req := &pb.GetSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.GetSecret(authCtx, req)
		require.NoError(t, err, "get secret should succeed")
		require.NotNil(t, resp)

		assert.Equal(t, secretID, resp.Secret.Id)
		assert.Equal(t, "Work Login", resp.Secret.Title)
		assert.Equal(t, pb.SecretType_SECRET_TYPE_CREDENTIAL, resp.Secret.Type)

		// Decrypt and verify data.
		var decrypted pb.CredentialData
		decryptSecretData(t, resp.Secret.EncryptedData, encryptionKey, &decrypted)

		assert.Equal(t, credentialData.Username, decrypted.Username)
		assert.Equal(t, credentialData.Password, decrypted.Password)
		assert.Equal(t, credentialData.Email, decrypted.Email)
		assert.Equal(t, credentialData.Url, decrypted.Url)
		assert.Len(t, decrypted.CustomFields, 2)

		t.Logf("Successfully retrieved and decrypted credential secret")
	})

	t.Run("Update credential secret and verify version increment", func(t *testing.T) {
		// Update credential data.
		updatedCredential := &pb.CredentialData{
			Username: "newuser",
			Password: "new-super-secret-password",
			Email:    "newemail@example.com",
			Url:      "https://newexample.com",
		}

		encryptedData := encryptSecretData(t, updatedCredential, encryptionKey)

		updatedMetadata := &pb.Metadata{
			Category:   "personal",
			Tags:       []string{"updated"},
			Notes:      "Updated credentials",
			IsFavorite: false,
		}

		req := &pb.UpdateSecretRequest{
			SecretId:      secretID,
			Title:         "Updated Work Login",
			EncryptedData: encryptedData,
			Metadata:      updatedMetadata,
			Version:       version,
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx, req)
		require.NoError(t, err, "update secret should succeed")
		require.NotNil(t, resp)

		assert.Equal(t, secretID, resp.Secret.Id)
		assert.Equal(t, "Updated Work Login", resp.Secret.Title)
		assert.Equal(t, int64(2), resp.Secret.Version, "version should increment from 1 to 2")
		assert.Equal(t, "Secret updated successfully", resp.Message)

		// Verify updated metadata.
		assert.Equal(t, updatedMetadata.Category, resp.Secret.Metadata.Category)
		assert.Equal(t, updatedMetadata.Tags, resp.Secret.Metadata.Tags)

		// Decrypt and verify updated data.
		var decrypted pb.CredentialData
		decryptSecretData(t, resp.Secret.EncryptedData, encryptionKey, &decrypted)

		assert.Equal(t, updatedCredential.Username, decrypted.Username)
		assert.Equal(t, updatedCredential.Password, decrypted.Password)
		assert.Equal(t, updatedCredential.Email, decrypted.Email)

		version = resp.Secret.Version
		t.Logf("Successfully updated secret, version incremented to %d", version)
	})

	t.Run("Update with stale version fails", func(t *testing.T) {
		encryptedData := encryptSecretData(t, credentialData, encryptionKey)

		req := &pb.UpdateSecretRequest{
			SecretId:      secretID,
			Title:         "Stale Update",
			EncryptedData: encryptedData,
			Metadata:      metadata,
			Version:       1, // Stale version (current is 2).
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx, req)
		require.Error(t, err, "update with stale version should fail")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Contains(t, st.Message(), "version conflict")

		t.Logf("Version conflict correctly detected")
	})

	t.Run("Delete credential secret", func(t *testing.T) {
		req := &pb.DeleteSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.DeleteSecret(authCtx, req)
		require.NoError(t, err, "delete secret should succeed")
		require.NotNil(t, resp)

		assert.Equal(t, "Secret deleted successfully", resp.Message)

		t.Logf("Successfully deleted secret")
	})

	t.Run("Verify deleted secret is marked is_deleted in database", func(t *testing.T) {
		query := "SELECT is_deleted, version FROM secrets WHERE id = $1"
		rows := tc.Query(context.Background(), t, query, secretID)
		defer rows.Close()

		require.True(t, rows.Next(), "secret should still exist in database")

		var isDeleted bool
		var dbVersion int64
		err := rows.Scan(&isDeleted, &dbVersion)
		require.NoError(t, err)

		assert.True(t, isDeleted, "is_deleted should be true")
		assert.Equal(t, int64(3), dbVersion, "version should increment on delete")

		t.Logf("Verified soft delete: is_deleted=true, version=%d", dbVersion)
	})

	t.Run("Cannot retrieve deleted secret", func(t *testing.T) {
		req := &pb.GetSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.GetSecret(authCtx, req)
		require.Error(t, err, "get deleted secret should fail")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
	})
}

// TestSecretsFlow_TextType tests CRUD operations for TEXT type secrets.
func TestSecretsFlow_TextType(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login user.
	authCtx, _, encryptionKey := registerAndLogin(t, server, "text-test@example.com", "secure-password")

	// Test data.
	textData := &pb.TextData{
		Content: "This is a secret note with sensitive information. Account number: 12345. PIN: 9876.",
	}

	metadata := &pb.Metadata{
		Category:   "notes",
		Tags:       []string{"personal", "sensitive"},
		Notes:      "Important note",
		IsFavorite: false,
	}

	var secretID string

	t.Run("Create text secret", func(t *testing.T) {
		encryptedData := encryptSecretData(t, textData, encryptionKey)

		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			Title:         "Secret Note",
			EncryptedData: encryptedData,
			Metadata:      metadata,
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.NoError(t, err, "create secret should succeed")
		require.NotNil(t, resp)

		assert.Equal(t, pb.SecretType_SECRET_TYPE_TEXT, resp.Secret.Type)
		assert.Equal(t, "Secret Note", resp.Secret.Title)
		assert.Equal(t, int64(1), resp.Secret.Version)

		secretID = resp.Secret.Id
		t.Logf("Created text secret with ID: %s", secretID)
	})

	t.Run("Verify text content is encrypted at rest", func(t *testing.T) {
		dbEncryptedData := queryDatabaseEncryptedData(t, tc, secretID)

		// Verify sensitive content is not in plaintext.
		assert.NotContains(t, string(dbEncryptedData), textData.Content)
		assert.NotContains(t, string(dbEncryptedData), "Account number: 12345")
		assert.NotContains(t, string(dbEncryptedData), "PIN: 9876")

		t.Logf("Verified text secret is encrypted at rest")
	})

	t.Run("Retrieve and decrypt text secret", func(t *testing.T) {
		req := &pb.GetSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.GetSecret(authCtx, req)
		require.NoError(t, err)

		var decrypted pb.TextData
		decryptSecretData(t, resp.Secret.EncryptedData, encryptionKey, &decrypted)

		assert.Equal(t, textData.Content, decrypted.Content)

		t.Logf("Successfully decrypted text secret")
	})

	t.Run("Update text secret", func(t *testing.T) {
		updatedText := &pb.TextData{
			Content: "Updated secret note content.",
		}

		encryptedData := encryptSecretData(t, updatedText, encryptionKey)

		req := &pb.UpdateSecretRequest{
			SecretId:      secretID,
			Title:         "Updated Secret Note",
			EncryptedData: encryptedData,
			Metadata:      metadata,
			Version:       1,
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx, req)
		require.NoError(t, err)

		assert.Equal(t, int64(2), resp.Secret.Version)

		// Verify updated content.
		var decrypted pb.TextData
		decryptSecretData(t, resp.Secret.EncryptedData, encryptionKey, &decrypted)
		assert.Equal(t, updatedText.Content, decrypted.Content)
	})

	t.Run("Delete text secret", func(t *testing.T) {
		req := &pb.DeleteSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.DeleteSecret(authCtx, req)
		require.NoError(t, err)
		assert.Equal(t, "Secret deleted successfully", resp.Message)
	})
}

// TestSecretsFlow_BinaryType tests CRUD operations for BINARY type secrets.
func TestSecretsFlow_BinaryType(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login user.
	authCtx, _, encryptionKey := registerAndLogin(t, server, "binary-test@example.com", "secure-password")

	// Test data (simulate a small binary file).
	binaryData := &pb.BinaryData{
		Filename: "secret-document.pdf",
		MimeType: "application/pdf",
		Size:     1024,
		Data:     []byte{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34}, // PDF header bytes
	}

	metadata := &pb.Metadata{
		Category: "documents",
		Tags:     []string{"important", "encrypted"},
		Notes:    "Confidential document",
	}

	var secretID string

	t.Run("Create binary secret", func(t *testing.T) {
		encryptedData := encryptSecretData(t, binaryData, encryptionKey)

		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_BINARY,
			Title:         "Secret Document",
			EncryptedData: encryptedData,
			Metadata:      metadata,
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, pb.SecretType_SECRET_TYPE_BINARY, resp.Secret.Type)
		assert.Equal(t, "Secret Document", resp.Secret.Title)

		secretID = resp.Secret.Id
		t.Logf("Created binary secret with ID: %s", secretID)
	})

	t.Run("Verify binary data is encrypted at rest", func(t *testing.T) {
		dbEncryptedData := queryDatabaseEncryptedData(t, tc, secretID)

		// Verify filename and binary data are not in plaintext.
		assert.NotContains(t, string(dbEncryptedData), binaryData.Filename)
		assert.NotContains(t, string(dbEncryptedData), binaryData.MimeType)
		// Note: bytes might appear by chance, so we check the full pattern isn't there.
		marshaled, _ := json.Marshal(binaryData)
		assert.NotContains(t, string(dbEncryptedData), string(marshaled))

		t.Logf("Verified binary secret is encrypted at rest")
	})

	t.Run("Retrieve and decrypt binary secret", func(t *testing.T) {
		req := &pb.GetSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.GetSecret(authCtx, req)
		require.NoError(t, err)

		var decrypted pb.BinaryData
		decryptSecretData(t, resp.Secret.EncryptedData, encryptionKey, &decrypted)

		assert.Equal(t, binaryData.Filename, decrypted.Filename)
		assert.Equal(t, binaryData.MimeType, decrypted.MimeType)
		assert.Equal(t, binaryData.Size, decrypted.Size)
		assert.Equal(t, binaryData.Data, decrypted.Data)

		t.Logf("Successfully decrypted binary secret")
	})

	t.Run("Update binary secret", func(t *testing.T) {
		updatedBinary := &pb.BinaryData{
			Filename: "updated-document.pdf",
			MimeType: "application/pdf",
			Size:     2048,
			Data:     []byte{0xFF, 0xD8, 0xFF, 0xE0}, // JPEG header
		}

		encryptedData := encryptSecretData(t, updatedBinary, encryptionKey)

		req := &pb.UpdateSecretRequest{
			SecretId:      secretID,
			Title:         "Updated Secret Document",
			EncryptedData: encryptedData,
			Metadata:      metadata,
			Version:       1,
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx, req)
		require.NoError(t, err)

		assert.Equal(t, int64(2), resp.Secret.Version)

		// Verify updated content.
		var decrypted pb.BinaryData
		decryptSecretData(t, resp.Secret.EncryptedData, encryptionKey, &decrypted)
		assert.Equal(t, updatedBinary.Filename, decrypted.Filename)
		assert.Equal(t, updatedBinary.Data, decrypted.Data)
	})

	t.Run("Delete binary secret", func(t *testing.T) {
		req := &pb.DeleteSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.DeleteSecret(authCtx, req)
		require.NoError(t, err)
		assert.Equal(t, "Secret deleted successfully", resp.Message)
	})
}

// TestSecretsFlow_BankCardType tests CRUD operations for BANK_CARD type secrets.
func TestSecretsFlow_BankCardType(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login user.
	authCtx, _, encryptionKey := registerAndLogin(t, server, "bankcard-test@example.com", "secure-password")

	// Test data.
	bankCardData := &pb.BankCardData{
		CardholderName: "John Doe",
		CardNumber:     "4532-1234-5678-9010",
		ExpiryMonth:    "12",
		ExpiryYear:     "2028",
		Cvv:            "123",
		Pin:            "9876",
		BankName:       "Test Bank",
	}

	metadata := &pb.Metadata{
		Category:   "finance",
		Tags:       []string{"credit-card", "personal"},
		Notes:      "Primary credit card",
		IsFavorite: true,
	}

	var secretID string

	t.Run("Create bank card secret", func(t *testing.T) {
		encryptedData := encryptSecretData(t, bankCardData, encryptionKey)

		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_BANK_CARD,
			Title:         "Primary Credit Card",
			EncryptedData: encryptedData,
			Metadata:      metadata,
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, pb.SecretType_SECRET_TYPE_BANK_CARD, resp.Secret.Type)
		assert.Equal(t, "Primary Credit Card", resp.Secret.Title)
		assert.Equal(t, int64(1), resp.Secret.Version)

		secretID = resp.Secret.Id
		t.Logf("Created bank card secret with ID: %s", secretID)
	})

	t.Run("Verify card details are encrypted at rest", func(t *testing.T) {
		dbEncryptedData := queryDatabaseEncryptedData(t, tc, secretID)

		// Verify sensitive card information is not in plaintext.
		assert.NotContains(t, string(dbEncryptedData), bankCardData.CardholderName)
		assert.NotContains(t, string(dbEncryptedData), bankCardData.CardNumber)
		assert.NotContains(t, string(dbEncryptedData), bankCardData.Cvv)
		assert.NotContains(t, string(dbEncryptedData), bankCardData.Pin)
		assert.NotContains(t, string(dbEncryptedData), "4532-1234-5678-9010")

		t.Logf("Verified bank card secret is encrypted at rest")
	})

	t.Run("Retrieve and decrypt bank card secret", func(t *testing.T) {
		req := &pb.GetSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.GetSecret(authCtx, req)
		require.NoError(t, err)

		var decrypted pb.BankCardData
		decryptSecretData(t, resp.Secret.EncryptedData, encryptionKey, &decrypted)

		assert.Equal(t, bankCardData.CardholderName, decrypted.CardholderName)
		assert.Equal(t, bankCardData.CardNumber, decrypted.CardNumber)
		assert.Equal(t, bankCardData.ExpiryMonth, decrypted.ExpiryMonth)
		assert.Equal(t, bankCardData.ExpiryYear, decrypted.ExpiryYear)
		assert.Equal(t, bankCardData.Cvv, decrypted.Cvv)
		assert.Equal(t, bankCardData.Pin, decrypted.Pin)
		assert.Equal(t, bankCardData.BankName, decrypted.BankName)

		t.Logf("Successfully decrypted bank card secret")
	})

	t.Run("Update bank card secret", func(t *testing.T) {
		updatedCard := &pb.BankCardData{
			CardholderName: "Jane Doe",
			CardNumber:     "5105-1051-0510-5100",
			ExpiryMonth:    "06",
			ExpiryYear:     "2030",
			Cvv:            "456",
			Pin:            "1234",
			BankName:       "Another Bank",
		}

		encryptedData := encryptSecretData(t, updatedCard, encryptionKey)

		req := &pb.UpdateSecretRequest{
			SecretId:      secretID,
			Title:         "Updated Credit Card",
			EncryptedData: encryptedData,
			Metadata:      metadata,
			Version:       1,
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx, req)
		require.NoError(t, err)

		assert.Equal(t, int64(2), resp.Secret.Version)

		// Verify updated content.
		var decrypted pb.BankCardData
		decryptSecretData(t, resp.Secret.EncryptedData, encryptionKey, &decrypted)
		assert.Equal(t, updatedCard.CardholderName, decrypted.CardholderName)
		assert.Equal(t, updatedCard.CardNumber, decrypted.CardNumber)
	})

	t.Run("Delete bank card secret", func(t *testing.T) {
		req := &pb.DeleteSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.DeleteSecret(authCtx, req)
		require.NoError(t, err)
		assert.Equal(t, "Secret deleted successfully", resp.Message)
	})
}

// TestSecretsFlow_ValidationErrors tests validation errors for secret operations.
func TestSecretsFlow_ValidationErrors(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login user.
	authCtx, _, encryptionKey := registerAndLogin(t, server, "validation-test@example.com", "secure-password")

	t.Run("Create secret with empty title fails", func(t *testing.T) {
		textData := &pb.TextData{Content: "test"}
		encryptedData := encryptSecretData(t, textData, encryptionKey)

		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			Title:         "", // Empty title
			EncryptedData: encryptedData,
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "title is required")
	})

	t.Run("Create secret with empty encrypted data fails", func(t *testing.T) {
		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			Title:         "Test",
			EncryptedData: "", // Empty encrypted data
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "encrypted_data is required")
	})

	t.Run("Create secret with unspecified type fails", func(t *testing.T) {
		textData := &pb.TextData{Content: "test"}
		encryptedData := encryptSecretData(t, textData, encryptionKey)

		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_UNSPECIFIED, // Invalid type
			Title:         "Test",
			EncryptedData: encryptedData,
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "secret type must be specified")
	})

	t.Run("Create secret with invalid base64 fails", func(t *testing.T) {
		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			Title:         "Test",
			EncryptedData: "not-valid-base64!!!",
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "invalid base64")
	})

	t.Run("Get secret with invalid UUID fails", func(t *testing.T) {
		req := &pb.GetSecretRequest{
			SecretId: "not-a-valid-uuid",
		}

		resp, err := server.secretsClient.GetSecret(authCtx, req)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "invalid secret_id format")
	})

	t.Run("Get non-existent secret fails", func(t *testing.T) {
		req := &pb.GetSecretRequest{
			SecretId: uuid.New().String(),
		}

		resp, err := server.secretsClient.GetSecret(authCtx, req)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.NotFound, st.Code())
		assert.Contains(t, st.Message(), "secret not found")
	})

	t.Run("Update secret without version fails", func(t *testing.T) {
		textData := &pb.TextData{Content: "test"}
		encryptedData := encryptSecretData(t, textData, encryptionKey)

		req := &pb.UpdateSecretRequest{
			SecretId:      uuid.New().String(),
			Title:         "Test",
			EncryptedData: encryptedData,
			Version:       0, // Invalid version
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx, req)
		require.Error(t, err)
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "version must be provided")
	})
}

// TestSecretsFlow_Authorization tests authorization checks for secret operations.
func TestSecretsFlow_Authorization(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login first user.
	authCtx1, _, encryptionKey1 := registerAndLogin(t, server, "user1@example.com", "password1")

	// Register and login second user.
	authCtx2, _, _ := registerAndLogin(t, server, "user2@example.com", "password2")

	// Create a secret as user1.
	textData := &pb.TextData{Content: "User 1's secret"}
	encryptedData := encryptSecretData(t, textData, encryptionKey1)

	createReq := &pb.CreateSecretRequest{
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
		Title:         "User 1 Secret",
		EncryptedData: encryptedData,
	}

	createResp, err := server.secretsClient.CreateSecret(authCtx1, createReq)
	require.NoError(t, err)
	secretID := createResp.Secret.Id

	t.Run("User cannot access another user's secret", func(t *testing.T) {
		// Try to get user1's secret as user2.
		req := &pb.GetSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.GetSecret(authCtx2, req)
		require.Error(t, err, "user2 should not be able to access user1's secret")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
		assert.Contains(t, st.Message(), "access denied")
	})

	t.Run("User cannot update another user's secret", func(t *testing.T) {
		req := &pb.UpdateSecretRequest{
			SecretId:      secretID,
			Title:         "Malicious Update",
			EncryptedData: encryptedData,
			Version:       1,
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx2, req)
		require.Error(t, err, "user2 should not be able to update user1's secret")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	})

	t.Run("User cannot delete another user's secret", func(t *testing.T) {
		req := &pb.DeleteSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.DeleteSecret(authCtx2, req)
		require.Error(t, err, "user2 should not be able to delete user1's secret")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.PermissionDenied, st.Code())
	})

	t.Run("Unauthenticated request fails", func(t *testing.T) {
		unauthCtx := context.Background()

		req := &pb.GetSecretRequest{
			SecretId: secretID,
		}

		resp, err := server.secretsClient.GetSecret(unauthCtx, req)
		require.Error(t, err, "unauthenticated request should fail")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})
}

// TestSecretsFlow_ListSecrets tests listing secrets for a user.
func TestSecretsFlow_ListSecrets(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login user.
	authCtx, _, encryptionKey := registerAndLogin(t, server, "list-test@example.com", "secure-password")

	// Create multiple secrets of different types.
	secretTypes := []struct {
		secretType pb.SecretType
		title      string
		data       interface{}
	}{
		{pb.SecretType_SECRET_TYPE_CREDENTIAL, "Login 1", &pb.CredentialData{Username: "user1", Password: "pass1"}},
		{pb.SecretType_SECRET_TYPE_TEXT, "Note 1", &pb.TextData{Content: "Note content 1"}},
		{pb.SecretType_SECRET_TYPE_BINARY, "File 1", &pb.BinaryData{Filename: "file1.txt", Data: []byte("data")}},
		{pb.SecretType_SECRET_TYPE_BANK_CARD, "Card 1", &pb.BankCardData{CardholderName: "John", CardNumber: "1234"}},
		{pb.SecretType_SECRET_TYPE_CREDENTIAL, "Login 2", &pb.CredentialData{Username: "user2", Password: "pass2"}},
	}

	for _, st := range secretTypes {
		encryptedData := encryptSecretData(t, st.data, encryptionKey)

		req := &pb.CreateSecretRequest{
			Type:          st.secretType,
			Title:         st.title,
			EncryptedData: encryptedData,
		}

		_, err := server.secretsClient.CreateSecret(authCtx, req)
		require.NoError(t, err, "failed to create secret: %s", st.title)
	}

	t.Run("List all secrets", func(t *testing.T) {
		req := &pb.ListSecretsRequest{
			PageSize: 100,
		}

		resp, err := server.secretsClient.ListSecrets(authCtx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Len(t, resp.Secrets, 5, "should return all 5 secrets")
		assert.Equal(t, int32(5), resp.TotalCount)

		// Verify all secrets are returned and not deleted.
		for _, secret := range resp.Secrets {
			assert.False(t, secret.IsDeleted)
			assert.NotEmpty(t, secret.EncryptedData)
		}

		t.Logf("Successfully listed %d secrets", len(resp.Secrets))
	})

	t.Run("List secrets with pagination", func(t *testing.T) {
		req := &pb.ListSecretsRequest{
			PageSize: 2,
		}

		resp, err := server.secretsClient.ListSecrets(authCtx, req)
		require.NoError(t, err)

		assert.Len(t, resp.Secrets, 2, "should return 2 secrets per page")
		assert.NotEmpty(t, resp.NextPageToken, "should have next page token")

		// Get next page.
		req.PageToken = resp.NextPageToken
		resp2, err := server.secretsClient.ListSecrets(authCtx, req)
		require.NoError(t, err)

		assert.Len(t, resp2.Secrets, 2, "should return 2 more secrets")

		// Verify no duplicate secrets.
		firstPageIDs := make(map[string]bool)
		for _, s := range resp.Secrets {
			firstPageIDs[s.Id] = true
		}
		for _, s := range resp2.Secrets {
			assert.NotContains(t, firstPageIDs, s.Id, "should not have duplicate secrets")
		}
	})
}

// TestSecretsFlow_MetadataHandling tests metadata fields and JSON serialization.
func TestSecretsFlow_MetadataHandling(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login user.
	authCtx, _, encryptionKey := registerAndLogin(t, server, "metadata-test@example.com", "secure-password")

	t.Run("Create secret with rich metadata", func(t *testing.T) {
		textData := &pb.TextData{Content: "Test"}
		encryptedData := encryptSecretData(t, textData, encryptionKey)

		metadata := &pb.Metadata{
			Category:   "work",
			Tags:       []string{"important", "project-x", "client-abc"},
			Notes:      "This is a detailed note about the secret",
			Url:        "https://example.com/resource",
			IsFavorite: true,
			CustomFields: map[string]string{
				"project":     "Project X",
				"department":  "Engineering",
				"cost_center": "CC-1234",
			},
		}

		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			Title:         "Rich Metadata Secret",
			EncryptedData: encryptedData,
			Metadata:      metadata,
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.NoError(t, err)

		// Verify all metadata fields.
		assert.Equal(t, metadata.Category, resp.Secret.Metadata.Category)
		assert.Equal(t, metadata.Tags, resp.Secret.Metadata.Tags)
		assert.Equal(t, metadata.Notes, resp.Secret.Metadata.Notes)
		assert.Equal(t, metadata.Url, resp.Secret.Metadata.Url)
		assert.Equal(t, metadata.IsFavorite, resp.Secret.Metadata.IsFavorite)
		assert.Equal(t, metadata.CustomFields, resp.Secret.Metadata.CustomFields)

		t.Logf("Successfully created secret with rich metadata")
	})

	t.Run("Create secret with minimal metadata", func(t *testing.T) {
		textData := &pb.TextData{Content: "Test"}
		encryptedData := encryptSecretData(t, textData, encryptionKey)

		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			Title:         "Minimal Metadata Secret",
			EncryptedData: encryptedData,
			Metadata:      &pb.Metadata{}, // Empty metadata
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.NoError(t, err)

		// Verify metadata exists but is empty.
		assert.NotNil(t, resp.Secret.Metadata)
		assert.Empty(t, resp.Secret.Metadata.Category)
		assert.Empty(t, resp.Secret.Metadata.Tags)
		assert.False(t, resp.Secret.Metadata.IsFavorite)
	})

	t.Run("Verify metadata JSON in database", func(t *testing.T) {
		textData := &pb.TextData{Content: "Test"}
		encryptedData := encryptSecretData(t, textData, encryptionKey)

		metadata := &pb.Metadata{
			Category: "test-category",
			Tags:     []string{"tag1", "tag2"},
		}

		req := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			Title:         "DB Metadata Test",
			EncryptedData: encryptedData,
			Metadata:      metadata,
		}

		resp, err := server.secretsClient.CreateSecret(authCtx, req)
		require.NoError(t, err)

		// Query database to verify metadata JSON.
		query := "SELECT metadata FROM secrets WHERE id = $1"
		rows := tc.Query(context.Background(), t, query, resp.Secret.Id)
		defer rows.Close()

		require.True(t, rows.Next())

		var metadataJSON []byte
		err = rows.Scan(&metadataJSON)
		require.NoError(t, err)

		// Parse and verify JSON structure.
		var dbMetadata pb.Metadata
		err = protojson.Unmarshal(metadataJSON, &dbMetadata)
		require.NoError(t, err)

		assert.Equal(t, metadata.Category, dbMetadata.Category)
		assert.Equal(t, metadata.Tags, dbMetadata.Tags)

		t.Logf("Verified metadata is correctly stored as JSON in database")
	})
}

// TestSecretsFlow_ConcurrentUpdates tests concurrent update scenarios.
func TestSecretsFlow_ConcurrentUpdates(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login user.
	authCtx, _, encryptionKey := registerAndLogin(t, server, "concurrent-test@example.com", "secure-password")

	// Create initial secret.
	textData := &pb.TextData{Content: "Initial content"}
	encryptedData := encryptSecretData(t, textData, encryptionKey)

	createReq := &pb.CreateSecretRequest{
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
		Title:         "Concurrent Test",
		EncryptedData: encryptedData,
	}

	createResp, err := server.secretsClient.CreateSecret(authCtx, createReq)
	require.NoError(t, err)

	secretID := createResp.Secret.Id
	initialVersion := createResp.Secret.Version

	t.Run("First concurrent update succeeds", func(t *testing.T) {
		updatedData := &pb.TextData{Content: "Update 1"}
		encryptedData := encryptSecretData(t, updatedData, encryptionKey)

		req := &pb.UpdateSecretRequest{
			SecretId:      secretID,
			Title:         "Update 1",
			EncryptedData: encryptedData,
			Version:       initialVersion,
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx, req)
		require.NoError(t, err)

		assert.Equal(t, int64(2), resp.Secret.Version)
	})

	t.Run("Second concurrent update with stale version fails", func(t *testing.T) {
		updatedData := &pb.TextData{Content: "Update 2"}
		encryptedData := encryptSecretData(t, updatedData, encryptionKey)

		req := &pb.UpdateSecretRequest{
			SecretId:      secretID,
			Title:         "Update 2",
			EncryptedData: encryptedData,
			Version:       initialVersion, // Stale version (should be 2 now)
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx, req)
		require.Error(t, err, "update with stale version should fail")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.FailedPrecondition, st.Code())
		assert.Contains(t, st.Message(), "version conflict")
	})

	t.Run("Update with correct version succeeds", func(t *testing.T) {
		updatedData := &pb.TextData{Content: "Update 3"}
		encryptedData := encryptSecretData(t, updatedData, encryptionKey)

		req := &pb.UpdateSecretRequest{
			SecretId:      secretID,
			Title:         "Update 3",
			EncryptedData: encryptedData,
			Version:       2, // Correct current version
		}

		resp, err := server.secretsClient.UpdateSecret(authCtx, req)
		require.NoError(t, err)

		assert.Equal(t, int64(3), resp.Secret.Version)
	})
}

// TestSecretsFlow_EncryptionVerification performs comprehensive encryption verification.
func TestSecretsFlow_EncryptionVerification(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSecretTestServer(t, tc)

	// Register and login user.
	authCtx, _, encryptionKey := registerAndLogin(t, server, "encryption-verify@example.com", "secure-password")

	// Highly sensitive data to verify encryption.
	sensitiveData := &pb.CredentialData{
		Username: "admin",
		Password: "SuperSecret123!@#$%^&*()",
		Email:    "admin@topsecret.com",
	}

	encryptedData := encryptSecretData(t, sensitiveData, encryptionKey)

	req := &pb.CreateSecretRequest{
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
		Title:         "Highly Sensitive Credentials",
		EncryptedData: encryptedData,
	}

	resp, err := server.secretsClient.CreateSecret(authCtx, req)
	require.NoError(t, err)
	secretID := resp.Secret.Id

	t.Run("Comprehensive encryption verification", func(t *testing.T) {
		// Query database directly for raw encrypted data.
		query := "SELECT encrypted_data, nonce FROM secrets WHERE id = $1"
		rows := tc.Query(context.Background(), t, query, secretID)
		defer rows.Close()

		require.True(t, rows.Next())

		var dbEncryptedData, dbNonce []byte
		err := rows.Scan(&dbEncryptedData, &dbNonce)
		require.NoError(t, err)

		t.Logf("Database encrypted_data length: %d bytes", len(dbEncryptedData))
		t.Logf("Database nonce length: %d bytes", len(dbNonce))

		// Verify nonce is exactly 12 bytes (AES-GCM standard).
		assert.Equal(t, crypto.NonceSize, len(dbNonce))

		// Verify encrypted data is longer than plaintext (due to GCM tag).
		plaintextJSON, _ := json.Marshal(sensitiveData)
		assert.Greater(t, len(dbEncryptedData), len(plaintextJSON),
			"encrypted data should be larger than plaintext due to GCM authentication tag")

		// Verify no sensitive strings appear in encrypted data.
		dbDataStr := string(dbEncryptedData)
		assert.NotContains(t, dbDataStr, sensitiveData.Username)
		assert.NotContains(t, dbDataStr, sensitiveData.Password)
		assert.NotContains(t, dbDataStr, sensitiveData.Email)
		assert.NotContains(t, dbDataStr, "admin")
		assert.NotContains(t, dbDataStr, "SuperSecret")
		assert.NotContains(t, dbDataStr, "@topsecret.com")

		// Verify encrypted data appears random (basic entropy check).
		// Count unique bytes in encrypted data.
		byteFreq := make(map[byte]int)
		for _, b := range dbEncryptedData {
			byteFreq[b]++
		}
		// Encrypted data should have good byte distribution.
		assert.Greater(t, len(byteFreq), 50, "encrypted data should have high byte diversity")

		t.Logf("Encryption verification passed: data is properly encrypted at rest")
	})

	t.Run("Verify nonce is unique for each secret", func(t *testing.T) {
		// Create another secret with same data.
		encryptedData2 := encryptSecretData(t, sensitiveData, encryptionKey)

		req2 := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			Title:         "Duplicate Credentials",
			EncryptedData: encryptedData2,
		}

		resp2, err := server.secretsClient.CreateSecret(authCtx, req2)
		require.NoError(t, err)

		// Query both secrets' nonces.
		query := "SELECT nonce FROM secrets WHERE id IN ($1, $2)"
		rows := tc.Query(context.Background(), t, query, secretID, resp2.Secret.Id)
		defer rows.Close()

		var nonces [][]byte
		for rows.Next() {
			var nonce []byte
			require.NoError(t, rows.Scan(&nonce))
			nonces = append(nonces, nonce)
		}

		require.Len(t, nonces, 2)

		// Nonces must be different even for same plaintext.
		assert.NotEqual(t, nonces[0], nonces[1],
			"nonces must be unique to prevent cryptographic attacks")

		t.Logf("Verified nonces are unique: %x vs %x", nonces[0][:4], nonces[1][:4])
	})

	t.Run("Verify base64 encoding in API response", func(t *testing.T) {
		getReq := &pb.GetSecretRequest{
			SecretId: secretID,
		}

		getResp, err := server.secretsClient.GetSecret(authCtx, getReq)
		require.NoError(t, err)

		// Verify encrypted_data is valid base64.
		decoded, err := base64.StdEncoding.DecodeString(getResp.Secret.EncryptedData)
		require.NoError(t, err, "encrypted_data should be valid base64")

		// Verify decoded contains nonce + ciphertext.
		assert.GreaterOrEqual(t, len(decoded), crypto.NonceSize+16,
			"decoded data should contain nonce + ciphertext + GCM tag (16 bytes)")

		t.Logf("Verified API response contains valid base64-encoded encrypted data")
	})
}

package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"

	"github.com/koyif/keyper/internal/crypto"
	"github.com/koyif/keyper/internal/server/testhelpers"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// TestUser represents a registered user with authentication credentials.
type TestUser struct {
	Email         string
	Password      string
	UserID        string
	AccessToken   string
	RefreshToken  string
	EncryptionKey []byte
	AuthCtx       context.Context
	DeviceID      string
	ExpiresAt     time.Time
}

// TestSecret represents a test secret with encrypted data.
type TestSecret struct {
	ID            string
	Title         string
	Type          pb.SecretType
	EncryptedData string
	Version       int64
	Data          interface{}
}

// CreateTestUser creates and registers a new test user with the given email and password.
// Returns a TestUser with authentication tokens and encryption key.
func CreateTestUser(t *testing.T, authClient pb.AuthServiceClient, email, password string) *TestUser {
	t.Helper()

	return CreateTestUserWithDevice(t, authClient, email, password, fmt.Sprintf("test-device-%s", randomString(8)))
}

// CreateTestUserWithDevice creates a test user with a specific device ID.
func CreateTestUserWithDevice(t *testing.T, authClient pb.AuthServiceClient, email, password, deviceID string) *TestUser {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Register the user.
	registerReq := &pb.RegisterRequest{
		Username:       email,
		MasterPassword: password,
		DeviceInfo:     deviceID,
	}

	registerResp, err := authClient.Register(ctx, registerReq)
	require.NoError(t, err, "failed to register user %s", email)
	require.NotNil(t, registerResp)

	// Derive encryption key from master password (client-side operation).
	salt, err := crypto.GenerateSalt(crypto.SaltLength)
	require.NoError(t, err, "failed to generate salt")
	encryptionKey := crypto.DeriveKey(password, salt)

	// Create authenticated context with access token.
	authCtx := metadata.AppendToOutgoingContext(
		context.Background(),
		"authorization", "Bearer "+registerResp.AccessToken,
		"x-device-id", deviceID,
	)

	return &TestUser{
		Email:         email,
		Password:      password,
		UserID:        registerResp.UserId,
		AccessToken:   registerResp.AccessToken,
		RefreshToken:  registerResp.RefreshToken,
		EncryptionKey: encryptionKey,
		AuthCtx:       authCtx,
		DeviceID:      deviceID,
		ExpiresAt:     registerResp.ExpiresAt.AsTime(),
	}
}

// LoginTestUser logs in an existing user and returns authentication tokens.
func LoginTestUser(t *testing.T, authClient pb.AuthServiceClient, email, password string) *TestUser {
	t.Helper()

	return LoginTestUserWithDevice(t, authClient, email, password, fmt.Sprintf("test-device-%s", randomString(8)))
}

// LoginTestUserWithDevice logs in a user with a specific device ID.
func LoginTestUserWithDevice(t *testing.T, authClient pb.AuthServiceClient, email, password, deviceID string) *TestUser {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Login the user.
	loginReq := &pb.LoginRequest{
		Username:       email,
		MasterPassword: password,
		DeviceInfo:     deviceID,
	}

	loginResp, err := authClient.Login(ctx, loginReq)
	require.NoError(t, err, "failed to login user %s", email)
	require.NotNil(t, loginResp)

	// Derive encryption key from master password.
	salt, err := crypto.GenerateSalt(crypto.SaltLength)
	require.NoError(t, err, "failed to generate salt")
	encryptionKey := crypto.DeriveKey(password, salt)

	// Create authenticated context.
	authCtx := metadata.AppendToOutgoingContext(
		context.Background(),
		"authorization", "Bearer "+loginResp.AccessToken,
		"x-device-id", deviceID,
	)

	return &TestUser{
		Email:         email,
		Password:      password,
		UserID:        loginResp.UserId,
		AccessToken:   loginResp.AccessToken,
		RefreshToken:  loginResp.RefreshToken,
		EncryptionKey: encryptionKey,
		AuthCtx:       authCtx,
		DeviceID:      deviceID,
		ExpiresAt:     loginResp.ExpiresAt.AsTime(),
	}
}

// CreateTestSecret creates a test secret for the authenticated user.
func CreateTestSecret(t *testing.T, secretsClient pb.SecretsServiceClient, user *TestUser, secretType pb.SecretType, data interface{}) *TestSecret {
	t.Helper()

	title := fmt.Sprintf("Test %s Secret %s", secretType.String(), randomString(8))
	return CreateTestSecretWithTitle(t, secretsClient, user, secretType, title, data)
}

// CreateTestSecretWithTitle creates a test secret with a specific title.
func CreateTestSecretWithTitle(t *testing.T, secretsClient pb.SecretsServiceClient, user *TestUser, secretType pb.SecretType, title string, data interface{}) *TestSecret {
	t.Helper()

	// Encrypt the data.
	encryptedData := encryptData(t, data, user.EncryptionKey)

	// Create the secret.
	ctx, cancel := context.WithTimeout(user.AuthCtx, testTimeout)
	defer cancel()

	createReq := &pb.CreateSecretRequest{
		Type:          secretType,
		Title:         title,
		EncryptedData: encryptedData,
	}

	createResp, err := secretsClient.CreateSecret(ctx, createReq)
	require.NoError(t, err, "failed to create secret")
	require.NotNil(t, createResp)

	return &TestSecret{
		ID:            createResp.Secret.Id,
		Title:         createResp.Secret.Title,
		Type:          createResp.Secret.Type,
		EncryptedData: createResp.Secret.EncryptedData,
		Version:       createResp.Secret.Version,
		Data:          data,
	}
}

// CreateCredentialSecret creates a test credential secret with sample data.
func CreateCredentialSecret(t *testing.T, secretsClient pb.SecretsServiceClient, user *TestUser) *TestSecret {
	t.Helper()

	data := &pb.CredentialData{
		Username: fmt.Sprintf("user-%s", randomString(6)),
		Password: randomString(16),
		Email:    fmt.Sprintf("test-%s@example.com", randomString(6)),
		Url:      fmt.Sprintf("https://example-%s.com", randomString(6)),
	}

	return CreateTestSecret(t, secretsClient, user, pb.SecretType_SECRET_TYPE_CREDENTIAL, data)
}

// CreateTextSecret creates a test text secret with sample data.
func CreateTextSecret(t *testing.T, secretsClient pb.SecretsServiceClient, user *TestUser) *TestSecret {
	t.Helper()

	data := &pb.TextData{
		Content: fmt.Sprintf("Test note content %s", randomString(20)),
	}

	return CreateTestSecret(t, secretsClient, user, pb.SecretType_SECRET_TYPE_TEXT, data)
}

// CreateBinarySecret creates a test binary secret with sample data.
func CreateBinarySecret(t *testing.T, secretsClient pb.SecretsServiceClient, user *TestUser) *TestSecret {
	t.Helper()

	data := &pb.BinaryData{
		Filename: fmt.Sprintf("file-%s.bin", randomString(6)),
		MimeType: "application/octet-stream",
		Size:     1024,
		Data:     randomBytes(1024),
	}

	return CreateTestSecret(t, secretsClient, user, pb.SecretType_SECRET_TYPE_BINARY, data)
}

// CreateBankCardSecret creates a test bank card secret with sample data.
func CreateBankCardSecret(t *testing.T, secretsClient pb.SecretsServiceClient, user *TestUser) *TestSecret {
	t.Helper()

	data := &pb.BankCardData{
		CardholderName: fmt.Sprintf("Test User %s", randomString(6)),
		CardNumber:     fmt.Sprintf("4532-%s-%s-%s", randomNumString(4), randomNumString(4), randomNumString(4)),
		ExpiryMonth:    "12",
		ExpiryYear:     "2030",
		Cvv:            randomNumString(3),
		Pin:            randomNumString(4),
		BankName:       fmt.Sprintf("Test Bank %s", randomString(6)),
	}

	return CreateTestSecret(t, secretsClient, user, pb.SecretType_SECRET_TYPE_BANK_CARD, data)
}

// SetupAuthenticatedClient creates a test user and returns the authenticated user object.
// This is a convenience function that combines CreateTestUser with device setup.
func SetupAuthenticatedClient(t *testing.T, authClient pb.AuthServiceClient, userID string) *TestUser {
	t.Helper()

	// For this helper, we'll create a new user with a deterministic email based on userID.
	email := fmt.Sprintf("user-%s@test.example.com", userID)
	password := fmt.Sprintf("password-%s", userID)

	return CreateTestUser(t, authClient, email, password)
}

// CleanupDatabase truncates all test tables to ensure test isolation.
func CleanupDatabase(ctx context.Context, t *testing.T, tc *testhelpers.TestContainer) {
	t.Helper()

	tables := []string{
		"secrets",
		"refresh_tokens",
		"users",
	}

	tc.Truncate(ctx, t, tables...)
	t.Log("Database cleaned up successfully")
}

// GenerateTestToken generates a random test token for testing.
func GenerateTestToken() string {
	return randomString(32)
}

// WaitForSync adds a small delay to ensure database operations have propagated.
// Useful for tests that need to verify timing-dependent behavior.
func WaitForSync(duration time.Duration) {
	time.Sleep(duration)
}

// encryptData encrypts test data using the provided encryption key.
func encryptData(t *testing.T, data interface{}, encryptionKey []byte) string {
	t.Helper()

	plaintext, err := json.Marshal(data)
	require.NoError(t, err, "failed to marshal data")

	encrypted, err := crypto.Encrypt(plaintext, encryptionKey)
	require.NoError(t, err, "failed to encrypt data")

	return encrypted
}

// DecryptData decrypts encrypted data and unmarshals it into the result.
func DecryptData(t *testing.T, encryptedData string, encryptionKey []byte, result interface{}) {
	t.Helper()

	plaintext, err := crypto.Decrypt(encryptedData, encryptionKey)
	require.NoError(t, err, "failed to decrypt data")

	err = json.Unmarshal(plaintext, result)
	require.NoError(t, err, "failed to unmarshal decrypted data")
}

// randomString generates a random alphanumeric string of the specified length.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random string: %v", err))
	}

	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b)
}

// randomNumString generates a random numeric string of the specified length.
func randomNumString(length int) string {
	const charset = "0123456789"
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random number string: %v", err))
	}

	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}

	return string(b)
}

// randomBytes generates random bytes of the specified length.
func randomBytes(length int) []byte {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		panic(fmt.Sprintf("failed to generate random bytes: %v", err))
	}
	return b
}

// CreateTestSecretForSync creates a secret suitable for sync testing.
// This creates a pb.Secret object (not via the Secrets service) for use with Push/Pull.
func CreateTestSecretForSync(t *testing.T, user *TestUser, secretType pb.SecretType, data interface{}) *pb.Secret {
	t.Helper()

	encryptedData := encryptData(t, data, user.EncryptionKey)

	return &pb.Secret{
		Id:            uuid.New().String(),
		UserId:        user.UserID,
		Title:         fmt.Sprintf("Sync Test %s %s", secretType.String(), randomString(6)),
		Type:          secretType,
		EncryptedData: encryptedData,
		Version:       0, // New secret for sync.
		IsDeleted:     false,
	}
}

// BatchCreateSecrets creates multiple test secrets of random types.
func BatchCreateSecrets(t *testing.T, secretsClient pb.SecretsServiceClient, user *TestUser, count int) []*TestSecret {
	t.Helper()

	secrets := make([]*TestSecret, 0, count)

	for i := 0; i < count; i++ {
		// Rotate through different secret types.
		var secret *TestSecret

		switch i % 4 {
		case 0:
			secret = CreateCredentialSecret(t, secretsClient, user)
		case 1:
			secret = CreateTextSecret(t, secretsClient, user)
		case 2:
			secret = CreateBinarySecret(t, secretsClient, user)
		case 3:
			secret = CreateBankCardSecret(t, secretsClient, user)
		}

		secrets = append(secrets, secret)
	}

	return secrets
}

// CreateMetadata creates sample metadata for testing.
func CreateMetadata(category string, tags []string) *pb.Metadata {
	return &pb.Metadata{
		Category:   category,
		Tags:       tags,
		Notes:      fmt.Sprintf("Test notes for %s", category),
		IsFavorite: false,
	}
}

// AssertSecretsEqual asserts that two secrets have the same essential fields.
func AssertSecretsEqual(t *testing.T, expected, actual *pb.Secret) {
	t.Helper()

	require.Equal(t, expected.Id, actual.Id, "secret IDs should match")
	require.Equal(t, expected.Title, actual.Title, "titles should match")
	require.Equal(t, expected.Type, actual.Type, "types should match")
	require.Equal(t, expected.EncryptedData, actual.EncryptedData, "encrypted data should match")
	require.Equal(t, expected.IsDeleted, actual.IsDeleted, "deleted status should match")
}

// GetSecretsByType filters secrets by type.
func GetSecretsByType(secrets []*pb.Secret, secretType pb.SecretType) []*pb.Secret {
	filtered := make([]*pb.Secret, 0)
	for _, s := range secrets {
		if s.Type == secretType {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// GetSecretByID finds a secret by ID in a slice.
func GetSecretByID(secrets []*pb.Secret, id string) *pb.Secret {
	for _, s := range secrets {
		if s.Id == id {
			return s
		}
	}
	return nil
}

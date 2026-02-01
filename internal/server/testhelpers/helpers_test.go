package testhelpers

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koyif/keyper/internal/server/repository"
)

func TestTestDB_CreateTestUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateTestUser("test@example.com", "hash123")

	assert.NotEqual(t, uuid.Nil, user.ID, "user ID should be set")
	assert.Equal(t, "test@example.com", user.Email, "email should match")
	assert.Equal(t, []byte("hash123"), user.PasswordHash, "password hash should match")
	assert.NotZero(t, user.CreatedAt, "created_at should be set")
	assert.NotZero(t, user.UpdatedAt, "updated_at should be set")
}

func TestTestDB_CreateRandomTestUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user1 := db.CreateRandomTestUser()
	user2 := db.CreateRandomTestUser()

	assert.NotEqual(t, uuid.Nil, user1.ID, "user1 ID should be set")
	assert.NotEqual(t, uuid.Nil, user2.ID, "user2 ID should be set")
	assert.NotEqual(t, user1.ID, user2.ID, "users should have different IDs")
	assert.NotEqual(t, user1.Email, user2.Email, "users should have different emails")
}

func TestTestDB_CreateTestSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	secret := db.CreateTestSecret(user.ID, "My Secret")

	assert.NotEqual(t, uuid.Nil, secret.ID, "secret ID should be set")
	assert.Equal(t, user.ID, secret.UserID, "user ID should match")
	assert.Equal(t, "My Secret", secret.Name, "name should match")
	assert.Equal(t, int32(1), secret.Type, "type should be CREDENTIAL")
	assert.Equal(t, int64(1), secret.Version, "version should be 1")
	assert.False(t, secret.IsDeleted, "should not be deleted")
	assert.NotZero(t, secret.CreatedAt, "created_at should be set")
	assert.NotZero(t, secret.UpdatedAt, "updated_at should be set")
}

func TestTestDB_CreateTestSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	secrets := db.CreateTestSecrets(user.ID, 5)

	require.Len(t, secrets, 5, "should create 5 secrets")

	for i, secret := range secrets {
		assert.NotEqual(t, uuid.Nil, secret.ID, "secret %d ID should be set", i)
		assert.Equal(t, user.ID, secret.UserID, "secret %d user ID should match", i)
		assert.Contains(t, secret.Name, "Test Secret", "secret %d name should contain 'Test Secret'", i)
	}

	// Verify all secrets are in database
	allSecrets := db.ListSecretsByUser(user.ID)
	assert.Len(t, allSecrets, 5, "should retrieve all 5 secrets")
}

func TestTestDB_CreateDeletedSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	secret := db.CreateDeletedSecret(user.ID, "Deleted Secret")

	assert.NotEqual(t, uuid.Nil, secret.ID, "secret ID should be set")

	// Verify it's deleted (Get should return ErrNotFound)
	db.AssertSecretNotFound(secret.ID)
}

func TestTestDB_Truncate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	// Create test data
	user := db.CreateRandomTestUser()
	db.CreateTestSecret(user.ID, "Secret 1")
	db.CreateTestSecret(user.ID, "Secret 2")

	// Verify data exists
	secrets := db.ListSecretsByUser(user.ID)
	assert.Len(t, secrets, 2, "should have 2 secrets before truncate")

	// Truncate secrets table
	db.Truncate("secrets")

	// Verify secrets are gone
	secrets = db.ListSecretsByUser(user.ID)
	assert.Len(t, secrets, 0, "should have 0 secrets after truncate")

	// User should still exist
	db.AssertUserExists(user.ID)
}

func TestTestDB_TruncateAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	// Create test data
	user := db.CreateRandomTestUser()
	db.CreateTestSecret(user.ID, "Secret")

	// Truncate all tables
	db.TruncateAll()

	// Verify all data is gone
	ctx := context.Background()
	var count int

	err := db.Pool().QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "users table should be empty")

	err = db.Pool().QueryRow(ctx, "SELECT COUNT(*) FROM secrets").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "secrets table should be empty")
}

func TestTestDB_GetSecretByID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	created := db.CreateTestSecret(user.ID, "My Secret")

	retrieved := db.GetSecretByID(created.ID)

	assert.Equal(t, created.ID, retrieved.ID, "IDs should match")
	assert.Equal(t, created.Name, retrieved.Name, "names should match")
	assert.Equal(t, created.Version, retrieved.Version, "versions should match")
}

func TestTestDB_GetUserByID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	created := db.CreateTestUser("test@example.com", "hash")

	retrieved := db.GetUserByID(created.ID)

	assert.Equal(t, created.ID, retrieved.ID, "IDs should match")
	assert.Equal(t, created.Email, retrieved.Email, "emails should match")
}

func TestTestDB_GetUserByEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	created := db.CreateTestUser("test@example.com", "hash")

	retrieved := db.GetUserByEmail("test@example.com")

	assert.Equal(t, created.ID, retrieved.ID, "IDs should match")
	assert.Equal(t, created.Email, retrieved.Email, "emails should match")
}

func TestTestDB_UpdateSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	secret := db.CreateTestSecret(user.ID, "Original Name")

	// Update the secret
	secret.Name = "Updated Name"
	secret.EncryptedData = []byte("new-encrypted-data")

	updated := db.UpdateSecret(secret)

	assert.Equal(t, secret.ID, updated.ID, "IDs should match")
	assert.Equal(t, "Updated Name", updated.Name, "name should be updated")
	assert.Equal(t, int64(2), updated.Version, "version should increment")
	assert.True(t, updated.UpdatedAt.After(secret.UpdatedAt), "updated_at should be newer")
}

func TestTestDB_DeleteSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	secret := db.CreateTestSecret(user.ID, "Secret to Delete")

	// Verify secret exists
	db.AssertSecretExists(secret.ID)

	// Delete the secret
	db.DeleteSecret(secret.ID, secret.Version)

	// Verify it's deleted
	db.AssertSecretDeleted(secret.ID)
}

func TestTestDB_ListSecretsByUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	db.CreateTestSecrets(user.ID, 3)

	secrets := db.ListSecretsByUser(user.ID)

	assert.Len(t, secrets, 3, "should retrieve 3 secrets")
}

func TestTestDB_ListModifiedSince(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()

	// Create initial secret
	secret1 := db.CreateTestSecret(user.ID, "Secret 1")
	time.Sleep(100 * time.Millisecond)

	// Record timestamp
	since := time.Now()
	time.Sleep(100 * time.Millisecond)

	// Create new secret after timestamp
	db.CreateTestSecret(user.ID, "Secret 2")

	// Update first secret
	secret1.Name = "Updated Secret 1"
	db.UpdateSecret(secret1)

	// List modified since timestamp
	secrets := db.ListModifiedSince(user.ID, since)

	assert.Len(t, secrets, 2, "should have 2 secrets modified after timestamp")
}

func TestTestDB_AssertSecretCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	db.CreateTestSecrets(user.ID, 5)

	// This should pass
	db.AssertSecretCount(user.ID, 5)
}

func TestTestDB_CountSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	db.CreateTestSecrets(user.ID, 3)

	count := db.CountSecrets(user.ID)

	assert.Equal(t, 3, count, "should count 3 secrets")
}

func TestTestDB_CreateRefreshToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	token := db.CreateRefreshToken(user.ID, "test-device")

	assert.NotEqual(t, uuid.Nil, token.ID, "token ID should be set")
	assert.Equal(t, user.ID, token.UserID, "user ID should match")
	assert.NotNil(t, token.DeviceID, "device ID should be set")
	assert.Equal(t, "test-device", *token.DeviceID, "device ID should match")
	assert.True(t, token.ExpiresAt.After(time.Now()), "token should not be expired")
}

func TestTestDB_MustExec(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()

	// Use MustExec to insert data
	db.MustExec(
		`INSERT INTO secrets (user_id, name, type, encrypted_data, nonce, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		user.ID, "Custom Secret", 1, []byte("data"), []byte("nonce123"), []byte(`{}`),
	)

	// Verify the secret was created
	secrets := db.ListSecretsByUser(user.ID)
	assert.Len(t, secrets, 1, "should have 1 secret")
	assert.Equal(t, "Custom Secret", secrets[0].Name, "name should match")
}

func TestTestDB_CreateTestSecretWithType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	secret := db.CreateTestSecretWithType(user.ID, "My Note", 2) // TEXT type

	assert.Equal(t, int32(2), secret.Type, "type should be TEXT")
	assert.Equal(t, "My Note", secret.Name, "name should match")
}

func TestTestDB_CreateTestSecretFull(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()

	customSecret := &repository.Secret{
		UserID:        user.ID,
		Name:          "Custom Full Secret",
		Type:          3, // BINARY
		EncryptedData: []byte("custom-encrypted-data"),
		Nonce:         []byte("custom-nonce"),
		Metadata:      []byte(`{"category":"important"}`),
	}

	created := db.CreateTestSecretFull(customSecret)

	assert.NotEqual(t, uuid.Nil, created.ID, "ID should be set")
	assert.Equal(t, "Custom Full Secret", created.Name, "name should match")
	assert.Equal(t, int32(3), created.Type, "type should match")
	assert.Equal(t, []byte("custom-encrypted-data"), created.EncryptedData, "encrypted data should match")
}

func TestTestDB_AssertSecretExists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()
	secret := db.CreateTestSecret(user.ID, "Existing Secret")

	// Should not panic or fail
	db.AssertSecretExists(secret.ID)
}

func TestTestDB_AssertSecretNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	nonExistentID := uuid.New()

	// Should not panic or fail
	db.AssertSecretNotFound(nonExistentID)
}

func TestTestDB_AssertUserExists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	user := db.CreateRandomTestUser()

	// Should not panic or fail
	db.AssertUserExists(user.ID)
}

func TestTestDB_CreateTestUserWithDetails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	db := NewTestDB(t)

	passwordHash := []byte("my-hash")
	encryptionKeyVerifier := []byte("my-verifier")
	salt := []byte("my-salt")

	user := db.CreateTestUserWithDetails("detailed@example.com", passwordHash, encryptionKeyVerifier, salt)

	assert.Equal(t, "detailed@example.com", user.Email, "email should match")
	assert.Equal(t, passwordHash, user.PasswordHash, "password hash should match")
	assert.Equal(t, encryptionKeyVerifier, user.EncryptionKeyVerifier, "encryption key verifier should match")
	assert.Equal(t, salt, user.Salt, "salt should match")
}

package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/config"
	"github.com/koyif/keyper/internal/server/repository"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// testServices holds common test dependencies.
type testServices struct {
	pool        *pgxpool.Pool
	secretRepo  *postgres.SecretRepository
	userRepo    *postgres.UserRepository
	transactor  *postgres.Transactor
	syncService *SyncService
}

// setupSyncServiceTest initializes test services and database.
func setupSyncServiceTest(t *testing.T) *testServices {
	t.Helper()

	pool := setupTestDB(t)
	secretRepo := postgres.NewSecretRepository(pool)
	userRepo := postgres.NewUserRepository(pool)
	transactor := postgres.NewTransactor(pool)
	syncService := NewSyncService(secretRepo, transactor, config.DefaultLimits())

	return &testServices{
		pool:        pool,
		secretRepo:  secretRepo,
		userRepo:    userRepo,
		transactor:  transactor,
		syncService: syncService,
	}
}

// setupTestContext creates a context with user ID and device ID.
func setupTestContext(userID uuid.UUID, deviceID string) context.Context {
	ctx := context.Background()
	ctx = context.WithValue(ctx, auth.UserIDContextKey, userID.String())
	if deviceID != "" {
		ctx = context.WithValue(ctx, auth.DeviceIDContextKey, deviceID)
	}
	return ctx
}

// TestSyncService_Pull tests the Pull operation.
func TestSyncService_Pull(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "test-device")

	// Create some test secrets.
	secret1 := &repository.Secret{
		UserID:        user.ID,
		Name:          "Secret 1",
		Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
		EncryptedData: []byte("encrypted1"),
		Nonce:         []byte("nonce1234567"),
		Metadata:      []byte(`{"category":"work"}`),
	}
	created1, err := ts.secretRepo.Create(ctx, secret1)
	require.NoError(t, err)

	secret2 := &repository.Secret{
		UserID:        user.ID,
		Name:          "Secret 2",
		Type:          int32(pb.SecretType_SECRET_TYPE_TEXT),
		EncryptedData: []byte("encrypted2"),
		Nonce:         []byte("nonce2345678"),
		Metadata:      []byte(`{"category":"personal"}`),
	}
	created2, err := ts.secretRepo.Create(ctx, secret2)
	require.NoError(t, err)

	// Delete one secret.
	err = ts.secretRepo.Delete(ctx, created2.ID, created2.Version)
	require.NoError(t, err)

	// Pull changes since epoch.
	req := &pb.PullRequest{
		LastSyncTime: timestamppb.New(time.Unix(0, 0)),
	}

	resp, err := ts.syncService.Pull(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should have 1 active secret and 1 deleted.
	assert.Len(t, resp.Secrets, 1)
	assert.Len(t, resp.DeletedSecretIds, 1)

	// Verify active secret.
	assert.Equal(t, created1.ID.String(), resp.Secrets[0].Id)
	assert.Equal(t, "Secret 1", resp.Secrets[0].Title)

	// Verify deleted secret ID.
	assert.Equal(t, created2.ID.String(), resp.DeletedSecretIds[0])

	// Should have sync time.
	assert.NotNil(t, resp.SyncTime)
}

// TestSyncService_Pull_NoChanges tests Pull with no changes since last sync.
func TestSyncService_Pull_NoChanges(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "")

	// Create a secret.
	secret := &repository.Secret{
		UserID:        user.ID,
		Name:          "Secret",
		Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
		EncryptedData: []byte("encrypted"),
		Nonce:         []byte("nonce1234567"),
		Metadata:      []byte(`{}`),
	}
	created, err := ts.secretRepo.Create(ctx, secret)
	require.NoError(t, err)

	// Pull changes after the secret was created.
	req := &pb.PullRequest{
		LastSyncTime: timestamppb.New(created.UpdatedAt.Add(1 * time.Second)),
	}

	resp, err := ts.syncService.Pull(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should have no changes.
	assert.Empty(t, resp.Secrets)
	assert.Empty(t, resp.DeletedSecretIds)
}

// TestSyncService_Push_Create tests Push operation for creating new secrets.
func TestSyncService_Push_Create(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "")

	// Prepare encrypted data with nonce.
	nonce := []byte("nonce1234567")
	ciphertext := []byte("encrypted_data")
	encryptedData := append(nonce, ciphertext...)
	encryptedDataB64 := base64.StdEncoding.EncodeToString(encryptedData)

	// Create metadata.
	metadata := &pb.Metadata{
		Category:   "work",
		Tags:       []string{"important"},
		IsFavorite: true,
	}

	// Push new secret.
	newSecretID := uuid.New()
	req := &pb.PushRequest{
		Secrets: []*pb.Secret{
			{
				Id:            newSecretID.String(),
				Title:         "New Secret",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				EncryptedData: encryptedDataB64,
				Metadata:      metadata,
				Version:       0, // New secret.
			},
		},
	}

	resp, err := ts.syncService.Push(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should have accepted the new secret.
	assert.Len(t, resp.AcceptedSecretIds, 1)
	assert.Empty(t, resp.Conflicts)
	assert.Contains(t, resp.AcceptedSecretIds, newSecretID.String())

	// Verify secret was created in database.
	created, err := ts.secretRepo.Get(ctx, newSecretID)
	require.NoError(t, err)
	assert.Equal(t, "New Secret", created.Name)
	assert.Equal(t, int64(1), created.Version)
}

// TestSyncService_Push_Update tests Push operation for updating existing secrets.
func TestSyncService_Push_Update(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "")

	// Create initial secret.
	secret := &repository.Secret{
		UserID:        user.ID,
		Name:          "Original Name",
		Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
		EncryptedData: []byte("original_data"),
		Nonce:         []byte("nonce1234567"),
		Metadata:      []byte(`{}`),
	}
	created, err := ts.secretRepo.Create(ctx, secret)
	require.NoError(t, err)

	// Prepare updated encrypted data.
	nonce := []byte("nonce9876543")
	ciphertext := []byte("updated_data")
	encryptedData := append(nonce, ciphertext...)
	encryptedDataB64 := base64.StdEncoding.EncodeToString(encryptedData)

	// Push update with correct version.
	req := &pb.PushRequest{
		Secrets: []*pb.Secret{
			{
				Id:            created.ID.String(),
				Title:         "Updated Name",
				Type:          pb.SecretType_SECRET_TYPE_TEXT,
				EncryptedData: encryptedDataB64,
				Version:       created.Version,
			},
		},
	}

	resp, err := ts.syncService.Push(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should have accepted the update.
	assert.Len(t, resp.AcceptedSecretIds, 1)
	assert.Empty(t, resp.Conflicts)

	// Verify secret was updated.
	updated, err := ts.secretRepo.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.Name)
	assert.Equal(t, int64(2), updated.Version) // Version incremented.
}

// TestSyncService_Push_VersionConflict tests Push operation with version conflict.
func TestSyncService_Push_VersionConflict(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "")

	// Create initial secret.
	secret := &repository.Secret{
		UserID:        user.ID,
		Name:          "Original",
		Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce1234567"),
		Metadata:      []byte(`{}`),
	}
	created, err := ts.secretRepo.Create(ctx, secret)
	require.NoError(t, err)

	// Update the secret on server side.
	created.Name = "Server Updated"
	updated, err := ts.secretRepo.Update(ctx, created)
	require.NoError(t, err)
	assert.Equal(t, int64(2), updated.Version)

	// Try to push update with old version (conflict).
	nonce := []byte("nonce9876543")
	ciphertext := []byte("client_data")
	encryptedData := append(nonce, ciphertext...)
	encryptedDataB64 := base64.StdEncoding.EncodeToString(encryptedData)

	req := &pb.PushRequest{
		Secrets: []*pb.Secret{
			{
				Id:            created.ID.String(),
				Title:         "Client Updated",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				EncryptedData: encryptedDataB64,
				Version:       1, // Old version.
			},
		},
	}

	resp, err := ts.syncService.Push(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should have conflict, no accepted updates.
	assert.Empty(t, resp.AcceptedSecretIds)
	assert.Len(t, resp.Conflicts, 1)

	// Verify conflict details.
	conflict := resp.Conflicts[0]
	assert.Equal(t, created.ID.String(), conflict.SecretId)
	assert.Equal(t, pb.ConflictType_CONFLICT_TYPE_VERSION_MISMATCH, conflict.Type)
	assert.NotNil(t, conflict.ServerVersion)
	assert.Equal(t, int64(2), conflict.ServerVersion.Version)
}

// TestSyncService_Push_Delete tests Push operation for deleting secrets.
func TestSyncService_Push_Delete(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "")

	// Create secret.
	secret := &repository.Secret{
		UserID:        user.ID,
		Name:          "To Delete",
		Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce1234567"),
		Metadata:      []byte(`{}`),
	}
	created, err := ts.secretRepo.Create(ctx, secret)
	require.NoError(t, err)

	// Push delete.
	req := &pb.PushRequest{
		DeletedSecretIds: []string{created.ID.String()},
	}

	resp, err := ts.syncService.Push(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should have accepted the delete.
	assert.Contains(t, resp.AcceptedSecretIds, created.ID.String())
	assert.Empty(t, resp.Conflicts)

	// Verify secret was soft-deleted.
	_, err = ts.secretRepo.Get(ctx, created.ID)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

// TestSyncService_Push_DeleteAlreadyDeleted tests Push operation deleting already deleted secret.
func TestSyncService_Push_DeleteAlreadyDeleted(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "")

	// Create and delete secret.
	secret := &repository.Secret{
		UserID:        user.ID,
		Name:          "Deleted",
		Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce1234567"),
		Metadata:      []byte(`{}`),
	}
	created, err := ts.secretRepo.Create(ctx, secret)
	require.NoError(t, err)

	err = ts.secretRepo.Delete(ctx, created.ID, created.Version)
	require.NoError(t, err)

	// Try to delete again.
	req := &pb.PushRequest{
		DeletedSecretIds: []string{created.ID.String()},
	}

	resp, err := ts.syncService.Push(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Should accept (idempotent delete).
	assert.Contains(t, resp.AcceptedSecretIds, created.ID.String())
	assert.Empty(t, resp.Conflicts)
}

// TestSyncService_Push_MultipleOperations tests Push with multiple operations in one request.
func TestSyncService_Push_MultipleOperations(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "")

	// Create existing secret.
	existing := &repository.Secret{
		UserID:        user.ID,
		Name:          "Existing",
		Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce1234567"),
		Metadata:      []byte(`{}`),
	}
	created, err := ts.secretRepo.Create(ctx, existing)
	require.NoError(t, err)

	// Prepare new secret.
	newID := uuid.New()
	nonce1 := []byte("nonce1111111")
	encData1 := base64.StdEncoding.EncodeToString(append(nonce1, []byte("new_data")...))

	// Prepare update.
	nonce2 := []byte("nonce2222222")
	encData2 := base64.StdEncoding.EncodeToString(append(nonce2, []byte("updated_data")...))

	// Push: create new, update existing, delete another.
	toDelete := &repository.Secret{
		UserID:        user.ID,
		Name:          "To Delete",
		Type:          int32(pb.SecretType_SECRET_TYPE_TEXT),
		EncryptedData: []byte("delete_data"),
		Nonce:         []byte("nonce3333333"),
		Metadata:      []byte(`{}`),
	}
	createdToDelete, err := ts.secretRepo.Create(ctx, toDelete)
	require.NoError(t, err)

	req := &pb.PushRequest{
		Secrets: []*pb.Secret{
			{
				Id:            newID.String(),
				Title:         "New Secret",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				EncryptedData: encData1,
				Version:       0,
			},
			{
				Id:            created.ID.String(),
				Title:         "Updated Existing",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				EncryptedData: encData2,
				Version:       created.Version,
			},
		},
		DeletedSecretIds: []string{createdToDelete.ID.String()},
	}

	resp, err := ts.syncService.Push(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// All operations should succeed.
	assert.Len(t, resp.AcceptedSecretIds, 3)
	assert.Empty(t, resp.Conflicts)

	// Verify new secret created.
	newSecret, err := ts.secretRepo.Get(ctx, newID)
	require.NoError(t, err)
	assert.Equal(t, "New Secret", newSecret.Name)

	// Verify existing secret updated.
	updatedSecret, err := ts.secretRepo.Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Existing", updatedSecret.Name)

	// Verify secret deleted.
	_, err = ts.secretRepo.Get(ctx, createdToDelete.ID)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

// TestSyncService_GetSyncStatus tests the GetSyncStatus operation.
func TestSyncService_GetSyncStatus(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "")
	ctx = context.WithValue(ctx, auth.DeviceIDContextKey, "test-device")

	// Create some secrets.
	for i := 0; i < 3; i++ {
		secret := &repository.Secret{
			UserID:        user.ID,
			Name:          "Secret",
			Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
			EncryptedData: []byte("data"),
			Nonce:         []byte("nonce1234567"),
			Metadata:      []byte(`{}`),
		}
		_, err := ts.secretRepo.Create(ctx, secret)
		require.NoError(t, err)
	}

	req := &pb.GetSyncStatusRequest{}

	resp, err := ts.syncService.GetSyncStatus(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, int32(3), resp.TotalSecrets)
	assert.Equal(t, int32(0), resp.PendingChanges)
	assert.NotNil(t, resp.LastSyncTime)
}

// TestSyncService_Pull_Unauthenticated tests Pull without authentication.
func TestSyncService_Pull_Unauthenticated(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	ctx := context.Background()
	// No user ID in context.

	req := &pb.PullRequest{
		LastSyncTime: timestamppb.Now(),
	}

	_, err := ts.syncService.Pull(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

// TestSyncService_Push_InvalidSecretID tests Push with invalid secret ID.
func TestSyncService_Push_InvalidSecretID(t *testing.T) {
	ts := setupSyncServiceTest(t)
	defer ts.pool.Close()

	// Create test user.
	user := createTestUser(context.Background(), t, ts.userRepo)
	ctx := setupTestContext(user.ID, "")

	nonce := []byte("nonce1234567")
	encData := base64.StdEncoding.EncodeToString(append(nonce, []byte("data")...))

	req := &pb.PushRequest{
		Secrets: []*pb.Secret{
			{
				Id:            "invalid-uuid",
				Title:         "Test",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				EncryptedData: encData,
				Version:       1,
			},
		},
	}

	resp, err := ts.syncService.Push(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Invalid ID should be skipped.
	assert.Empty(t, resp.AcceptedSecretIds)
	assert.Empty(t, resp.Conflicts)
}

// setupTestDB creates a test database pool and ensures cleanup.
// Note: This requires TEST_POSTGRES_* environment variables or uses defaults.
func setupTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	host := getEnvOrDefault("TEST_POSTGRES_HOST", "localhost")
	port := getEnvOrDefault("TEST_POSTGRES_PORT", "5432")
	user := getEnvOrDefault("TEST_POSTGRES_USER", "keyper")
	password := getEnvOrDefault("TEST_POSTGRES_PASSWORD", "keyper_dev_password")
	database := getEnvOrDefault("TEST_POSTGRES_DB", "keyper_test")
	sslMode := getEnvOrDefault("TEST_POSTGRES_SSL_MODE", "disable")

	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=%s",
		user, password, host, port, database, sslMode,
	)

	poolConfig, err := pgxpool.ParseConfig(connString)
	require.NoError(t, err)

	poolConfig.MaxConns = 5
	poolConfig.MinConns = 1
	poolConfig.MaxConnLifetime = 10 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute

	ctx := context.Background()
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	require.NoError(t, err)

	require.NoError(t, pool.Ping(ctx))

	// Clean up test data.
	cleanupTestData(t, pool)

	return pool
}

// cleanupTestData removes all test data from the database.
func cleanupTestData(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx := context.Background()
	queries := []string{
		"DELETE FROM refresh_tokens",
		"DELETE FROM secrets",
		"DELETE FROM users",
	}

	for _, query := range queries {
		_, err := pool.Exec(ctx, query)
		require.NoError(t, err)
	}
}

// getEnvOrDefault returns the value of an environment variable or a default value.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// createTestUser is a helper function to create a test user in the database.
func createTestUser(ctx context.Context, t *testing.T, repo *postgres.UserRepository) *repository.User {
	t.Helper()

	email := uuid.New().String() + "@example.com"
	user, err := repo.CreateUser(ctx, email, []byte("hash"), []byte("verifier"), []byte("salt"))
	require.NoError(t, err)

	return user
}

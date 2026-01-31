package handlers

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/config"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	"github.com/koyif/keyper/internal/server/testhelpers"
	pb "github.com/koyif/keyper/pkg/api/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// createTestEncryptedData creates valid encrypted data for testing (12-byte nonce + ciphertext).
func createTestEncryptedData() string {
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	ciphertext := []byte("this_is_test_encrypted_data_content")
	combined := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(combined)
}

// setupSecretsTest creates a test database, service, and a test user.
// Returns the database, service, user ID, and authenticated context.
func setupSecretsTest(t *testing.T) (*testhelpers.TestDB, *SecretsService, uuid.UUID, context.Context) {
	t.Helper()

	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	secretRepo := postgres.NewSecretRepository(pool)
	service := NewSecretsService(secretRepo, config.DefaultLimits())

	// Create a test user to satisfy foreign key constraints
	user := db.CreateRandomTestUser()
	ctx := context.WithValue(context.Background(), auth.UserIDContextKey, user.ID.String())

	return db, service, user.ID, ctx
}

// TestSecretsService_CreateSecret_Validation tests input validation for CreateSecret.
func TestSecretsService_CreateSecret_Validation(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	tests := []struct {
		name    string
		req     *pb.CreateSecretRequest
		wantErr bool
		errCode codes.Code
		errMsg  string
	}{
		{
			name: "empty title",
			req: &pb.CreateSecretRequest{
				Title:         "",
				EncryptedData: createTestEncryptedData(),
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
			errMsg:  "title is required",
		},
		{
			name: "empty encrypted data",
			req: &pb.CreateSecretRequest{
				Title:         "Test Secret",
				EncryptedData: "",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
			errMsg:  "encrypted_data is required",
		},
		{
			name: "unspecified type",
			req: &pb.CreateSecretRequest{
				Title:         "Test Secret",
				EncryptedData: createTestEncryptedData(),
				Type:          pb.SecretType_SECRET_TYPE_UNSPECIFIED,
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
			errMsg:  "secret type must be specified",
		},
		{
			name: "invalid base64",
			req: &pb.CreateSecretRequest{
				Title:         "Test Secret",
				EncryptedData: "not-valid-base64!!!",
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
			errMsg:  "invalid base64",
		},
		{
			name: "encrypted data too short",
			req: &pb.CreateSecretRequest{
				Title:         "Test Secret",
				EncryptedData: base64.StdEncoding.EncodeToString([]byte("short")),
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
			errMsg:  "encrypted_data too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := service.CreateSecret(ctx, tt.req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.errCode, st.Code())
				assert.Contains(t, st.Message(), tt.errMsg)
			}
		})
	}
}

// TestSecretsService_CreateSecret_Success tests successful secret creation.
func TestSecretsService_CreateSecret_Success(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	req := &pb.CreateSecretRequest{
		Title:         "My Login Secret",
		EncryptedData: createTestEncryptedData(),
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
		Metadata: &pb.Metadata{
			Category:   "work",
			IsFavorite: true,
			Tags:       []string{"important", "production"},
			Notes:      "This is a test secret",
		},
	}

	resp, err := service.CreateSecret(ctx, req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Secret)
	assert.NotEmpty(t, resp.Secret.Id)
	assert.Equal(t, "My Login Secret", resp.Secret.Title)
	assert.Equal(t, pb.SecretType_SECRET_TYPE_CREDENTIAL, resp.Secret.Type)
	assert.Equal(t, int64(1), resp.Secret.Version)
	assert.Equal(t, "Secret created successfully", resp.Message)

	// Verify metadata
	assert.NotNil(t, resp.Secret.Metadata)
	assert.Equal(t, "work", resp.Secret.Metadata.Category)
	assert.True(t, resp.Secret.Metadata.IsFavorite)
	assert.Equal(t, []string{"important", "production"}, resp.Secret.Metadata.Tags)
}

// TestSecretsService_GetSecret_Success tests retrieving a secret by ID.
func TestSecretsService_GetSecret_Success(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	// Create a secret first
	createReq := &pb.CreateSecretRequest{
		Title:         "Secret to Get",
		EncryptedData: createTestEncryptedData(),
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
	}
	createResp, err := service.CreateSecret(ctx, createReq)
	require.NoError(t, err)

	// Get the secret
	getReq := &pb.GetSecretRequest{
		SecretId: createResp.Secret.Id,
	}

	getResp, err := service.GetSecret(ctx, getReq)

	require.NoError(t, err)
	assert.NotNil(t, getResp)
	assert.NotNil(t, getResp.Secret)
	assert.Equal(t, createResp.Secret.Id, getResp.Secret.Id)
	assert.Equal(t, "Secret to Get", getResp.Secret.Title)
}

// TestSecretsService_GetSecret_NotFound tests getting non-existent secret.
func TestSecretsService_GetSecret_NotFound(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	req := &pb.GetSecretRequest{
		SecretId: uuid.New().String(),
	}

	resp, err := service.GetSecret(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// TestSecretsService_GetSecret_PermissionDenied tests access control.
func TestSecretsService_GetSecret_PermissionDenied(t *testing.T) {
	db, service, _, ctx1 := setupSecretsTest(t)

	// Create a second user for permission testing
	user2 := db.CreateRandomTestUser()
	ctx2 := context.WithValue(context.Background(), auth.UserIDContextKey, user2.ID.String())

	// User 1 creates a secret
	createReq := &pb.CreateSecretRequest{
		Title:         "User1's Secret",
		EncryptedData: createTestEncryptedData(),
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
	}
	createResp, err := service.CreateSecret(ctx1, createReq)
	require.NoError(t, err)

	// User 2 tries to access User 1's secret
	getReq := &pb.GetSecretRequest{
		SecretId: createResp.Secret.Id,
	}

	getResp, err := service.GetSecret(ctx2, getReq)

	assert.Error(t, err)
	assert.Nil(t, getResp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	assert.Contains(t, st.Message(), "access denied")
}

// TestSecretsService_UpdateSecret_Success tests successful secret update.
func TestSecretsService_UpdateSecret_Success(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	// Create a secret
	createReq := &pb.CreateSecretRequest{
		Title:         "Original Title",
		EncryptedData: createTestEncryptedData(),
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
	}
	createResp, err := service.CreateSecret(ctx, createReq)
	require.NoError(t, err)

	// Update the secret
	updateReq := &pb.UpdateSecretRequest{
		SecretId:      createResp.Secret.Id,
		Title:         "Updated Title",
		EncryptedData: createTestEncryptedData(),
		Version:       createResp.Secret.Version,
		Metadata: &pb.Metadata{
			Category: "personal",
		},
	}

	updateResp, err := service.UpdateSecret(ctx, updateReq)

	require.NoError(t, err)
	assert.NotNil(t, updateResp)
	assert.NotNil(t, updateResp.Secret)
	assert.Equal(t, "Updated Title", updateResp.Secret.Title)
	assert.Equal(t, int64(2), updateResp.Secret.Version)
	assert.Equal(t, "Secret updated successfully", updateResp.Message)
}

// TestSecretsService_UpdateSecret_VersionConflict tests optimistic locking.
func TestSecretsService_UpdateSecret_VersionConflict(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	// Create a secret
	createReq := &pb.CreateSecretRequest{
		Title:         "Test Secret",
		EncryptedData: createTestEncryptedData(),
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
	}
	createResp, err := service.CreateSecret(ctx, createReq)
	require.NoError(t, err)

	// Update with current version (should succeed)
	updateReq1 := &pb.UpdateSecretRequest{
		SecretId:      createResp.Secret.Id,
		Title:         "First Update",
		EncryptedData: createTestEncryptedData(),
		Version:       1,
	}
	updateResp1, err := service.UpdateSecret(ctx, updateReq1)
	require.NoError(t, err)
	assert.Equal(t, int64(2), updateResp1.Secret.Version)

	// Try to update with old version (should fail with version conflict)
	updateReq2 := &pb.UpdateSecretRequest{
		SecretId:      createResp.Secret.Id,
		Title:         "Second Update",
		EncryptedData: createTestEncryptedData(),
		Version:       1, // Using old version
	}

	updateResp2, err := service.UpdateSecret(ctx, updateReq2)

	assert.Error(t, err)
	assert.Nil(t, updateResp2)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "version conflict")
}

// TestSecretsService_DeleteSecret_Success tests successful secret deletion.
func TestSecretsService_DeleteSecret_Success(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	// Create a secret
	createReq := &pb.CreateSecretRequest{
		Title:         "Secret to Delete",
		EncryptedData: createTestEncryptedData(),
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
	}
	createResp, err := service.CreateSecret(ctx, createReq)
	require.NoError(t, err)

	// Delete the secret
	deleteReq := &pb.DeleteSecretRequest{
		SecretId: createResp.Secret.Id,
	}

	deleteResp, err := service.DeleteSecret(ctx, deleteReq)

	require.NoError(t, err)
	assert.NotNil(t, deleteResp)
	assert.Equal(t, "Secret deleted successfully", deleteResp.Message)

	// Verify secret is soft-deleted (can't be retrieved)
	getReq := &pb.GetSecretRequest{
		SecretId: createResp.Secret.Id,
	}
	getResp, err := service.GetSecret(ctx, getReq)
	assert.Error(t, err)
	assert.Nil(t, getResp)
}

// TestSecretsService_ListSecrets_Success tests listing secrets with pagination.
func TestSecretsService_ListSecrets_Success(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	// Create multiple secrets
	for i := 0; i < 5; i++ {
		createReq := &pb.CreateSecretRequest{
			Title:         "Secret " + string(rune('A'+i)),
			EncryptedData: createTestEncryptedData(),
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
		}
		_, err := service.CreateSecret(ctx, createReq)
		require.NoError(t, err)
	}

	// List all secrets
	listReq := &pb.ListSecretsRequest{
		PageSize: 10,
	}

	listResp, err := service.ListSecrets(ctx, listReq)

	require.NoError(t, err)
	assert.NotNil(t, listResp)
	assert.Len(t, listResp.Secrets, 5)
	assert.Equal(t, int32(5), listResp.TotalCount)
}

// TestSecretsService_ListSecrets_Pagination tests pagination.
func TestSecretsService_ListSecrets_Pagination(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	// Create 15 secrets
	for i := 0; i < 15; i++ {
		createReq := &pb.CreateSecretRequest{
			Title:         "Paginated Secret " + string(rune('0'+i)),
			EncryptedData: createTestEncryptedData(),
			Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
		}
		_, err := service.CreateSecret(ctx, createReq)
		require.NoError(t, err)
	}

	// Get first page
	listReq1 := &pb.ListSecretsRequest{
		PageSize: 10,
	}

	listResp1, err := service.ListSecrets(ctx, listReq1)

	require.NoError(t, err)
	assert.Len(t, listResp1.Secrets, 10)
	assert.NotEmpty(t, listResp1.NextPageToken)

	// Get second page
	listReq2 := &pb.ListSecretsRequest{
		PageSize:  10,
		PageToken: listResp1.NextPageToken,
	}

	listResp2, err := service.ListSecrets(ctx, listReq2)

	require.NoError(t, err)
	assert.Len(t, listResp2.Secrets, 5)
	assert.Empty(t, listResp2.NextPageToken)
}

// TestSecretsService_SearchSecrets_Success tests searching secrets.
func TestSecretsService_SearchSecrets_Success(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	// Create secrets with different attributes
	secrets := []struct {
		title    string
		category string
		favorite bool
		tags     []string
		sType    pb.SecretType
	}{
		{"Work Email", "work", true, []string{"email", "important"}, pb.SecretType_SECRET_TYPE_CREDENTIAL},
		{"Personal Email", "personal", false, []string{"email"}, pb.SecretType_SECRET_TYPE_CREDENTIAL},
		{"Credit Card", "finance", true, []string{"important"}, pb.SecretType_SECRET_TYPE_BANK_CARD},
		{"Random Note", "personal", false, []string{}, pb.SecretType_SECRET_TYPE_TEXT},
	}

	for _, s := range secrets {
		createReq := &pb.CreateSecretRequest{
			Title:         s.title,
			EncryptedData: createTestEncryptedData(),
			Type:          s.sType,
			Metadata: &pb.Metadata{
				Category:   s.category,
				IsFavorite: s.favorite,
				Tags:       s.tags,
			},
		}
		_, err := service.CreateSecret(ctx, createReq)
		require.NoError(t, err)
	}

	tests := []struct {
		name          string
		searchReq     *pb.SearchSecretsRequest
		expectedCount int
	}{
		{
			name: "search by query",
			searchReq: &pb.SearchSecretsRequest{
				Query: "Email",
			},
			expectedCount: 2,
		},
		{
			name: "search by category",
			searchReq: &pb.SearchSecretsRequest{
				Category: "work",
			},
			expectedCount: 1,
		},
		{
			name: "search favorites only",
			searchReq: &pb.SearchSecretsRequest{
				FavoritesOnly: true,
			},
			expectedCount: 2,
		},
		{
			name: "search by type",
			searchReq: &pb.SearchSecretsRequest{
				Type: pb.SecretType_SECRET_TYPE_BANK_CARD,
			},
			expectedCount: 1,
		},
		{
			name: "search by tags",
			searchReq: &pb.SearchSecretsRequest{
				Tags: []string{"important"},
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			searchResp, err := service.SearchSecrets(ctx, tt.searchReq)

			require.NoError(t, err)
			assert.NotNil(t, searchResp)
			assert.Len(t, searchResp.Secrets, tt.expectedCount)
			assert.Equal(t, int32(tt.expectedCount), searchResp.TotalCount) //nolint:gosec // G115: Test code, expectedCount is small
		})
	}
}

// TestSecretsService_SearchSecrets_MultipleFilters tests combining multiple search filters.
func TestSecretsService_SearchSecrets_MultipleFilters(t *testing.T) {
	_, service, _, ctx := setupSecretsTest(t)

	// Create a specific secret that matches all filters
	createReq := &pb.CreateSecretRequest{
		Title:         "Important Work Login",
		EncryptedData: createTestEncryptedData(),
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
		Metadata: &pb.Metadata{
			Category:   "work",
			IsFavorite: true,
			Tags:       []string{"important", "production"},
		},
	}
	_, err := service.CreateSecret(ctx, createReq)
	require.NoError(t, err)

	// Create a secret that doesn't match all filters
	createReq2 := &pb.CreateSecretRequest{
		Title:         "Personal Note",
		EncryptedData: createTestEncryptedData(),
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
		Metadata: &pb.Metadata{
			Category: "personal",
		},
	}
	_, err = service.CreateSecret(ctx, createReq2)
	require.NoError(t, err)

	// Search with multiple filters
	searchReq := &pb.SearchSecretsRequest{
		Category:      "work",
		FavoritesOnly: true,
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
		Tags:          []string{"important"},
	}

	searchResp, err := service.SearchSecrets(ctx, searchReq)

	require.NoError(t, err)
	assert.NotNil(t, searchResp)
	assert.Len(t, searchResp.Secrets, 1)
	assert.Equal(t, "Important Work Login", searchResp.Secrets[0].Title)
}

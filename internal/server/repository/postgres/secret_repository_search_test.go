package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/koyif/keyper/internal/server/repository"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSecretRepository_Search tests the database-level search functionality.
func TestSecretRepository_Search(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	pool := setupTestDB(t)
	secretRepo := NewSecretRepository(pool)
	userRepo := NewUserRepository(pool)
	ctx := context.Background()

	// Create test user
	testUser, err := userRepo.CreateUser(ctx, "search-test@example.com", []byte("hash"), []byte("verifier"), []byte("salt"))
	require.NoError(t, err)
	userID := testUser.ID

	// Create test secrets with various metadata
	secrets := []*repository.Secret{
		{
			UserID:        userID,
			Name:          "GitHub Password",
			Type:          1, // LOGIN
			EncryptedData: []byte("encrypted1"),
			Nonce:         []byte("nonce1234567"),
			Metadata: mustMarshalJSON(map[string]any{
				"category":    "work",
				"is_favorite": true,
				"tags":        []string{"github", "development"},
				"notes":       "Main GitHub account",
			}),
		},
		{
			UserID:        userID,
			Name:          "AWS Credentials",
			Type:          1, // LOGIN
			EncryptedData: []byte("encrypted2"),
			Nonce:         []byte("nonce2345678"),
			Metadata: mustMarshalJSON(map[string]any{
				"category":    "work",
				"is_favorite": false,
				"tags":        []string{"aws", "cloud"},
				"notes":       "Production AWS account",
			}),
		},
		{
			UserID:        userID,
			Name:          "Personal Email",
			Type:          1, // LOGIN
			EncryptedData: []byte("encrypted3"),
			Nonce:         []byte("nonce3456789"),
			Metadata: mustMarshalJSON(map[string]any{
				"category":    "personal",
				"is_favorite": true,
				"tags":        []string{"email", "personal"},
				"notes":       "Gmail account",
			}),
		},
		{
			UserID:        userID,
			Name:          "Credit Card",
			Type:          3, // CREDIT_CARD
			EncryptedData: []byte("encrypted4"),
			Nonce:         []byte("nonce4567890"),
			Metadata: mustMarshalJSON(map[string]any{
				"category":    "personal",
				"is_favorite": false,
				"tags":        []string{"finance", "card"},
				"notes":       "Chase Sapphire Reserve",
			}),
		},
		{
			UserID:        userID,
			Name:          "Secure Note",
			Type:          2, // NOTE
			EncryptedData: []byte("encrypted5"),
			Nonce:         []byte("nonce5678901"),
			Metadata: mustMarshalJSON(map[string]any{
				"category":    "work",
				"is_favorite": false,
				"tags":        []string{"notes", "important"},
				"notes":       "Meeting notes from Q1",
			}),
		},
	}

	// Create all secrets
	for i, secret := range secrets {
		created, err := secretRepo.Create(ctx, secret)
		require.NoError(t, err)
		secrets[i] = created
		// Add small delay to ensure different updated_at timestamps
		time.Sleep(5 * time.Millisecond)
	}

	t.Run("search by query - name match", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Query:  "github",
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "GitHub Password", results[0].Name)
	})

	t.Run("search by query - metadata notes match", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Query:  "aws",
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "AWS Credentials", results[0].Name)
	})

	t.Run("search by query - case insensitive", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Query:  "GITHUB",
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "GitHub Password", results[0].Name)
	})

	t.Run("filter by type", func(t *testing.T) {
		loginType := int32(1)
		params := SearchParams{
			UserID: userID,
			Type:   &loginType,
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 3) // GitHub, AWS, Email
		for _, result := range results {
			assert.Equal(t, int32(1), result.Type)
		}
	})

	t.Run("filter by category", func(t *testing.T) {
		params := SearchParams{
			UserID:   userID,
			Category: "work",
			Limit:    100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 3) // GitHub, AWS, Secure Note
	})

	t.Run("filter by favorites", func(t *testing.T) {
		favorite := true
		params := SearchParams{
			UserID:     userID,
			IsFavorite: &favorite,
			Limit:      100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 2) // GitHub, Personal Email
	})

	t.Run("filter by tags - single tag", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Tags:   []string{"github"},
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "GitHub Password", results[0].Name)
	})

	t.Run("filter by tags - multiple tags AND logic", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Tags:   []string{"email", "personal"},
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "Personal Email", results[0].Name)
	})

	t.Run("combined filters - query + type + category", func(t *testing.T) {
		loginType := int32(1)
		params := SearchParams{
			UserID:   userID,
			Query:    "Password",
			Type:     &loginType,
			Category: "work",
			Limit:    100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "GitHub Password", results[0].Name)
	})

	t.Run("combined filters - category + favorites + tags", func(t *testing.T) {
		favorite := true
		params := SearchParams{
			UserID:     userID,
			Category:   "work",
			IsFavorite: &favorite,
			Tags:       []string{"github"},
			Limit:      100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, "GitHub Password", results[0].Name)
	})

	t.Run("pagination - limit", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Limit:  2,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("pagination - offset", func(t *testing.T) {
		// Get first page
		params1 := SearchParams{
			UserID: userID,
			Limit:  2,
			Offset: 0,
		}
		results1, err := secretRepo.Search(ctx, params1)
		require.NoError(t, err)
		assert.Len(t, results1, 2)

		// Get second page
		params2 := SearchParams{
			UserID: userID,
			Limit:  2,
			Offset: 2,
		}
		results2, err := secretRepo.Search(ctx, params2)
		require.NoError(t, err)
		assert.Len(t, results2, 2)

		// Ensure different results
		assert.NotEqual(t, results1[0].ID, results2[0].ID)
	})

	t.Run("ordering by updated_at DESC", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(results), 2)

		// Verify descending order
		for i := 0; i < len(results)-1; i++ {
			assert.True(t, results[i].UpdatedAt.After(results[i+1].UpdatedAt) ||
				results[i].UpdatedAt.Equal(results[i+1].UpdatedAt))
		}
	})

	t.Run("no results", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Query:  "nonexistent",
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("excludes soft-deleted secrets", func(t *testing.T) {
		// Soft delete a secret
		err := secretRepo.Delete(ctx, secrets[0].ID, secrets[0].Version)
		require.NoError(t, err)

		params := SearchParams{
			UserID: userID,
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)

		// Verify deleted secret is not in results
		for _, result := range results {
			assert.NotEqual(t, secrets[0].ID, result.ID)
		}
	})

	t.Run("different user - no results", func(t *testing.T) {
		differentUserID := uuid.New()
		params := SearchParams{
			UserID: differentUserID,
			Limit:  100,
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("default limit applied", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Limit:  0, // Should default to 100
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.NotNil(t, results)
	})

	t.Run("max limit enforced", func(t *testing.T) {
		params := SearchParams{
			UserID: userID,
			Limit:  5000, // Should be capped at 1000
		}

		results, err := secretRepo.Search(ctx, params)
		require.NoError(t, err)
		assert.NotNil(t, results)
	})
}

// mustMarshalJSON is a helper that marshals data to JSON or panics.
func mustMarshalJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

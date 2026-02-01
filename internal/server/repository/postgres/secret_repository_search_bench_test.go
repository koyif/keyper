package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/koyif/keyper/internal/server/repository"
)

// BenchmarkSecretRepository_Search benchmarks the database-level search performance.
func BenchmarkSecretRepository_Search(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	pool := setupTestDB(&testing.T{})
	secretRepo := NewSecretRepository(pool)
	userRepo := NewUserRepository(pool)
	ctx := context.Background()

	// Create test user
	testUser, err := userRepo.CreateUser(ctx, repository.CreateUserParams{
		Email:                 "bench-test@example.com",
		PasswordHash:          []byte("hash"),
		EncryptionKeyVerifier: []byte("verifier"),
		Salt:                  []byte("salt"),
	})
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}
	userID := testUser.ID

	// Create 1,000 test secrets for realistic performance testing
	const numSecrets = 1000
	categories := []string{"work", "personal", "finance", "development"}
	tags := [][]string{
		{"github", "development"},
		{"aws", "cloud", "infrastructure"},
		{"email", "personal"},
		{"finance", "investment"},
		{"notes", "important"},
	}

	b.Logf("Creating %d test secrets...", numSecrets)
	for i := 0; i < numSecrets; i++ {
		secret := &repository.Secret{
			UserID:        userID,
			Name:          fmt.Sprintf("Secret %d", i),
			Type:          int32(i % 4), //nolint:gosec // G115: Benchmark test, i%4 is always < max int32
			EncryptedData: []byte(fmt.Sprintf("encrypted%d", i)),
			Nonce:         []byte(fmt.Sprintf("nonce%07d", i)),
			Metadata: mustMarshalJSON(map[string]any{
				"category":    categories[i%len(categories)], //nolint:gosec // G602: Benchmark test, len is always > 0
				"is_favorite": i%3 == 0,                      // Every 3rd is favorite
				"tags":        tags[i%len(tags)],             //nolint:gosec // G602: Benchmark test, len is always > 0
				"notes":       fmt.Sprintf("Notes for secret %d", i),
			}),
		}

		_, err := secretRepo.Create(ctx, secret)
		if err != nil {
			b.Fatalf("Failed to create secret: %v", err)
		}
	}
	b.Logf("Created %d secrets", numSecrets)

	// Benchmark different search scenarios
	benchmarks := []struct {
		name   string
		params SearchParams
	}{
		{
			name: "NoFilters",
			params: SearchParams{
				UserID: userID,
				Limit:  100,
			},
		},
		{
			name: "QueryOnly",
			params: SearchParams{
				UserID: userID,
				Query:  "Secret",
				Limit:  100,
			},
		},
		{
			name: "TypeFilter",
			params: SearchParams{
				UserID: userID,
				Type:   intPtr(1),
				Limit:  100,
			},
		},
		{
			name: "CategoryFilter",
			params: SearchParams{
				UserID:   userID,
				Category: "work",
				Limit:    100,
			},
		},
		{
			name: "FavoritesFilter",
			params: SearchParams{
				UserID:     userID,
				IsFavorite: boolPtr(true),
				Limit:      100,
			},
		},
		{
			name: "TagsFilter",
			params: SearchParams{
				UserID: userID,
				Tags:   []string{"github"},
				Limit:  100,
			},
		},
		{
			name: "CombinedFilters",
			params: SearchParams{
				UserID:   userID,
				Query:    "Secret",
				Type:     intPtr(1),
				Category: "work",
				Limit:    100,
			},
		},
		{
			name: "AllFilters",
			params: SearchParams{
				UserID:     userID,
				Query:      "Secret",
				Type:       intPtr(1),
				Category:   "work",
				IsFavorite: boolPtr(true),
				Tags:       []string{"github"},
				Limit:      100,
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				results, err := secretRepo.Search(ctx, bm.params)
				if err != nil {
					b.Fatalf("Search failed: %v", err)
				}
				// Prevent compiler optimization
				_ = results
			}
		})
	}
}

// BenchmarkSecretRepository_Search_Pagination benchmarks pagination performance.
func BenchmarkSecretRepository_Search_Pagination(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	pool := setupTestDB(&testing.T{})
	secretRepo := NewSecretRepository(pool)
	userRepo := NewUserRepository(pool)
	ctx := context.Background()

	testUser, err := userRepo.CreateUser(ctx, repository.CreateUserParams{
		Email:                 "bench-pagination@example.com",
		PasswordHash:          []byte("hash"),
		EncryptionKeyVerifier: []byte("verifier"),
		Salt:                  []byte("salt"),
	})
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}
	userID := testUser.ID

	// Create 1,000 secrets
	for i := 0; i < 1000; i++ {
		secret := &repository.Secret{
			UserID:        userID,
			Name:          fmt.Sprintf("Secret %d", i),
			Type:          1,
			EncryptedData: []byte(fmt.Sprintf("encrypted%d", i)),
			Nonce:         []byte(fmt.Sprintf("nonce%07d", i)),
			Metadata:      []byte("{}"),
		}
		_, err := secretRepo.Create(ctx, secret)
		if err != nil {
			b.Fatalf("Failed to create secret: %v", err)
		}
	}

	limits := []int{10, 50, 100, 500}
	for _, limit := range limits {
		b.Run(fmt.Sprintf("Limit%d", limit), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				params := SearchParams{
					UserID: userID,
					Limit:  limit,
					Offset: 0,
				}
				results, err := secretRepo.Search(ctx, params)
				if err != nil {
					b.Fatalf("Search failed: %v", err)
				}
				_ = results
			}
		})
	}
}

// BenchmarkSecretRepository_Search_vs_ListByUser compares search vs list performance.
func BenchmarkSecretRepository_Search_vs_ListByUser(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	pool := setupTestDB(&testing.T{})
	secretRepo := NewSecretRepository(pool)
	userRepo := NewUserRepository(pool)
	ctx := context.Background()

	testUser, err := userRepo.CreateUser(ctx, repository.CreateUserParams{
		Email:                 "bench-comparison@example.com",
		PasswordHash:          []byte("hash"),
		EncryptionKeyVerifier: []byte("verifier"),
		Salt:                  []byte("salt"),
	})
	if err != nil {
		b.Fatalf("Failed to create test user: %v", err)
	}
	userID := testUser.ID

	// Create 1,000 secrets
	for i := 0; i < 1000; i++ {
		secret := &repository.Secret{
			UserID:        userID,
			Name:          fmt.Sprintf("Secret %d", i),
			Type:          int32(i % 4), //nolint:gosec // G115: Benchmark test, i%4 is always < max int32
			EncryptedData: []byte(fmt.Sprintf("encrypted%d", i)),
			Nonce:         []byte(fmt.Sprintf("nonce%07d", i)),
			Metadata: mustMarshalJSON(map[string]any{
				"category":    "work",
				"is_favorite": i%3 == 0,
				"tags":        []string{"test"},
			}),
		}
		_, err := secretRepo.Create(ctx, secret)
		if err != nil {
			b.Fatalf("Failed to create secret: %v", err)
		}
	}

	b.Run("Search_DatabaseLevel", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			params := SearchParams{
				UserID:   userID,
				Category: "work",
				Type:     intPtr(1),
				Limit:    100,
			}
			results, err := secretRepo.Search(ctx, params)
			if err != nil {
				b.Fatalf("Search failed: %v", err)
			}
			_ = results
		}
	})

	b.Run("ListByUser_ThenFilter", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Load all secrets (like old implementation)
			allSecrets, err := secretRepo.ListByUser(ctx, userID, 10000, 0)
			if err != nil {
				b.Fatalf("ListByUser failed: %v", err)
			}

			// In-memory filtering
			var filtered []*repository.Secret
			targetType := int32(1)
			for _, secret := range allSecrets {
				if secret.Type != targetType {
					continue
				}

				var metadata map[string]any
				if len(secret.Metadata) > 0 {
					if err := json.Unmarshal(secret.Metadata, &metadata); err != nil {
						continue
					}
				}

				if cat, ok := metadata["category"].(string); ok && cat == "work" {
					filtered = append(filtered, secret)
				}

				if len(filtered) >= 100 {
					break
				}
			}
			_ = filtered
		}
	})
}

// Helper functions
func intPtr(i int32) *int32 {
	return &i
}

func boolPtr(b bool) *bool {
	return &b
}

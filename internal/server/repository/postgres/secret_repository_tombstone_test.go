package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/koyif/keyper/internal/server/repository"
)

// setSecretTimestamp updates the updated_at timestamp for a secret.
func setSecretTimestamp(t *testing.T, pool *pgxpool.Pool, secretID uuid.UUID, timestamp time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), "UPDATE secrets SET updated_at = $1 WHERE id = $2", timestamp, secretID)
	if err != nil {
		t.Fatalf("Failed to update timestamp: %v", err)
	}
}

func TestHardDeleteTombstones(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	repo := NewSecretRepository(pool)
	userRepo := NewUserRepository(pool)
	ctx := context.Background()

	// Create a test user first
	user := createTestUser(t, ctx, userRepo)
	userID := user.ID

	// Create test secrets
	now := time.Now()

	// Create an old tombstone (should be deleted)
	oldTombstone := &repository.Secret{
		UserID:        userID,
		Name:          "old-tombstone",
		Type:          1,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
		Metadata:      []byte("{}"),
		IsDeleted:     false,
	}
	oldTombstone, err := repo.Create(ctx, oldTombstone)
	if err != nil {
		t.Fatalf("Failed to create old tombstone: %v", err)
	}

	// Soft delete it
	err = repo.Delete(ctx, oldTombstone.ID, oldTombstone.Version)
	if err != nil {
		t.Fatalf("Failed to soft delete old tombstone: %v", err)
	}

	// Manually update the updated_at to be 40 days ago
	oldDate := now.Add(-40 * 24 * time.Hour)
	setSecretTimestamp(t, pool, oldTombstone.ID, oldDate)

	// Create a recent tombstone (should NOT be deleted)
	recentTombstone := &repository.Secret{
		UserID:        userID,
		Name:          "recent-tombstone",
		Type:          1,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
		Metadata:      []byte("{}"),
		IsDeleted:     false,
	}
	recentTombstone, err = repo.Create(ctx, recentTombstone)
	if err != nil {
		t.Fatalf("Failed to create recent tombstone: %v", err)
	}

	// Soft delete it
	err = repo.Delete(ctx, recentTombstone.ID, recentTombstone.Version)
	if err != nil {
		t.Fatalf("Failed to soft delete recent tombstone: %v", err)
	}

	// Create a non-deleted secret (should NOT be deleted)
	activeSecret := &repository.Secret{
		UserID:        userID,
		Name:          "active-secret",
		Type:          1,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
		Metadata:      []byte("{}"),
		IsDeleted:     false,
	}
	activeSecret, err = repo.Create(ctx, activeSecret)
	if err != nil {
		t.Fatalf("Failed to create active secret: %v", err)
	}

	// Run the cleanup with 30 day retention
	cutoffTime := now.Add(-30 * 24 * time.Hour)
	deleted, err := repo.HardDeleteTombstones(ctx, cutoffTime, 1000)
	if err != nil {
		t.Fatalf("HardDeleteTombstones failed: %v", err)
	}

	// Should have deleted exactly 1 (the old tombstone)
	if deleted != 1 {
		t.Errorf("Expected 1 tombstone deleted, got %d", deleted)
	}

	// Verify old tombstone is gone
	var count int
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM secrets WHERE id = $1", oldTombstone.ID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check old tombstone: %v", err)
	}
	if count != 0 {
		t.Error("Old tombstone should be permanently deleted")
	}

	// Verify recent tombstone still exists
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM secrets WHERE id = $1", recentTombstone.ID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check recent tombstone: %v", err)
	}
	if count != 1 {
		t.Error("Recent tombstone should still exist")
	}

	// Verify active secret still exists
	err = pool.QueryRow(ctx, "SELECT COUNT(*) FROM secrets WHERE id = $1", activeSecret.ID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check active secret: %v", err)
	}
	if count != 1 {
		t.Error("Active secret should still exist")
	}
}

func TestHardDeleteTombstones_BatchSize(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	repo := NewSecretRepository(pool)
	userRepo := NewUserRepository(pool)
	ctx := context.Background()

	// Create a test user first
	user := createTestUser(t, ctx, userRepo)
	userID := user.ID

	// Create 5 old tombstones
	now := time.Now()
	oldDate := now.Add(-40 * 24 * time.Hour)

	for i := range 5 {
		secret := &repository.Secret{
			UserID:        userID,
			Name:          "tombstone",
			Type:          1,
			EncryptedData: []byte("data"),
			Nonce:         []byte("nonce"),
			Metadata:      []byte("{}"),
			IsDeleted:     false,
		}
		secret, err := repo.Create(ctx, secret)
		if err != nil {
			t.Fatalf("Failed to create secret %d: %v", i, err)
		}

		// Soft delete it
		err = repo.Delete(ctx, secret.ID, secret.Version)
		if err != nil {
			t.Fatalf("Failed to soft delete secret %d: %v", i, err)
		}

		// Update timestamp
		setSecretTimestamp(t, pool, secret.ID, oldDate)
	}

	cutoffTime := now.Add(-30 * 24 * time.Hour)

	// First batch with limit 2
	deleted, err := repo.HardDeleteTombstones(ctx, cutoffTime, 2)
	if err != nil {
		t.Fatalf("HardDeleteTombstones (batch 1) failed: %v", err)
	}
	if deleted != 2 {
		t.Errorf("Expected 2 tombstones deleted in batch 1, got %d", deleted)
	}

	// Second batch with limit 2
	deleted, err = repo.HardDeleteTombstones(ctx, cutoffTime, 2)
	if err != nil {
		t.Fatalf("HardDeleteTombstones (batch 2) failed: %v", err)
	}
	if deleted != 2 {
		t.Errorf("Expected 2 tombstones deleted in batch 2, got %d", deleted)
	}

	// Third batch with limit 2 (should only delete 1)
	deleted, err = repo.HardDeleteTombstones(ctx, cutoffTime, 2)
	if err != nil {
		t.Fatalf("HardDeleteTombstones (batch 3) failed: %v", err)
	}
	if deleted != 1 {
		t.Errorf("Expected 1 tombstone deleted in batch 3, got %d", deleted)
	}

	// Fourth batch should delete nothing
	deleted, err = repo.HardDeleteTombstones(ctx, cutoffTime, 2)
	if err != nil {
		t.Fatalf("HardDeleteTombstones (batch 4) failed: %v", err)
	}
	if deleted != 0 {
		t.Errorf("Expected 0 tombstones deleted in batch 4, got %d", deleted)
	}
}

func TestHardDeleteTombstones_DefaultBatchSize(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	repo := NewSecretRepository(pool)
	ctx := context.Background()

	cutoffTime := time.Now().Add(-30 * 24 * time.Hour)

	// Test with invalid batch size (should use default of 1000)
	deleted, err := repo.HardDeleteTombstones(ctx, cutoffTime, 0)
	if err != nil {
		t.Fatalf("HardDeleteTombstones failed: %v", err)
	}

	// Should succeed (even with 0 results)
	if deleted != 0 {
		t.Errorf("Expected 0 tombstones deleted, got %d", deleted)
	}

	// Test with negative batch size (should use default of 1000)
	deleted, err = repo.HardDeleteTombstones(ctx, cutoffTime, -10)
	if err != nil {
		t.Fatalf("HardDeleteTombstones failed: %v", err)
	}

	if deleted != 0 {
		t.Errorf("Expected 0 tombstones deleted, got %d", deleted)
	}
}

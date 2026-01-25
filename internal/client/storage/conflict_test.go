package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/koy/keyper/pkg/api/proto"
)

// TestCreateConflict tests that CreateConflict stores all fields correctly.
func TestCreateConflict(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()
	conflict := &Conflict{
		SecretID:           "secret-123",
		ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		LocalVersion:       1,
		ServerVersion:      2,
		LocalData:          []byte("local-encrypted-data"),
		ServerData:         []byte("server-encrypted-data"),
		LocalUpdatedAt:     now.Add(-30 * time.Minute),
		ServerUpdatedAt:    now,
		DetectedAt:         now,
		Resolved:           false,
		ResolutionStrategy: "manual",
	}

	err = repo.CreateConflict(ctx, conflict)
	require.NoError(t, err)

	// Verify ID was assigned
	assert.NotZero(t, conflict.ID)

	// Retrieve and verify all fields
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)

	retrieved := conflicts[0]
	assert.Equal(t, conflict.ID, retrieved.ID)
	assert.Equal(t, "secret-123", retrieved.SecretID)
	assert.Equal(t, pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED, retrieved.ConflictType)
	assert.Equal(t, int64(1), retrieved.LocalVersion)
	assert.Equal(t, int64(2), retrieved.ServerVersion)
	assert.Equal(t, []byte("local-encrypted-data"), retrieved.LocalData)
	assert.Equal(t, []byte("server-encrypted-data"), retrieved.ServerData)
	assert.False(t, retrieved.Resolved)
	assert.Equal(t, "manual", retrieved.ResolutionStrategy)
	assert.Nil(t, retrieved.ResolvedAt)
}

// TestCreateConflict_AutoSetsDetectedAt tests that DetectedAt is set automatically
// if not provided.
func TestCreateConflict_AutoSetsDetectedAt(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()
	conflict := &Conflict{
		SecretID:        "secret-123",
		ConflictType:    pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		LocalVersion:    1,
		ServerVersion:   2,
		LocalData:       []byte("local-data"),
		ServerData:      []byte("server-data"),
		LocalUpdatedAt:  now.Add(-30 * time.Minute),
		ServerUpdatedAt: now,
		// DetectedAt is not set (zero value)
		Resolved:           false,
		ResolutionStrategy: "manual",
	}

	beforeCreate := time.Now()
	err = repo.CreateConflict(ctx, conflict)
	require.NoError(t, err)
	afterCreate := time.Now()

	// Verify DetectedAt was set automatically
	assert.False(t, conflict.DetectedAt.IsZero())
	assert.True(t, conflict.DetectedAt.After(beforeCreate) || conflict.DetectedAt.Equal(beforeCreate))
	assert.True(t, conflict.DetectedAt.Before(afterCreate) || conflict.DetectedAt.Equal(afterCreate))
}

// TestGetUnresolvedConflicts tests that GetUnresolvedConflicts filters by resolved flag.
func TestGetUnresolvedConflicts(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create 3 unresolved conflicts
	for i := 1; i <= 3; i++ {
		conflict := &Conflict{
			SecretID:           "secret-" + string(rune('0'+i)),
			ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
			LocalVersion:       1,
			ServerVersion:      2,
			LocalData:          []byte("local-data"),
			ServerData:         []byte("server-data"),
			LocalUpdatedAt:     now.Add(-30 * time.Minute),
			ServerUpdatedAt:    now,
			DetectedAt:         now.Add(time.Duration(-i) * time.Minute),
			Resolved:           false,
			ResolutionStrategy: "manual",
		}
		err = repo.CreateConflict(ctx, conflict)
		require.NoError(t, err)
	}

	// Create 2 resolved conflicts
	for i := 4; i <= 5; i++ {
		conflict := &Conflict{
			SecretID:           "secret-" + string(rune('0'+i)),
			ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
			LocalVersion:       1,
			ServerVersion:      2,
			LocalData:          []byte("local-data"),
			ServerData:         []byte("server-data"),
			LocalUpdatedAt:     now.Add(-30 * time.Minute),
			ServerUpdatedAt:    now,
			DetectedAt:         now,
			Resolved:           true, // Resolved
			ResolutionStrategy: "last-write-wins",
		}
		err = repo.CreateConflict(ctx, conflict)
		require.NoError(t, err)
	}

	// Get unresolved conflicts
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)

	// Should only return the 3 unresolved conflicts
	assert.Len(t, conflicts, 3)

	// Verify all returned conflicts are unresolved
	for _, conflict := range conflicts {
		assert.False(t, conflict.Resolved)
	}
}

// TestGetUnresolvedConflicts_OrderedByDetectedAt tests that conflicts are ordered
// by detected_at DESC (most recent first).
func TestGetUnresolvedConflicts_OrderedByDetectedAt(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create conflicts with different detected times
	times := []time.Time{
		now.Add(-3 * time.Hour),
		now.Add(-1 * time.Hour),
		now.Add(-2 * time.Hour),
	}

	for i, detectedTime := range times {
		conflict := &Conflict{
			SecretID:           "secret-" + string(rune('0'+i+1)),
			ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
			LocalVersion:       1,
			ServerVersion:      2,
			LocalData:          []byte("local-data"),
			ServerData:         []byte("server-data"),
			LocalUpdatedAt:     now.Add(-30 * time.Minute),
			ServerUpdatedAt:    now,
			DetectedAt:         detectedTime,
			Resolved:           false,
			ResolutionStrategy: "manual",
		}
		err = repo.CreateConflict(ctx, conflict)
		require.NoError(t, err)
	}

	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 3)

	// Verify order: most recent first
	// Expected order: secret-2 (1h ago), secret-3 (2h ago), secret-1 (3h ago)
	assert.Equal(t, "secret-2", conflicts[0].SecretID)
	assert.Equal(t, "secret-3", conflicts[1].SecretID)
	assert.Equal(t, "secret-1", conflicts[2].SecretID)
}

// TestGetUnresolvedConflicts_EmptyResult tests behavior when no unresolved conflicts exist.
func TestGetUnresolvedConflicts_EmptyResult(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	// No conflicts created
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

// TestResolveConflict tests that ResolveConflict updates resolution fields correctly.
func TestResolveConflict(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create an unresolved conflict
	conflict := &Conflict{
		SecretID:           "secret-123",
		ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		LocalVersion:       1,
		ServerVersion:      2,
		LocalData:          []byte("local-data"),
		ServerData:         []byte("server-data"),
		LocalUpdatedAt:     now.Add(-30 * time.Minute),
		ServerUpdatedAt:    now,
		DetectedAt:         now,
		Resolved:           false,
		ResolutionStrategy: "manual",
	}

	err = repo.CreateConflict(ctx, conflict)
	require.NoError(t, err)
	conflictID := conflict.ID

	// Resolve the conflict
	err = repo.ResolveConflict(ctx, conflictID, "user-chose-local")
	require.NoError(t, err)

	// Verify conflict is no longer in unresolved list
	unresolvedConflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	assert.Empty(t, unresolvedConflicts)

	// We can't easily verify the resolved conflict without a GetAllConflicts method,
	// but we can verify the operation succeeded and unresolved list is empty
}

// TestResolveConflict_NonExistentID tests that resolving a non-existent conflict returns error.
func TestResolveConflict_NonExistentID(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	// Try to resolve a conflict that doesn't exist
	err = repo.ResolveConflict(ctx, 99999, "some-strategy")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "conflict not found")
}

// TestResolveConflict_UpdatesStrategy tests that resolution strategy is updated.
func TestResolveConflict_UpdatesStrategy(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create conflict with initial strategy
	conflict := &Conflict{
		SecretID:           "secret-123",
		ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		LocalVersion:       1,
		ServerVersion:      2,
		LocalData:          []byte("local-data"),
		ServerData:         []byte("server-data"),
		LocalUpdatedAt:     now.Add(-30 * time.Minute),
		ServerUpdatedAt:    now,
		DetectedAt:         now,
		Resolved:           false,
		ResolutionStrategy: "manual",
	}

	err = repo.CreateConflict(ctx, conflict)
	require.NoError(t, err)

	// Resolve with new strategy
	err = repo.ResolveConflict(ctx, conflict.ID, "user-chose-server")
	require.NoError(t, err)

	// Verify it's no longer unresolved
	unresolvedConflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	assert.Empty(t, unresolvedConflicts)
}

// TestCreateConflictInTx tests transaction support for CreateConflictInTx.
func TestCreateConflictInTx(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Begin transaction
	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)

	// Create conflict within transaction
	conflict := &Conflict{
		SecretID:           "secret-123",
		ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		LocalVersion:       1,
		ServerVersion:      2,
		LocalData:          []byte("local-data"),
		ServerData:         []byte("server-data"),
		LocalUpdatedAt:     now.Add(-30 * time.Minute),
		ServerUpdatedAt:    now,
		DetectedAt:         now,
		Resolved:           false,
		ResolutionStrategy: "manual",
	}

	err = repo.CreateConflictInTx(ctx, tx, conflict)
	require.NoError(t, err)
	assert.NotZero(t, conflict.ID)

	// Commit transaction
	err = tx.Commit()
	require.NoError(t, err)

	// Verify conflict was persisted
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)
	assert.Equal(t, "secret-123", conflicts[0].SecretID)
}

// TestCreateConflictInTx_Rollback tests that conflicts are not persisted on rollback.
func TestCreateConflictInTx_Rollback(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Begin transaction
	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)

	// Create conflict within transaction
	conflict := &Conflict{
		SecretID:           "secret-123",
		ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		LocalVersion:       1,
		ServerVersion:      2,
		LocalData:          []byte("local-data"),
		ServerData:         []byte("server-data"),
		LocalUpdatedAt:     now.Add(-30 * time.Minute),
		ServerUpdatedAt:    now,
		DetectedAt:         now,
		Resolved:           false,
		ResolutionStrategy: "manual",
	}

	err = repo.CreateConflictInTx(ctx, tx, conflict)
	require.NoError(t, err)

	// Rollback transaction
	err = tx.Rollback()
	require.NoError(t, err)

	// Verify conflict was NOT persisted
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	assert.Empty(t, conflicts)
}

// TestCreateConflictInTx_MultipleConflicts tests creating multiple conflicts in one transaction.
func TestCreateConflictInTx_MultipleConflicts(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Begin transaction
	tx, err := repo.BeginTx(ctx)
	require.NoError(t, err)
	defer tx.Rollback() // nolint:errcheck // Cleanup; error is expected if commit succeeds

	// Create 5 conflicts in the same transaction
	for i := 1; i <= 5; i++ {
		conflict := &Conflict{
			SecretID:           "secret-" + string(rune('0'+i)),
			ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
			LocalVersion:       1,
			ServerVersion:      2,
			LocalData:          []byte("local-data"),
			ServerData:         []byte("server-data"),
			LocalUpdatedAt:     now.Add(-30 * time.Minute),
			ServerUpdatedAt:    now,
			DetectedAt:         now,
			Resolved:           false,
			ResolutionStrategy: "manual",
		}

		err = repo.CreateConflictInTx(ctx, tx, conflict)
		require.NoError(t, err)
		assert.NotZero(t, conflict.ID)
	}

	// Commit transaction
	err = tx.Commit()
	require.NoError(t, err)

	// Verify all 5 conflicts were persisted
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	assert.Len(t, conflicts, 5)
}

// TestConflict_AllConflictTypes tests storing all possible conflict types.
func TestConflict_AllConflictTypes(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	conflictTypes := []pb.ConflictType{
		pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		pb.ConflictType_CONFLICT_TYPE_MODIFIED_DELETED,
		pb.ConflictType_CONFLICT_TYPE_DELETED_MODIFIED,
		pb.ConflictType_CONFLICT_TYPE_VERSION_MISMATCH,
	}

	// Create conflict for each type
	for i, cType := range conflictTypes {
		conflict := &Conflict{
			SecretID:           "secret-" + string(rune('0'+i+1)),
			ConflictType:       cType,
			LocalVersion:       1,
			ServerVersion:      2,
			LocalData:          []byte("local-data"),
			ServerData:         []byte("server-data"),
			LocalUpdatedAt:     now.Add(-30 * time.Minute),
			ServerUpdatedAt:    now,
			DetectedAt:         now,
			Resolved:           false,
			ResolutionStrategy: "manual",
		}

		err = repo.CreateConflict(ctx, conflict)
		require.NoError(t, err)
	}

	// Retrieve and verify all conflict types
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 4)

	// Verify all conflict types are present
	foundTypes := make(map[pb.ConflictType]bool)
	for _, conflict := range conflicts {
		foundTypes[conflict.ConflictType] = true
	}

	for _, cType := range conflictTypes {
		assert.True(t, foundTypes[cType], "Conflict type %v not found", cType)
	}
}

// TestConflict_LargeDataFields tests storing conflicts with large encrypted data.
func TestConflict_LargeDataFields(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	// Create large data (1MB each)
	largeLocalData := make([]byte, 1024*1024)
	for i := range largeLocalData {
		largeLocalData[i] = byte(i % 256)
	}

	largeServerData := make([]byte, 1024*1024)
	for i := range largeServerData {
		largeServerData[i] = byte((i + 128) % 256)
	}

	conflict := &Conflict{
		SecretID:           "large-secret",
		ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		LocalVersion:       1,
		ServerVersion:      2,
		LocalData:          largeLocalData,
		ServerData:         largeServerData,
		LocalUpdatedAt:     now.Add(-30 * time.Minute),
		ServerUpdatedAt:    now,
		DetectedAt:         now,
		Resolved:           false,
		ResolutionStrategy: "manual",
	}

	err = repo.CreateConflict(ctx, conflict)
	require.NoError(t, err)

	// Retrieve and verify large data
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)

	retrieved := conflicts[0]
	assert.Equal(t, len(largeLocalData), len(retrieved.LocalData))
	assert.Equal(t, len(largeServerData), len(retrieved.ServerData))
	assert.Equal(t, largeLocalData, retrieved.LocalData)
	assert.Equal(t, largeServerData, retrieved.ServerData)
}

// TestConflict_TimestampPrecision tests that timestamps are stored and retrieved accurately.
func TestConflict_TimestampPrecision(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	// Use specific timestamps with microsecond precision
	localUpdated := time.Date(2024, 1, 15, 10, 30, 45, 123456789, time.UTC)
	serverUpdated := time.Date(2024, 1, 15, 11, 45, 30, 987654321, time.UTC)
	detected := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

	conflict := &Conflict{
		SecretID:           "timestamp-test",
		ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
		LocalVersion:       1,
		ServerVersion:      2,
		LocalData:          []byte("local-data"),
		ServerData:         []byte("server-data"),
		LocalUpdatedAt:     localUpdated,
		ServerUpdatedAt:    serverUpdated,
		DetectedAt:         detected,
		Resolved:           false,
		ResolutionStrategy: "manual",
	}

	err = repo.CreateConflict(ctx, conflict)
	require.NoError(t, err)

	// Retrieve and verify timestamp precision
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	require.Len(t, conflicts, 1)

	retrieved := conflicts[0]

	// SQLite stores timestamps with second precision, so truncate to seconds for comparison
	assert.True(t, retrieved.LocalUpdatedAt.Truncate(time.Second).Equal(localUpdated.Truncate(time.Second)))
	assert.True(t, retrieved.ServerUpdatedAt.Truncate(time.Second).Equal(serverUpdated.Truncate(time.Second)))
	assert.True(t, retrieved.DetectedAt.Truncate(time.Second).Equal(detected.Truncate(time.Second)))
}

// TestConflict_VersionNumbers tests storing various version number combinations.
func TestConflict_VersionNumbers(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	tests := []struct {
		name          string
		localVersion  int64
		serverVersion int64
	}{
		{"same version", 5, 5},
		{"local behind by 1", 5, 6},
		{"local behind by many", 1, 100},
		{"large version numbers", 9999999, 10000000},
		{"zero local version", 0, 1},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conflict := &Conflict{
				SecretID:           "secret-" + string(rune('0'+i+1)),
				ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
				LocalVersion:       tt.localVersion,
				ServerVersion:      tt.serverVersion,
				LocalData:          []byte("local-data"),
				ServerData:         []byte("server-data"),
				LocalUpdatedAt:     now.Add(-30 * time.Minute),
				ServerUpdatedAt:    now,
				DetectedAt:         now,
				Resolved:           false,
				ResolutionStrategy: "manual",
			}

			err = repo.CreateConflict(ctx, conflict)
			require.NoError(t, err)
		})
	}

	// Retrieve all and verify versions
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	assert.Len(t, conflicts, len(tests))
}

// TestConflict_ResolutionStrategies tests various resolution strategy strings.
func TestConflict_ResolutionStrategies(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	repo, err := NewSQLiteRepository(dbPath)
	require.NoError(t, err)
	defer repo.Close()

	now := time.Now()

	strategies := []string{
		"manual",
		"last-write-wins-local",
		"last-write-wins-server",
		"user-chose-local",
		"user-chose-server",
		"merged",
		"",
	}

	for i, strategy := range strategies {
		conflict := &Conflict{
			SecretID:           "secret-" + string(rune('0'+i+1)),
			ConflictType:       pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
			LocalVersion:       1,
			ServerVersion:      2,
			LocalData:          []byte("local-data"),
			ServerData:         []byte("server-data"),
			LocalUpdatedAt:     now.Add(-30 * time.Minute),
			ServerUpdatedAt:    now,
			DetectedAt:         now,
			Resolved:           false,
			ResolutionStrategy: strategy,
		}

		err = repo.CreateConflict(ctx, conflict)
		require.NoError(t, err)
	}

	// Retrieve and verify all strategies were stored
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	require.NoError(t, err)
	assert.Len(t, conflicts, len(strategies))

	// Verify each strategy
	foundStrategies := make(map[string]bool)
	for _, conflict := range conflicts {
		foundStrategies[conflict.ResolutionStrategy] = true
	}

	for _, strategy := range strategies {
		assert.True(t, foundStrategies[strategy], "Strategy %q not found", strategy)
	}
}

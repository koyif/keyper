package storage

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/koy/keyper/pkg/api/proto"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *SQLiteRepository {
	t.Helper()

	// Use in-memory database for tests
	repo, err := NewSQLiteRepository(":memory:")
	if err != nil {
		t.Fatalf("Failed to create test repository: %v", err)
	}

	t.Cleanup(func() {
		repo.Close()
	})

	return repo
}

func TestNewSQLiteRepository(t *testing.T) {
	// Test creating repository with file path
	tempFile := t.TempDir() + "/test.db"
	repo, err := NewSQLiteRepository(tempFile)
	if err != nil {
		t.Fatalf("Failed to create repository: %v", err)
	}
	defer repo.Close()

	// Verify database file was created
	if _, err := os.Stat(tempFile); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}

	// Verify schema_migrations table exists
	var count int
	err = repo.db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count)
	if err != nil {
		t.Errorf("schema_migrations table not found: %v", err)
	}

	// Verify current version is set
	var version int
	err = repo.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		t.Errorf("Failed to get schema version: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Errorf("Expected schema version %d, got %d", CurrentSchemaVersion, version)
	}
}

func TestMigrationIdempotency(t *testing.T) {
	tempFile := t.TempDir() + "/test.db"

	// Create repository first time
	repo1, err := NewSQLiteRepository(tempFile)
	if err != nil {
		t.Fatalf("Failed to create repository first time: %v", err)
	}
	repo1.Close()

	// Create repository second time (should not fail)
	repo2, err := NewSQLiteRepository(tempFile)
	if err != nil {
		t.Fatalf("Failed to create repository second time: %v", err)
	}
	defer repo2.Close()

	// Verify version is still correct
	var version int
	err = repo2.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version)
	if err != nil {
		t.Errorf("Failed to get schema version: %v", err)
	}
	if version != CurrentSchemaVersion {
		t.Errorf("Expected schema version %d, got %d", CurrentSchemaVersion, version)
	}
}

func TestCreate(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	secret := &LocalSecret{
		ID:            "test-id-1",
		Name:          "Test Secret",
		Type:          proto.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData: []byte("encrypted-data"),
		Nonce:         []byte("nonce-12345"),
		Metadata:      `{"url":"https://example.com"}`,
	}

	err := repo.Create(ctx, secret)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Verify defaults were set
	if secret.Version != 1 {
		t.Errorf("Expected version 1, got %d", secret.Version)
	}
	if secret.SyncStatus != SyncStatusPending {
		t.Errorf("Expected sync status 'pending', got '%s'", secret.SyncStatus)
	}
	if secret.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}

	// Verify secret was created in database
	retrieved, err := repo.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to get created secret: %v", err)
	}

	if retrieved.Name != secret.Name {
		t.Errorf("Expected name '%s', got '%s'", secret.Name, retrieved.Name)
	}
	if retrieved.Type != secret.Type {
		t.Errorf("Expected type %d, got %d", secret.Type, retrieved.Type)
	}
}

func TestGet(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Create a test secret
	secret := &LocalSecret{
		ID:            "test-id-2",
		Name:          "Get Test",
		Type:          proto.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
	}

	err := repo.Create(ctx, secret)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Test Get
	retrieved, err := repo.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	if retrieved.ID != secret.ID {
		t.Errorf("Expected ID '%s', got '%s'", secret.ID, retrieved.ID)
	}
	if retrieved.Name != secret.Name {
		t.Errorf("Expected name '%s', got '%s'", secret.Name, retrieved.Name)
	}

	// Test Get non-existent
	_, err = repo.Get(ctx, "non-existent-id")
	if err == nil {
		t.Error("Expected error when getting non-existent secret")
	}
}

func TestGetByName(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Create a test secret
	secret := &LocalSecret{
		ID:            "test-id-3",
		Name:          "Named Secret",
		Type:          proto.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
	}

	err := repo.Create(ctx, secret)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Test GetByName
	retrieved, err := repo.GetByName(ctx, secret.Name)
	if err != nil {
		t.Fatalf("Failed to get secret by name: %v", err)
	}

	if retrieved.ID != secret.ID {
		t.Errorf("Expected ID '%s', got '%s'", secret.ID, retrieved.ID)
	}

	// Test GetByName non-existent
	_, err = repo.GetByName(ctx, "non-existent-name")
	if err == nil {
		t.Error("Expected error when getting non-existent secret by name")
	}
}

func TestUpdate(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Create a test secret
	secret := &LocalSecret{
		ID:            "test-id-4",
		Name:          "Update Test",
		Type:          proto.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("original-data"),
		Nonce:         []byte("nonce"),
		SyncStatus:    SyncStatusSynced,
	}

	err := repo.Create(ctx, secret)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Update the secret
	secret.Name = "Updated Name"
	secret.EncryptedData = []byte("updated-data")
	secret.Version = 2

	err = repo.Update(ctx, secret)
	if err != nil {
		t.Fatalf("Failed to update secret: %v", err)
	}

	// Verify update
	retrieved, err := repo.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to get updated secret: %v", err)
	}

	if retrieved.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", retrieved.Name)
	}
	if string(retrieved.EncryptedData) != "updated-data" {
		t.Errorf("Expected data 'updated-data', got '%s'", string(retrieved.EncryptedData))
	}
	if retrieved.Version != 2 {
		t.Errorf("Expected version 2, got %d", retrieved.Version)
	}
	// Sync status should change to pending when updating
	if retrieved.SyncStatus != SyncStatusPending {
		t.Errorf("Expected sync status 'pending', got '%s'", retrieved.SyncStatus)
	}

	// Test update non-existent
	secret.ID = "non-existent-id"
	err = repo.Update(ctx, secret)
	if err == nil {
		t.Error("Expected error when updating non-existent secret")
	}
}

func TestDelete(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Create a test secret
	secret := &LocalSecret{
		ID:            "test-id-5",
		Name:          "Delete Test",
		Type:          proto.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
	}

	err := repo.Create(ctx, secret)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Delete the secret (soft delete)
	err = repo.Delete(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to delete secret: %v", err)
	}

	// Verify secret is marked as deleted
	retrieved, err := repo.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to get deleted secret: %v", err)
	}

	if !retrieved.IsDeleted {
		t.Error("Secret should be marked as deleted")
	}
	if retrieved.SyncStatus != SyncStatusPending {
		t.Errorf("Expected sync status 'pending', got '%s'", retrieved.SyncStatus)
	}

	// Test delete non-existent
	err = repo.Delete(ctx, "non-existent-id")
	if err == nil {
		t.Error("Expected error when deleting non-existent secret")
	}
}

func TestHardDelete(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Create a test secret
	secret := &LocalSecret{
		ID:            "test-id-6",
		Name:          "Hard Delete Test",
		Type:          proto.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
	}

	err := repo.Create(ctx, secret)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Hard delete the secret
	err = repo.HardDelete(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to hard delete secret: %v", err)
	}

	// Verify secret is completely removed
	_, err = repo.Get(ctx, secret.ID)
	if err == nil {
		t.Error("Expected error when getting hard deleted secret")
	}
}

func TestList(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Create multiple test secrets
	secrets := []*LocalSecret{
		{
			ID:            "test-id-7",
			Name:          "Secret 1",
			Type:          proto.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: []byte("data1"),
			Nonce:         []byte("nonce1"),
		},
		{
			ID:            "test-id-8",
			Name:          "Secret 2",
			Type:          proto.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: []byte("data2"),
			Nonce:         []byte("nonce2"),
		},
		{
			ID:            "test-id-9",
			Name:          "Secret 3",
			Type:          proto.SecretType_SECRET_TYPE_CREDENTIAL,
			EncryptedData: []byte("data3"),
			Nonce:         []byte("nonce3"),
			IsDeleted:     true,
		},
	}

	for _, s := range secrets {
		// Sleep briefly to ensure different timestamps
		time.Sleep(time.Millisecond)
		err := repo.Create(ctx, s)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}
	}

	// Test list all (excluding deleted)
	all, err := repo.List(ctx, ListFilters{})
	if err != nil {
		t.Fatalf("Failed to list secrets: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("Expected 2 secrets, got %d", len(all))
	}

	// Test list with type filter
	credType := proto.SecretType_SECRET_TYPE_CREDENTIAL
	creds, err := repo.List(ctx, ListFilters{Type: &credType})
	if err != nil {
		t.Fatalf("Failed to list credentials: %v", err)
	}
	if len(creds) != 1 {
		t.Errorf("Expected 1 credential, got %d", len(creds))
	}

	// Test list including deleted
	withDeleted, err := repo.List(ctx, ListFilters{IncludeDeleted: true})
	if err != nil {
		t.Fatalf("Failed to list with deleted: %v", err)
	}
	if len(withDeleted) != 3 {
		t.Errorf("Expected 3 secrets with deleted, got %d", len(withDeleted))
	}

	// Test list with limit
	limited, err := repo.List(ctx, ListFilters{Limit: 1})
	if err != nil {
		t.Fatalf("Failed to list with limit: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("Expected 1 secret with limit, got %d", len(limited))
	}
}

func TestGetPendingSync(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Create secrets with different sync statuses
	secrets := []*LocalSecret{
		{
			ID:            "test-id-10",
			Name:          "Pending 1",
			Type:          proto.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: []byte("data1"),
			Nonce:         []byte("nonce1"),
			SyncStatus:    SyncStatusPending,
		},
		{
			ID:            "test-id-11",
			Name:          "Synced 1",
			Type:          proto.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: []byte("data2"),
			Nonce:         []byte("nonce2"),
			SyncStatus:    SyncStatusSynced,
		},
		{
			ID:            "test-id-12",
			Name:          "Pending 2",
			Type:          proto.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: []byte("data3"),
			Nonce:         []byte("nonce3"),
			SyncStatus:    SyncStatusPending,
		},
	}

	for _, s := range secrets {
		err := repo.Create(ctx, s)
		if err != nil {
			t.Fatalf("Failed to create secret: %v", err)
		}
	}

	// Get pending sync secrets
	pending, err := repo.GetPendingSync(ctx)
	if err != nil {
		t.Fatalf("Failed to get pending sync: %v", err)
	}

	if len(pending) != 2 {
		t.Errorf("Expected 2 pending secrets, got %d", len(pending))
	}

	for _, s := range pending {
		if s.SyncStatus != SyncStatusPending {
			t.Errorf("Expected sync status 'pending', got '%s'", s.SyncStatus)
		}
	}
}

func TestUpdateSyncStatus(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Create a test secret
	secret := &LocalSecret{
		ID:            "test-id-13",
		Name:          "Sync Status Test",
		Type:          proto.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
		SyncStatus:    SyncStatusPending,
		ServerVersion: 0,
	}

	err := repo.Create(ctx, secret)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Update sync status
	err = repo.UpdateSyncStatus(ctx, secret.ID, SyncStatusSynced, 1)
	if err != nil {
		t.Fatalf("Failed to update sync status: %v", err)
	}

	// Verify update
	retrieved, err := repo.Get(ctx, secret.ID)
	if err != nil {
		t.Fatalf("Failed to get secret: %v", err)
	}

	if retrieved.SyncStatus != SyncStatusSynced {
		t.Errorf("Expected sync status 'synced', got '%s'", retrieved.SyncStatus)
	}
	if retrieved.ServerVersion != 1 {
		t.Errorf("Expected server version 1, got %d", retrieved.ServerVersion)
	}
}

func TestIndexes(t *testing.T) {
	repo := setupTestDB(t)

	// Verify indexes exist
	rows, err := repo.db.Query(`
		SELECT name FROM sqlite_master
		WHERE type='index' AND tbl_name='secrets'
	`)
	if err != nil {
		t.Fatalf("Failed to query indexes: %v", err)
	}
	defer rows.Close()

	indexes := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("Failed to scan index name: %v", err)
		}
		indexes[name] = true
	}

	expectedIndexes := []string{
		"idx_secrets_type",
		"idx_secrets_sync_status",
		"idx_secrets_updated_at",
		"idx_secrets_name",
	}

	for _, expected := range expectedIndexes {
		if !indexes[expected] {
			t.Errorf("Expected index '%s' not found", expected)
		}
	}
}

func TestConcurrentAccess(t *testing.T) {
	repo := setupTestDB(t)
	ctx := context.Background()

	// Create a secret
	secret := &LocalSecret{
		ID:            "test-id-14",
		Name:          "Concurrent Test",
		Type:          proto.SecretType_SECRET_TYPE_TEXT,
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
	}

	err := repo.Create(ctx, secret)
	if err != nil {
		t.Fatalf("Failed to create secret: %v", err)
	}

	// Test concurrent reads
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := repo.Get(ctx, secret.ID)
			if err != nil {
				t.Errorf("Concurrent read failed: %v", err)
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

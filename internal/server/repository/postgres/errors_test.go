package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koyif/keyper/internal/server/repository"
)

func TestClassifyUpdateError_Success(t *testing.T) {
	secretID := uuid.New()
	err := classifyRowsAffectedError(context.Background(), nil, nil, 1, secretID)
	if err != nil {
		t.Errorf("expected nil, got: %v", err)
	}
}

func TestClassifyUpdateError_DatabaseError(t *testing.T) {
	secretID := uuid.New()
	dbErr := errors.New("connection failed")
	err := classifyRowsAffectedError(context.Background(), nil, dbErr, 0, secretID)
	if err == nil {
		t.Error("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

func TestClassifyUpdateError_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	pool := setupTestDB(t)
	defer pool.Close()

	// Use a non-existent secret ID
	nonExistentID := uuid.New()

	err := classifyRowsAffectedError(context.Background(), pool, nil, 0, nonExistentID)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestClassifyUpdateError_VersionConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	pool := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create a test user and secret
	userRepo := NewUserRepository(pool)
	user := createTestUser(t, ctx, userRepo)

	secretRepo := NewSecretRepository(pool)
	secret := createTestSecret(t, ctx, secretRepo, user.ID)

	// Secret exists, but 0 rows affected means version conflict
	err := classifyRowsAffectedError(ctx, pool, nil, 0, secret.ID)
	if !errors.Is(err, repository.ErrVersionConflict) {
		t.Errorf("expected ErrVersionConflict, got: %v", err)
	}
}

func TestClassifyDeleteError_Success(t *testing.T) {
	secretID := uuid.New()
	err := classifyRowsAffectedError(context.Background(), nil, nil, 1, secretID)
	if err != nil {
		t.Errorf("expected nil, got: %v", err)
	}
}

func TestClassifyDeleteError_DatabaseError(t *testing.T) {
	secretID := uuid.New()
	dbErr := errors.New("connection failed")
	err := classifyRowsAffectedError(context.Background(), nil, dbErr, 0, secretID)
	if err == nil {
		t.Error("expected error, got nil")
	}
	if !errors.Is(err, dbErr) {
		t.Errorf("expected wrapped dbErr, got: %v", err)
	}
}

func TestClassifyDeleteError_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	pool := setupTestDB(t)
	defer pool.Close()

	// Use a non-existent secret ID
	nonExistentID := uuid.New()

	err := classifyRowsAffectedError(context.Background(), pool, nil, 0, nonExistentID)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got: %v", err)
	}
}

func TestClassifyDeleteError_VersionConflict(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	pool := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create a test user and secret
	userRepo := NewUserRepository(pool)
	user := createTestUser(t, ctx, userRepo)

	secretRepo := NewSecretRepository(pool)
	secret := createTestSecret(t, ctx, secretRepo, user.ID)

	// Secret exists, but 0 rows affected means version conflict
	err := classifyRowsAffectedError(ctx, pool, nil, 0, secret.ID)
	if !errors.Is(err, repository.ErrVersionConflict) {
		t.Errorf("expected ErrVersionConflict, got: %v", err)
	}
}

func TestSecretExists_Exists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	pool := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create a test user and secret
	userRepo := NewUserRepository(pool)
	user := createTestUser(t, ctx, userRepo)

	secretRepo := NewSecretRepository(pool)
	secret := createTestSecret(t, ctx, secretRepo, user.ID)

	exists, err := secretExists(ctx, pool, secret.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exists {
		t.Error("expected secret to exist")
	}
}

func TestSecretExists_DoesNotExist(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	pool := setupTestDB(t)
	defer pool.Close()

	nonExistentID := uuid.New()
	exists, err := secretExists(context.Background(), pool, nonExistentID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected secret to not exist")
	}
}

func TestSecretExists_DeletedSecret(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	pool := setupTestDB(t)
	defer pool.Close()

	ctx := context.Background()

	// Create a test user and secret
	userRepo := NewUserRepository(pool)
	user := createTestUser(t, ctx, userRepo)

	secretRepo := NewSecretRepository(pool)
	secret := createTestSecret(t, ctx, secretRepo, user.ID)

	// Soft delete the secret
	err := secretRepo.Delete(ctx, secret.ID, secret.Version)
	if err != nil {
		t.Fatalf("failed to delete secret: %v", err)
	}

	// Soft-deleted secrets should not exist for our purposes
	exists, err := secretExists(ctx, pool, secret.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exists {
		t.Error("expected deleted secret to not exist")
	}
}

// Test helper to ensure our test database pool implements querier interface
func TestQuerierInterface(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	pool := setupTestDB(t)
	defer pool.Close()

	// This should compile, proving pool implements querier
	var _ querier = pool
}

// Test querier interface compatibility
func TestQuerierInterfaceFromPool(t *testing.T) {
	// Create a mock to verify interface compatibility
	var pool *pgxpool.Pool
	var _ querier = pool // This should compile
}

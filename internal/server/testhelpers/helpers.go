package testhelpers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/koyif/keyper/internal/server/repository"
)

type TestDB struct {
	pool *pgxpool.Pool
	t    *testing.T
}

func NewTestDB(t *testing.T) *TestDB {
	t.Helper()

	ctx := context.Background()
	tc := NewTestContainer(ctx, t)

	db := &TestDB{
		pool: tc.Pool(),
		t:    t,
	}

	return db
}

func (db *TestDB) Pool() *pgxpool.Pool {
	return db.pool
}

func (db *TestDB) Truncate(tables ...string) {
	db.t.Helper()

	ctx := context.Background()
	for _, table := range tables {
		query := fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)
		_, err := db.pool.Exec(ctx, query)
		require.NoError(db.t, err, "failed to truncate table %s", table)
	}
}

func (db *TestDB) TruncateAll() {
	db.t.Helper()
	db.Truncate("refresh_tokens", "secrets", "users")
}

func (db *TestDB) CreateTestUser(email, passwordHash string) *repository.User {
	db.t.Helper()
	return db.CreateTestUserWithDetails(email, []byte(passwordHash), []byte("verifier"), []byte("salt"))
}

func (db *TestDB) CreateTestUserWithDetails(email string, passwordHash, encryptionKeyVerifier, salt []byte) *repository.User {
	db.t.Helper()

	ctx := context.Background()
	query := `
		INSERT INTO users (email, password_hash, encryption_key_verifier, salt)
		VALUES ($1, $2, $3, $4)
		RETURNING id, email, password_hash, encryption_key_verifier, salt, created_at, updated_at
	`

	var user repository.User
	err := db.pool.QueryRow(ctx, query, email, passwordHash, encryptionKeyVerifier, salt).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EncryptionKeyVerifier,
		&user.Salt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	require.NoError(db.t, err, "failed to create test user with details")

	return &user
}

func (db *TestDB) CreateRandomTestUser() *repository.User {
	db.t.Helper()

	email := fmt.Sprintf("test-%s@example.com", uuid.New().String())
	return db.CreateTestUser(email, "test_hash")
}

func (db *TestDB) CreateTestSecret(userID uuid.UUID, name string) *repository.Secret {
	db.t.Helper()
	return db.CreateTestSecretWithType(userID, name, 1)
}

func (db *TestDB) CreateTestSecretWithType(userID uuid.UUID, name string, secretType int32) *repository.Secret {
	db.t.Helper()

	secret := &repository.Secret{
		UserID:        userID,
		Name:          name,
		Type:          secretType,
		EncryptedData: []byte("encrypted-data"),
		Nonce:         []byte("nonce1234567"),
		Metadata:      []byte(`{}`),
	}

	return db.CreateTestSecretFull(secret)
}

func (db *TestDB) CreateTestSecretFull(secret *repository.Secret) *repository.Secret {
	db.t.Helper()

	ctx := context.Background()
	query := `
		INSERT INTO secrets (user_id, name, type, encrypted_data, nonce, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
	`

	var created repository.Secret
	err := db.pool.QueryRow(ctx, query,
		secret.UserID,
		secret.Name,
		secret.Type,
		secret.EncryptedData,
		secret.Nonce,
		secret.Metadata,
	).Scan(
		&created.ID,
		&created.UserID,
		&created.Name,
		&created.Type,
		&created.EncryptedData,
		&created.Nonce,
		&created.Metadata,
		&created.Version,
		&created.IsDeleted,
		&created.CreatedAt,
		&created.UpdatedAt,
	)
	require.NoError(db.t, err, "failed to create full test secret")

	return &created
}

func (db *TestDB) CreateTestSecrets(userID uuid.UUID, count int) []*repository.Secret {
	db.t.Helper()

	secrets := make([]*repository.Secret, count)
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("Test Secret %d", i+1)
		secrets[i] = db.CreateTestSecret(userID, name)

		// Small delay to ensure different timestamps
		if i < count-1 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	return secrets
}

func (db *TestDB) CreateDeletedSecret(userID uuid.UUID, name string) *repository.Secret {
	db.t.Helper()

	secret := db.CreateTestSecret(userID, name)
	db.DeleteSecret(secret.ID, secret.Version)

	return secret
}

// MustExec executes a SQL statement and fails the test on error.
// Useful for setting up test data with custom SQL.
func (db *TestDB) MustExec(query string, args ...interface{}) {
	db.t.Helper()

	ctx := context.Background()
	_, err := db.pool.Exec(ctx, query, args...)
	require.NoError(db.t, err, "failed to execute query: %s", query)
}

// GetSecretByID retrieves a secret by ID for verification.
// Fails the test if the secret is not found.
func (db *TestDB) GetSecretByID(secretID uuid.UUID) *repository.Secret {
	db.t.Helper()

	ctx := context.Background()
	query := `
		SELECT id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
		FROM secrets
		WHERE id = $1 AND is_deleted = FALSE
	`

	var secret repository.Secret
	err := db.pool.QueryRow(ctx, query, secretID).Scan(
		&secret.ID,
		&secret.UserID,
		&secret.Name,
		&secret.Type,
		&secret.EncryptedData,
		&secret.Nonce,
		&secret.Metadata,
		&secret.Version,
		&secret.IsDeleted,
		&secret.CreatedAt,
		&secret.UpdatedAt,
	)
	require.NoError(db.t, err, "failed to get secret by ID")

	return &secret
}

// GetUserByID retrieves a user by ID for verification.
// Fails the test if the user is not found.
func (db *TestDB) GetUserByID(userID uuid.UUID) *repository.User {
	db.t.Helper()

	ctx := context.Background()
	query := `
		SELECT id, email, password_hash, encryption_key_verifier, salt, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	var user repository.User
	err := db.pool.QueryRow(ctx, query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EncryptionKeyVerifier,
		&user.Salt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	require.NoError(db.t, err, "failed to get user by ID")

	return &user
}

// GetUserByEmail retrieves a user by email for verification.
// Fails the test if the user is not found.
func (db *TestDB) GetUserByEmail(email string) *repository.User {
	db.t.Helper()

	ctx := context.Background()
	query := `
		SELECT id, email, password_hash, encryption_key_verifier, salt, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	var user repository.User
	err := db.pool.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EncryptionKeyVerifier,
		&user.Salt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	require.NoError(db.t, err, "failed to get user by email")

	return &user
}

// ListSecretsByUser retrieves all secrets for a user.
func (db *TestDB) ListSecretsByUser(userID uuid.UUID) []*repository.Secret {
	db.t.Helper()

	ctx := context.Background()
	query := `
		SELECT id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
		FROM secrets
		WHERE user_id = $1 AND is_deleted = FALSE
		ORDER BY updated_at DESC
		LIMIT 1000
	`

	rows, err := db.pool.Query(ctx, query, userID)
	require.NoError(db.t, err, "failed to list secrets by user")
	defer rows.Close()

	var secrets []*repository.Secret
	for rows.Next() {
		var secret repository.Secret
		err := rows.Scan(
			&secret.ID,
			&secret.UserID,
			&secret.Name,
			&secret.Type,
			&secret.EncryptedData,
			&secret.Nonce,
			&secret.Metadata,
			&secret.Version,
			&secret.IsDeleted,
			&secret.CreatedAt,
			&secret.UpdatedAt,
		)
		require.NoError(db.t, err, "failed to scan secret")
		secrets = append(secrets, &secret)
	}

	require.NoError(db.t, rows.Err(), "error iterating secrets")
	return secrets
}

// ListModifiedSince retrieves secrets modified since a specific time.
func (db *TestDB) ListModifiedSince(userID uuid.UUID, since time.Time) []*repository.Secret {
	db.t.Helper()

	ctx := context.Background()
	query := `
		SELECT id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
		FROM secrets
		WHERE user_id = $1 AND updated_at > $2
		ORDER BY updated_at ASC
		LIMIT 1000
	`

	rows, err := db.pool.Query(ctx, query, userID, since)
	require.NoError(db.t, err, "failed to list modified secrets")
	defer rows.Close()

	var secrets []*repository.Secret
	for rows.Next() {
		var secret repository.Secret
		err := rows.Scan(
			&secret.ID,
			&secret.UserID,
			&secret.Name,
			&secret.Type,
			&secret.EncryptedData,
			&secret.Nonce,
			&secret.Metadata,
			&secret.Version,
			&secret.IsDeleted,
			&secret.CreatedAt,
			&secret.UpdatedAt,
		)
		require.NoError(db.t, err, "failed to scan secret")
		secrets = append(secrets, &secret)
	}

	require.NoError(db.t, rows.Err(), "error iterating secrets")
	return secrets
}

// UpdateSecret updates a secret in the database.
// Fails the test if the update fails.
func (db *TestDB) UpdateSecret(secret *repository.Secret) *repository.Secret {
	db.t.Helper()

	ctx := context.Background()
	query := `
		UPDATE secrets
		SET name = $1, type = $2, encrypted_data = $3, nonce = $4, metadata = $5,
		    version = version + 1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $6 AND version = $7
		RETURNING id, user_id, name, type, encrypted_data, nonce, metadata, version, is_deleted, created_at, updated_at
	`

	var updated repository.Secret
	err := db.pool.QueryRow(ctx, query,
		secret.Name,
		secret.Type,
		secret.EncryptedData,
		secret.Nonce,
		secret.Metadata,
		secret.ID,
		secret.Version,
	).Scan(
		&updated.ID,
		&updated.UserID,
		&updated.Name,
		&updated.Type,
		&updated.EncryptedData,
		&updated.Nonce,
		&updated.Metadata,
		&updated.Version,
		&updated.IsDeleted,
		&updated.CreatedAt,
		&updated.UpdatedAt,
	)
	require.NoError(db.t, err, "failed to update secret")

	return &updated
}

// DeleteSecret soft-deletes a secret.
// Fails the test if the delete fails.
func (db *TestDB) DeleteSecret(secretID uuid.UUID, version int64) {
	db.t.Helper()

	ctx := context.Background()
	query := `
		UPDATE secrets
		SET is_deleted = TRUE, version = version + 1, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1 AND version = $2
	`

	result, err := db.pool.Exec(ctx, query, secretID, version)
	require.NoError(db.t, err, "failed to delete secret")

	rowsAffected := result.RowsAffected()
	require.Equal(db.t, int64(1), rowsAffected, "expected 1 row affected, got %d", rowsAffected)
}

// AssertSecretExists verifies that a secret exists and is not deleted.
func (db *TestDB) AssertSecretExists(secretID uuid.UUID) {
	db.t.Helper()

	secret := db.GetSecretByID(secretID)
	require.False(db.t, secret.IsDeleted, "expected secret to exist (not deleted)")
}

// AssertSecretNotFound verifies that a secret does not exist or is deleted.
func (db *TestDB) AssertSecretNotFound(secretID uuid.UUID) {
	db.t.Helper()

	ctx := context.Background()
	query := `
		SELECT id FROM secrets
		WHERE id = $1 AND is_deleted = FALSE
	`

	var id uuid.UUID
	err := db.pool.QueryRow(ctx, query, secretID).Scan(&id)
	require.Error(db.t, err, "expected secret not found error")
}

// AssertSecretDeleted verifies that a secret is soft-deleted.
func (db *TestDB) AssertSecretDeleted(secretID uuid.UUID) {
	db.t.Helper()

	// Try to get the secret - it should return ErrNotFound because Get excludes deleted
	db.AssertSecretNotFound(secretID)
}

// AssertUserExists verifies that a user exists.
func (db *TestDB) AssertUserExists(userID uuid.UUID) {
	db.t.Helper()

	_ = db.GetUserByID(userID) // Will fail test if not found
}

// AssertSecretCount verifies the number of secrets for a user.
func (db *TestDB) AssertSecretCount(userID uuid.UUID, expectedCount int) {
	db.t.Helper()

	secrets := db.ListSecretsByUser(userID)
	require.Len(db.t, secrets, expectedCount, "unexpected secret count for user")
}

// CountSecrets returns the total number of non-deleted secrets for a user.
func (db *TestDB) CountSecrets(userID uuid.UUID) int {
	db.t.Helper()

	secrets := db.ListSecretsByUser(userID)
	return len(secrets)
}

// CreateRefreshToken creates a refresh token for a user.
func (db *TestDB) CreateRefreshToken(userID uuid.UUID, deviceID string) *repository.RefreshToken {
	db.t.Helper()

	ctx := context.Background()
	tokenHash := []byte(fmt.Sprintf("hash-%s", uuid.New().String()))
	expiresAt := time.Now().Add(24 * time.Hour)

	query := `
		INSERT INTO refresh_tokens (user_id, token_hash, device_id, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, user_id, token_hash, device_id, expires_at, created_at
	`

	var token repository.RefreshToken
	deviceIDPtr := &deviceID
	err := db.pool.QueryRow(ctx, query, userID, tokenHash, deviceIDPtr, expiresAt).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.DeviceID,
		&token.ExpiresAt,
		&token.CreatedAt,
	)
	require.NoError(db.t, err, "failed to create refresh token")

	return &token
}

// RevokeRefreshToken revokes a refresh token by deleting it.
func (db *TestDB) RevokeRefreshToken(tokenID uuid.UUID) {
	db.t.Helper()

	ctx := context.Background()
	query := `DELETE FROM refresh_tokens WHERE id = $1`

	result, err := db.pool.Exec(ctx, query, tokenID)
	require.NoError(db.t, err, "failed to revoke refresh token")

	rowsAffected := result.RowsAffected()
	require.Equal(db.t, int64(1), rowsAffected, "expected 1 row affected, got %d", rowsAffected)
}

// WaitForDBPropagation adds a small delay to ensure database operations have propagated.
// Useful for timing-dependent tests.
func (db *TestDB) WaitForDBPropagation() {
	db.t.Helper()
	time.Sleep(50 * time.Millisecond)
}

package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/koyif/keyper/internal/server/repository"
)

func TestTransactor_WithTransaction_Success(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	transactor := NewTransactor(pool)
	ctx := context.Background()

	var userID uuid.UUID

	err := transactor.WithTransaction(ctx, func(txCtx context.Context) error {
		// Create user within transaction
		user, err := userRepo.CreateUser(txCtx, "tx@example.com", []byte("hash"), []byte("verifier"), []byte("salt"))
		if err != nil {
			return err
		}
		userID = user.ID

		// Create secret within same transaction
		secret := &repository.Secret{
			UserID:        user.ID,
			Name:          "TX Secret",
			Type:          1,
			EncryptedData: []byte("data"),
			Nonce:         []byte("nonce"),
			Metadata:      []byte(`{}`),
		}
		_, err = secretRepo.Create(txCtx, secret)
		return err
	})

	require.NoError(t, err)

	// Verify both user and secret were committed
	user, err := userRepo.GetUserByID(ctx, userID)
	require.NoError(t, err)
	assert.NotNil(t, user)

	secrets, err := secretRepo.ListByUser(ctx, userID, 10, 0)
	require.NoError(t, err)
	assert.Len(t, secrets, 1)
}

func TestTransactor_WithTransaction_Rollback(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	secretRepo := NewSecretRepository(pool)
	transactor := NewTransactor(pool)
	ctx := context.Background()

	email := "rollback@example.com"
	expectedErr := errors.New("intentional error")

	err := transactor.WithTransaction(ctx, func(txCtx context.Context) error {
		// Create user within transaction
		user, err := userRepo.CreateUser(txCtx, email, []byte("hash"), []byte("verifier"), []byte("salt"))
		if err != nil {
			return err
		}

		// Create secret
		secret := &repository.Secret{
			UserID:        user.ID,
			Name:          "TX Secret",
			Type:          1,
			EncryptedData: []byte("data"),
			Nonce:         []byte("nonce"),
			Metadata:      []byte(`{}`),
		}
		_, err = secretRepo.Create(txCtx, secret)
		if err != nil {
			return err
		}

		// Return error to trigger rollback
		return expectedErr
	})

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)

	// Verify user was rolled back
	_, err = userRepo.GetUserByEmail(ctx, email)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

func TestTransactor_WithTransaction_Panic(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	transactor := NewTransactor(pool)
	ctx := context.Background()

	email := "panic@example.com"

	defer func() {
		r := recover()
		require.NotNil(t, r)
		assert.Equal(t, "intentional panic", r)

		// Verify user was rolled back
		_, err := userRepo.GetUserByEmail(ctx, email)
		require.Error(t, err)
		assert.ErrorIs(t, err, repository.ErrNotFound)
	}()

	//nolint:errcheck // intentional - testing panic recovery
	_ = transactor.WithTransaction(ctx, func(txCtx context.Context) error {
		// Create user
		_, err := userRepo.CreateUser(txCtx, email, []byte("hash"), []byte("verifier"), []byte("salt"))
		if err != nil {
			return err
		}

		// Panic to trigger rollback
		panic("intentional panic")
	})
}

func TestTransactor_WithTransaction_Nested(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	transactor := NewTransactor(pool)
	ctx := context.Background()

	email := "nested@example.com"

	err := transactor.WithTransaction(ctx, func(txCtx context.Context) error {
		// Create user in outer transaction
		_, err := userRepo.CreateUser(txCtx, email, []byte("hash"), []byte("verifier"), []byte("salt"))
		if err != nil {
			return err
		}

		// Nested transaction (should reuse existing transaction)
		return transactor.WithTransaction(txCtx, func(nestedCtx context.Context) error {
			// Verify we can still access the user created in outer transaction
			user, err := userRepo.GetUserByEmail(nestedCtx, email)
			if err != nil {
				return err
			}
			assert.NotNil(t, user)
			return nil
		})
	})

	require.NoError(t, err)

	// Verify user was committed
	user, err := userRepo.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	assert.NotNil(t, user)
}

func TestTransactor_WithTransaction_NestedRollback(t *testing.T) {
	pool := setupTestDB(t)
	defer pool.Close()

	userRepo := NewUserRepository(pool)
	transactor := NewTransactor(pool)
	ctx := context.Background()

	email := "nested_rollback@example.com"
	expectedErr := errors.New("nested error")

	err := transactor.WithTransaction(ctx, func(txCtx context.Context) error {
		// Create user in outer transaction
		_, err := userRepo.CreateUser(txCtx, email, []byte("hash"), []byte("verifier"), []byte("salt"))
		if err != nil {
			return err
		}

		// Nested transaction that fails
		return transactor.WithTransaction(txCtx, func(_ context.Context) error {
			return expectedErr
		})
	})

	require.Error(t, err)
	assert.Equal(t, expectedErr, err)

	// Verify entire transaction was rolled back
	_, err = userRepo.GetUserByEmail(ctx, email)
	require.Error(t, err)
	assert.ErrorIs(t, err, repository.ErrNotFound)
}

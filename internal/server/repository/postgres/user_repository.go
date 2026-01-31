package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koyif/keyper/internal/server/repository"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{
		pool: pool,
	}
}

func (r *UserRepository) CreateUser(ctx context.Context, email string, passwordHash, encryptionKeyVerifier, salt []byte) (*repository.User, error) {
	query := `
		INSERT INTO users (email, password_hash, encryption_key_verifier, salt)
		VALUES ($1, $2, $3, $4)
		RETURNING id, email, password_hash, encryption_key_verifier, salt, created_at, updated_at
	`

	q := getQuerier(ctx, r.pool)
	var user repository.User
	err := q.QueryRow(ctx, query, email, passwordHash, encryptionKeyVerifier, salt).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EncryptionKeyVerifier,
		&user.Salt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		// Check for unique constraint violation
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("user with email %s: %w", email, repository.ErrDuplicate)
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return &user, nil
}

// Returns repository.ErrNotFound if the user doesn't exist.
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*repository.User, error) {
	query := `
		SELECT id, email, password_hash, encryption_key_verifier, salt, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	q := getQuerier(ctx, r.pool)
	var user repository.User
	err := q.QueryRow(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EncryptionKeyVerifier,
		&user.Salt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// Returns repository.ErrNotFound if the user doesn't exist.
func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*repository.User, error) {
	query := `
		SELECT id, email, password_hash, encryption_key_verifier, salt, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	q := getQuerier(ctx, r.pool)
	var user repository.User
	err := q.QueryRow(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EncryptionKeyVerifier,
		&user.Salt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *repository.User) error {
	query := `
		UPDATE users
		SET email = $2, password_hash = $3, encryption_key_verifier = $4, salt = $5, updated_at = CURRENT_TIMESTAMP
		WHERE id = $1
	`

	q := getQuerier(ctx, r.pool)
	result, err := q.Exec(ctx, query, user.ID, user.Email, user.PasswordHash, user.EncryptionKeyVerifier, user.Salt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("user with email %s: %w", user.Email, repository.ErrDuplicate)
		}
		return fmt.Errorf("failed to update user: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

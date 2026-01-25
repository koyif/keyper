package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// UserRepository defines the interface for user operations.
type UserRepository interface {
	// Create stores a new user in the database.
	Create(ctx context.Context, user *User) error

	// GetByID retrieves a user by their ID.
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)

	// GetByEmail retrieves a user by their email address.
	GetByEmail(ctx context.Context, email string) (*User, error)

	// Update updates an existing user's information.
	Update(ctx context.Context, user *User) error

	// UpdatePassword updates a user's password hash.
	UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash []byte) error

	// Delete removes a user from the database.
	Delete(ctx context.Context, id uuid.UUID) error
}

// userRepo implements UserRepository using PostgreSQL.
type userRepo struct {
	db *sql.DB
}

// NewUserRepository creates a new instance of UserRepository.
func NewUserRepository(db *sql.DB) UserRepository {
	return &userRepo{db: db}
}

// Create stores a new user in the database.
func (r *userRepo) Create(ctx context.Context, user *User) error {
	query := `
		INSERT INTO users (id, email, password_hash, encryption_key_verifier, salt, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now()
	}

	_, err := r.db.ExecContext(
		ctx,
		query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.EncryptionKeyVerifier,
		user.Salt,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		// Check for unique constraint violation on email
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return ErrDuplicate
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by their ID.
func (r *userRepo) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	query := `
		SELECT id, email, password_hash, encryption_key_verifier, salt, created_at, updated_at
		FROM users
		WHERE id = $1
	`

	var user User
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EncryptionKeyVerifier,
		&user.Salt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	return &user, nil
}

// GetByEmail retrieves a user by their email address.
func (r *userRepo) GetByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, email, password_hash, encryption_key_verifier, salt, created_at, updated_at
		FROM users
		WHERE email = $1
	`

	var user User
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.PasswordHash,
		&user.EncryptionKeyVerifier,
		&user.Salt,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// Update updates an existing user's information.
func (r *userRepo) Update(ctx context.Context, user *User) error {
	query := `
		UPDATE users
		SET email = $2, password_hash = $3, encryption_key_verifier = $4, salt = $5, updated_at = $6
		WHERE id = $1
	`

	user.UpdatedAt = time.Now()

	result, err := r.db.ExecContext(
		ctx,
		query,
		user.ID,
		user.Email,
		user.PasswordHash,
		user.EncryptionKeyVerifier,
		user.Salt,
		user.UpdatedAt,
	)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return ErrDuplicate
		}
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// UpdatePassword updates a user's password hash.
func (r *userRepo) UpdatePassword(ctx context.Context, userID uuid.UUID, passwordHash []byte) error {
	query := `
		UPDATE users
		SET password_hash = $2, updated_at = $3
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, userID, passwordHash, time.Now())
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete removes a user from the database.
func (r *userRepo) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return ErrNotFound
	}

	return nil
}

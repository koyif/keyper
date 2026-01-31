package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/koyif/keyper/internal/server/repository"
)

type RefreshTokenRepository struct {
	pool *pgxpool.Pool
}

func NewRefreshTokenRepository(pool *pgxpool.Pool) *RefreshTokenRepository {
	return &RefreshTokenRepository{
		pool: pool,
	}
}

func (r *RefreshTokenRepository) Create(ctx context.Context, userID uuid.UUID, tokenHash []byte, deviceID *string, expiresAt time.Time) (*repository.RefreshToken, error) {
	query := `
		INSERT INTO refresh_tokens (user_id, token_hash, device_id, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, user_id, token_hash, device_id, expires_at, created_at
	`

	q := getQuerier(ctx, r.pool)
	var token repository.RefreshToken
	err := q.QueryRow(ctx, query, userID, tokenHash, deviceID, expiresAt).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.DeviceID,
		&token.ExpiresAt,
		&token.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	return &token, nil
}

// Returns repository.ErrNotFound if the token doesn't exist or has expired.
func (r *RefreshTokenRepository) GetByTokenHash(ctx context.Context, tokenHash []byte) (*repository.RefreshToken, error) {
	query := `
		SELECT id, user_id, token_hash, device_id, expires_at, created_at
		FROM refresh_tokens
		WHERE token_hash = $1 AND expires_at > CURRENT_TIMESTAMP
	`

	q := getQuerier(ctx, r.pool)
	var token repository.RefreshToken
	err := q.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID,
		&token.UserID,
		&token.TokenHash,
		&token.DeviceID,
		&token.ExpiresAt,
		&token.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	return &token, nil
}

func (r *RefreshTokenRepository) DeleteByID(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM refresh_tokens WHERE id = $1`

	q := getQuerier(ctx, r.pool)
	result, err := q.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	if result.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return nil
}

// Returns the number of tokens deleted.
func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at <= CURRENT_TIMESTAMP`

	q := getQuerier(ctx, r.pool)
	result, err := q.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}

	return result.RowsAffected(), nil
}

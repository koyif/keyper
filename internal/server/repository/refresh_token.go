package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// RefreshTokenRepository defines the interface for refresh token operations.
type RefreshTokenRepository interface {
	// Create creates a new refresh token and returns it with generated ID.
	Create(ctx context.Context, userID uuid.UUID, tokenHash []byte, deviceID *string, expiresAt time.Time) (*RefreshToken, error)

	// GetByTokenHash retrieves a refresh token by its hash.
	GetByTokenHash(ctx context.Context, tokenHash []byte) (*RefreshToken, error)

	// DeleteByID deletes a specific refresh token by ID.
	DeleteByID(ctx context.Context, id uuid.UUID) error

	// DeleteExpired removes all expired refresh tokens.
	DeleteExpired(ctx context.Context) (int64, error)
}

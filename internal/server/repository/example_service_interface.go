package repository

// This file demonstrates how consuming code (e.g., service layer) would define
// interfaces for what they need from repositories, following Go best practices.
//
// Services should define minimal interfaces that include only the methods they use.
// This keeps dependencies clear and makes testing easier.

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Example: AuthService might define this interface.
// It only needs user creation and lookup by email, not lookup by ID.
//
//nolint:unused // example interface for documentation
type authUserRepository interface {
	CreateUser(ctx context.Context, params CreateUserParams) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
}

// Example: SecretsService might define this interface.
// It needs full CRUD but not the sync-specific ListModifiedSince.
//
//nolint:unused // example interface for documentation
type secretsRepository interface {
	Create(ctx context.Context, secret *Secret) (*Secret, error)
	Get(ctx context.Context, id uuid.UUID) (*Secret, error)
	Update(ctx context.Context, secret *Secret) (*Secret, error)
	Delete(ctx context.Context, id uuid.UUID, currentVersion int64) error
	ListByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*Secret, error)
}

// Example: SyncService would define a different interface.
// It needs the sync-specific method but not regular listing.
//
//nolint:unused // example interface for documentation
type syncSecretRepository interface {
	Get(ctx context.Context, id uuid.UUID) (*Secret, error)
	Create(ctx context.Context, secret *Secret) (*Secret, error)
	Update(ctx context.Context, secret *Secret) (*Secret, error)
	ListModifiedSince(ctx context.Context, userID uuid.UUID, since time.Time, limit int) ([]*Secret, error)
}

// Example: TokenService interface.
//
//nolint:unused // example interface for documentation
type exampleRefreshTokenRepository interface {
	Create(ctx context.Context, userID uuid.UUID, tokenHash []byte, deviceID *string, expiresAt time.Time) (*RefreshToken, error)
	GetByTokenHash(ctx context.Context, tokenHash []byte) (*RefreshToken, error)
	DeleteByID(ctx context.Context, id uuid.UUID) error
}

// Example: A background cleanup job might only need this.
//
//nolint:unused // example interface for documentation
type exampleTokenCleanupRepository interface {
	DeleteExpired(ctx context.Context) (int64, error)
}

// The actual service structs would look like this:

// type AuthService struct {
//     users authUserRepository  // Accepts the interface, not the concrete type
// }
//
// func NewAuthService(users authUserRepository) *AuthService {
//     return &AuthService{users: users}
// }

// When wiring up the application, pass the concrete implementation:

// pool := db.NewPool(ctx, cfg)
// userRepo := postgres.NewUserRepository(pool)  // Returns concrete type
// authService := NewAuthService(userRepo)        // Accepts interface
//
// The concrete UserRepository satisfies authUserRepository interface implicitly.

package repository

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user entity in the database.
type User struct {
	ID                    uuid.UUID
	Email                 string
	PasswordHash          []byte
	EncryptionKeyVerifier []byte
	Salt                  []byte
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// CreateUserParams holds the parameters for creating a new user.
type CreateUserParams struct {
	Email                 string
	PasswordHash          []byte
	EncryptionKeyVerifier []byte
	Salt                  []byte
}

// Secret represents an encrypted secret entity in the database.
type Secret struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Name          string
	Type          int32
	EncryptedData []byte
	Nonce         []byte
	Metadata      []byte // JSON-encoded metadata
	Version       int64
	IsDeleted     bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// RefreshToken represents a refresh token entity in the database.
type RefreshToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TokenHash []byte
	DeviceID  *string // Nullable
	ExpiresAt time.Time
	CreatedAt time.Time
}

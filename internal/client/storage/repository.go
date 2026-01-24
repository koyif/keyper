package storage

import (
	"context"
	"time"

	"github.com/koy/keyper/pkg/api/proto"
)

// SyncStatus represents the synchronization status of a secret
type SyncStatus string

const (
	SyncStatusSynced   SyncStatus = "synced"
	SyncStatusPending  SyncStatus = "pending"
	SyncStatusConflict SyncStatus = "conflict"
)

// LocalSecret represents a secret stored locally in SQLite
type LocalSecret struct {
	ID             string
	Name           string
	Type           proto.SecretType
	EncryptedData  []byte
	Nonce          []byte
	Metadata       string // JSON string
	Version        int64
	IsDeleted      bool
	SyncStatus     SyncStatus
	ServerVersion  int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LocalUpdatedAt time.Time
}

// Repository defines the interface for secret storage operations
type Repository interface {
	// Create creates a new secret
	Create(ctx context.Context, secret *LocalSecret) error

	// Get retrieves a secret by ID
	Get(ctx context.Context, id string) (*LocalSecret, error)

	// GetByName retrieves a secret by name
	GetByName(ctx context.Context, name string) (*LocalSecret, error)

	// Update updates an existing secret
	Update(ctx context.Context, secret *LocalSecret) error

	// Delete soft-deletes a secret (sets is_deleted flag)
	Delete(ctx context.Context, id string) error

	// HardDelete permanently removes a secret from the database
	HardDelete(ctx context.Context, id string) error

	// List retrieves all secrets with optional filters
	List(ctx context.Context, filters ListFilters) ([]*LocalSecret, error)

	// GetPendingSync retrieves all secrets that need to be synced
	GetPendingSync(ctx context.Context) ([]*LocalSecret, error)

	// UpdateSyncStatus updates the sync status of a secret
	UpdateSyncStatus(ctx context.Context, id string, status SyncStatus, serverVersion int64) error

	// Close closes the database connection
	Close() error
}

// ListFilters defines filters for listing secrets
type ListFilters struct {
	Type           *proto.SecretType
	SyncStatus     *SyncStatus
	IncludeDeleted bool
	Limit          int
	Offset         int
}

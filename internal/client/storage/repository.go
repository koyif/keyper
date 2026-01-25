package storage

import (
	"context"
	"errors"
	"time"

	"github.com/koyif/keyper/pkg/api/proto"
)

// ErrSecretNotFound is returned when a secret is not found in the repository.
var ErrSecretNotFound = errors.New("secret not found")

// ErrConflictNotFound is returned when a conflict is not found in the repository.
var ErrConflictNotFound = errors.New("conflict not found")

// SyncStatus represents the synchronization status of a secret.
type SyncStatus string

const (
	SyncStatusSynced   SyncStatus = "synced"
	SyncStatusPending  SyncStatus = "pending"
	SyncStatusConflict SyncStatus = "conflict"
)

// LocalSecret represents a secret stored locally in SQLite.
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

// Conflict represents a synchronization conflict stored in the conflicts table.
type Conflict struct {
	ID                 int64
	SecretID           string
	ConflictType       proto.ConflictType
	LocalVersion       int64
	ServerVersion      int64
	LocalData          []byte
	ServerData         []byte
	LocalUpdatedAt     time.Time
	ServerUpdatedAt    time.Time
	DetectedAt         time.Time
	Resolved           bool
	ResolvedAt         *time.Time
	ResolutionStrategy string
}

// Repository defines the interface for secret storage operations.
type Repository interface {
	// Create creates a new secret.
	Create(ctx context.Context, secret *LocalSecret) error

	// Get retrieves a secret by ID.
	Get(ctx context.Context, id string) (*LocalSecret, error)

	// GetByName retrieves a secret by name.
	GetByName(ctx context.Context, name string) (*LocalSecret, error)

	// Update updates an existing secret.
	Update(ctx context.Context, secret *LocalSecret) error

	// Delete soft-deletes a secret (sets is_deleted flag).
	Delete(ctx context.Context, id string) error

	// HardDelete permanently removes a secret from the database.
	HardDelete(ctx context.Context, id string) error

	// List retrieves all secrets with optional filters.
	List(ctx context.Context, filters ListFilters) ([]*LocalSecret, error)

	// GetPendingSync retrieves all secrets that need to be synced.
	GetPendingSync(ctx context.Context) ([]*LocalSecret, error)

	// UpdateSyncStatus updates the sync status of a secret.
	UpdateSyncStatus(ctx context.Context, id string, status SyncStatus, serverVersion int64) error

	// CreateConflict stores a conflict for later resolution.
	CreateConflict(ctx context.Context, conflict *Conflict) error

	// GetUnresolvedConflicts retrieves all unresolved conflicts.
	GetUnresolvedConflicts(ctx context.Context) ([]*Conflict, error)

	// ResolveConflict marks a conflict as resolved.
	ResolveConflict(ctx context.Context, id int64, strategy string) error

	// Close closes the database connection.
	Close() error
}

// ListFilters defines filters for listing secrets.
type ListFilters struct {
	Type           *proto.SecretType
	SyncStatus     *SyncStatus
	IncludeDeleted bool
	Limit          int
	Offset         int
}

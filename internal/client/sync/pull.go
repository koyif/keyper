package sync

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/crypto"
	pb "github.com/koy/keyper/pkg/api/proto"
)

// PullResult contains the result of a Pull operation.
type PullResult struct {
	Secrets          []*pb.Secret
	DeletedSecretIDs []string
	CurrentVersion   int64
	SyncTime         time.Time
	HasConflicts     bool
	Conflicts        []*pb.Conflict
}

// Pull fetches secrets from the server that have been modified since the last sync.
// It uses the last_sync_at timestamp from the config and the device ID to identify this client.
// Returns a PullResult containing all modified/new secrets and deleted secret IDs from the server.
func Pull(ctx context.Context, cfg *config.Config, sess *session.Session) (*PullResult, error) {
	// Ensure we have a valid session
	if !sess.IsAuthenticated() {
		return nil, fmt.Errorf("not authenticated")
	}

	// Ensure token is valid, refresh if necessary
	if err := sess.EnsureValidToken(cfg.Server, grpc.WithTransportCredentials(insecure.NewCredentials())); err != nil {
		return nil, fmt.Errorf("failed to ensure valid token: %w", err)
	}

	// Get or create device ID
	deviceID, err := GetDeviceID(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get device ID: %w", err)
	}

	// Parse last sync timestamp from config
	var lastSyncTime *timestamppb.Timestamp
	if cfg.LastSyncAt != "" {
		t, err := time.Parse(time.RFC3339, cfg.LastSyncAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse last_sync_at timestamp: %w", err)
		}
		lastSyncTime = timestamppb.New(t)
	}

	// Connect to server
	conn, err := grpc.NewClient(cfg.Server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Create SyncService client
	client := pb.NewSyncServiceClient(conn)

	// Add authentication token to context
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + sess.GetAccessToken(),
		"device-id":     deviceID,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Set timeout for the request
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Build Pull request
	req := &pb.PullRequest{
		LastSyncVersion: 0, // TODO: Implement version tracking in future
		LastSyncTime:    lastSyncTime,
	}

	// Call server Pull endpoint
	resp, err := client.Pull(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("pull request failed: %w", err)
	}

	// Parse response
	result := &PullResult{
		Secrets:          resp.Secrets,
		DeletedSecretIDs: resp.DeletedSecretIds,
		CurrentVersion:   resp.CurrentVersion,
		SyncTime:         resp.SyncTime.AsTime(),
		HasConflicts:     resp.HasConflicts,
		Conflicts:        resp.Conflicts,
	}

	// Update last_sync_at in config after successful pull
	syncTimeStr := result.SyncTime.Format(time.RFC3339)
	if err := UpdateLastSyncAt(cfg, syncTimeStr); err != nil {
		return nil, fmt.Errorf("failed to update last_sync_at: %w", err)
	}

	return result, nil
}

// PullAndSync performs a complete pull operation including decryption and local database merge.
// This is the high-level function that orchestrates the entire pull-decrypt-merge workflow.
func PullAndSync(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository) error {
	// Ensure we have an encryption key
	encryptionKey := sess.GetEncryptionKey()
	if encryptionKey == nil {
		return fmt.Errorf("no encryption key available in session")
	}

	// Pull secrets from server
	result, err := Pull(ctx, cfg, sess)
	if err != nil {
		return fmt.Errorf("failed to pull from server: %w", err)
	}

	// Decrypt secrets
	decryptedSecrets, err := decryptSecrets(result.Secrets, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt secrets: %w", err)
	}

	// Merge to local database
	if err := mergeToLocalDB(ctx, cfg, repo, decryptedSecrets, result.DeletedSecretIDs, result.CurrentVersion); err != nil {
		return fmt.Errorf("failed to merge to local database: %w", err)
	}

	return nil
}

// decryptSecrets validates decryption of secrets and prepares them for local storage.
// The encrypted_data is kept encrypted for storage, but we validate it can be decrypted.
// Returns a slice of LocalSecret structs ready for database insertion.
func decryptSecrets(secrets []*pb.Secret, encryptionKey []byte) ([]*storage.LocalSecret, error) {
	if len(secrets) == 0 {
		return nil, nil
	}

	prepared := make([]*storage.LocalSecret, 0, len(secrets))

	for _, secret := range secrets {
		// Validate that we can decrypt the encrypted_data field
		// This ensures the encryption key is correct and data is not corrupted
		_, err := crypto.Decrypt(secret.EncryptedData, encryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", secret.Id, err)
		}

		// Parse metadata as JSON if present
		var metadataJSON string
		if secret.Metadata != nil {
			metadataBytes, err := json.Marshal(secret.Metadata)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal metadata for secret %s: %w", secret.Id, err)
			}
			metadataJSON = string(metadataBytes)
		}

		// Decode the base64 encrypted data to bytes for local storage
		// The encrypted_data from proto is base64-encoded string
		encryptedBytes := []byte(secret.EncryptedData)

		// Extract nonce from the encrypted data
		// AES-GCM format: [nonce (12 bytes)][ciphertext][tag (16 bytes)]
		var nonce []byte
		if len(encryptedBytes) >= crypto.NonceSize {
			nonce = encryptedBytes[:crypto.NonceSize]
		}

		// Create LocalSecret struct
		localSecret := &storage.LocalSecret{
			ID:             secret.Id,
			Name:           secret.Title,
			Type:           secret.Type,
			EncryptedData:  encryptedBytes, // Keep encrypted for local storage
			Nonce:          nonce,
			Metadata:       metadataJSON,
			Version:        secret.Version,
			IsDeleted:      secret.IsDeleted,
			SyncStatus:     storage.SyncStatusSynced,
			ServerVersion:  secret.Version,
			CreatedAt:      secret.CreatedAt.AsTime(),
			UpdatedAt:      secret.UpdatedAt.AsTime(),
			LocalUpdatedAt: time.Now(),
		}

		prepared = append(prepared, localSecret)
	}

	return prepared, nil
}

// determineConflictType identifies the type of conflict based on deletion states.
func determineConflictType(existing *storage.LocalSecret, server *storage.LocalSecret) pb.ConflictType {
	if existing.IsDeleted && !server.IsDeleted {
		return pb.ConflictType_CONFLICT_TYPE_DELETED_MODIFIED
	}
	if !existing.IsDeleted && server.IsDeleted {
		return pb.ConflictType_CONFLICT_TYPE_MODIFIED_DELETED
	}
	return pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED
}

// storeConflict creates a conflict record in the database and updates the secret's status.
// Side effects: Modifies existing.SyncStatus to storage.SyncStatusConflict when strategy is not "last-write-wins-server".
func storeConflict(ctx context.Context, tx *sql.Tx, repo *storage.SQLiteRepository, secretID string, conflictType pb.ConflictType, existing *storage.LocalSecret, server *storage.LocalSecret, resolved bool, strategy string) error {
	conflict := &storage.Conflict{
		SecretID:           secretID,
		ConflictType:       conflictType,
		LocalVersion:       existing.Version,
		ServerVersion:      server.ServerVersion,
		LocalData:          existing.EncryptedData,
		ServerData:         server.EncryptedData,
		LocalUpdatedAt:     existing.UpdatedAt,
		ServerUpdatedAt:    server.UpdatedAt,
		Resolved:           resolved,
		ResolutionStrategy: strategy,
	}

	if err := repo.CreateConflictInTx(ctx, tx, conflict); err != nil {
		return fmt.Errorf("failed to store conflict: %w", err)
	}

	// Mark secret as in conflict status (if not applying server version)
	if strategy != "last-write-wins-server" {
		existing.SyncStatus = storage.SyncStatusConflict
		if err := repo.UpdateInTx(ctx, tx, existing); err != nil {
			return fmt.Errorf("failed to update conflict status: %w", err)
		}
	}

	return nil
}

// resolveLastWriteWins resolves a conflict using the last-write-wins strategy.
func resolveLastWriteWins(ctx context.Context, tx *sql.Tx, repo *storage.SQLiteRepository, existing *storage.LocalSecret, server *storage.LocalSecret, conflictType pb.ConflictType) error {
	useLocal := existing.UpdatedAt.After(server.UpdatedAt)

	if useLocal {
		log.Printf("Conflict resolution for %s: keeping local version (local: %s, server: %s)",
			server.ID, existing.UpdatedAt.Format(time.RFC3339), server.UpdatedAt.Format(time.RFC3339))

		return storeConflict(ctx, tx, repo, server.ID, conflictType, existing, server, true, "last-write-wins-local")
	}

	log.Printf("Conflict resolution for %s: keeping server version (local: %s, server: %s)",
		server.ID, existing.UpdatedAt.Format(time.RFC3339), server.UpdatedAt.Format(time.RFC3339))

	// Store conflict for audit trail
	if err := storeConflict(ctx, tx, repo, server.ID, conflictType, existing, server, true, "last-write-wins-server"); err != nil {
		return err
	}

	// Apply server version
	if err := repo.UpdateInTx(ctx, tx, server); err != nil {
		return fmt.Errorf("failed to update secret with server version: %w", err)
	}

	return nil
}

// mergeToLocalDB merges decrypted secrets into the local SQLite database.
// It handles inserts, updates, and deletes in a single atomic transaction.
// Implements conflict detection and resolution based on config settings.
func mergeToLocalDB(ctx context.Context, cfg *config.Config, repo storage.Repository, secrets []*storage.LocalSecret, deletedIDs []string, _ int64) error {
	// We need to cast the repository to access the underlying database for transactions
	sqliteRepo, ok := repo.(*storage.SQLiteRepository)
	if !ok {
		return fmt.Errorf("repository must be a SQLiteRepository for transaction support")
	}

	// Begin transaction
	tx, err := sqliteRepo.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		// nolint:errcheck // Rollback error is expected to fail after Commit
		_ = tx.Rollback()
	}()

	// Process deletions first
	for _, id := range deletedIDs {
		if err := sqliteRepo.HardDeleteInTx(ctx, tx, id); err != nil {
			// If the secret doesn't exist, that's fine - it's already deleted
			if !errors.Is(err, storage.ErrSecretNotFound) {
				return fmt.Errorf("failed to delete secret %s: %w", id, err)
			}
		}
	}

	// Process inserts/updates
	for _, secret := range secrets {
		// Check if secret exists locally
		existing, err := sqliteRepo.GetInTx(ctx, tx, secret.ID)
		if err != nil && !errors.Is(err, storage.ErrSecretNotFound) {
			return fmt.Errorf("failed to check existing secret %s: %w", secret.ID, err)
		}

		if existing == nil {
			// Insert new secret
			if err := sqliteRepo.CreateInTx(ctx, tx, secret); err != nil {
				return fmt.Errorf("failed to insert secret %s: %w", secret.ID, err)
			}
			continue
		}

		// Check for no-conflict case first
		if existing.SyncStatus != storage.SyncStatusPending || existing.Version == secret.ServerVersion {
			// No conflict: update if server version is newer or equal
			if secret.ServerVersion >= existing.ServerVersion {
				if err := sqliteRepo.UpdateInTx(ctx, tx, secret); err != nil {
					return fmt.Errorf("failed to update secret %s: %w", secret.ID, err)
				}
			}
			continue
		}

		// Conflict detected
		log.Printf("Conflict detected for secret %s: local version %d (pending), server version %d",
			secret.ID, existing.Version, secret.ServerVersion)

		conflictType := determineConflictType(existing, secret)

		if cfg.ManualConflictResolution {
			log.Printf("Manual conflict resolution enabled for %s: storing both versions for user review", secret.ID)

			if err := storeConflict(ctx, tx, sqliteRepo, secret.ID, conflictType, existing, secret, false, "manual"); err != nil {
				return fmt.Errorf("failed to handle manual conflict for %s: %w", secret.ID, err)
			}
		} else {
			if err := resolveLastWriteWins(ctx, tx, sqliteRepo, existing, secret, conflictType); err != nil {
				return fmt.Errorf("failed to resolve conflict for %s: %w", secret.ID, err)
			}
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

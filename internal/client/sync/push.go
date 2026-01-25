package sync

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	pb "github.com/koy/keyper/pkg/api/proto"
)

// PushResult contains the result of a Push operation.
type PushResult struct {
	NewVersion        int64
	SyncTime          time.Time
	AcceptedSecretIDs []string
	Conflicts         []*pb.Conflict
	Message           string
	PartialSuccess    bool
	FailedSecretIDs   []string
}

// Push sends local pending changes to the server.
// It queries local SQLite for secrets with sync_status='pending' and sends them to the server.
// Returns a PushResult containing the new version and list of successfully synced secret IDs.
func Push(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository) (*PushResult, error) {
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

	// Query local secrets with sync_status='pending'
	pendingSecrets, err := repo.GetPendingSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending secrets: %w", err)
	}

	// If no pending secrets, return early
	if len(pendingSecrets) == 0 {
		log.Println("No pending secrets to push")
		return &PushResult{
			Message: "No changes to push",
		}, nil
	}

	// Separate deleted and non-deleted secrets
	var secretsToSend []*pb.Secret
	var deletedIDs []string

	for _, local := range pendingSecrets {
		if local.IsDeleted {
			deletedIDs = append(deletedIDs, local.ID)
		} else {
			protoSecret, err := convertToProtoSecret(local)
			if err != nil {
				log.Printf("Warning: failed to convert secret %s: %v", local.ID, err)
				continue
			}
			secretsToSend = append(secretsToSend, protoSecret)
		}
	}

	log.Printf("Pushing %d secrets and %d deletions to server", len(secretsToSend), len(deletedIDs))

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

	// Build Push request
	req := &pb.PushRequest{
		Secrets:          secretsToSend,
		DeletedSecretIds: deletedIDs,
		BaseVersion:      0, // TODO: Implement version tracking in future
	}

	// Call server Push endpoint
	resp, err := client.Push(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("push request failed: %w", err)
	}

	// Parse response
	result := &PushResult{
		NewVersion:        resp.NewVersion,
		SyncTime:          resp.SyncTime.AsTime(),
		AcceptedSecretIDs: resp.AcceptedSecretIds,
		Conflicts:         resp.Conflicts,
		Message:           resp.Message,
	}

	// Determine if there were any failures
	acceptedSet := make(map[string]bool)
	for _, id := range resp.AcceptedSecretIds {
		acceptedSet[id] = true
	}

	// Check which secrets were not accepted
	for _, local := range pendingSecrets {
		if !acceptedSet[local.ID] {
			result.FailedSecretIDs = append(result.FailedSecretIDs, local.ID)
		}
	}

	result.PartialSuccess = len(result.FailedSecretIDs) > 0

	// Update sync status for successfully pushed secrets
	if err := updateSyncStatusAfterPush(ctx, repo, resp.AcceptedSecretIds, resp.NewVersion); err != nil {
		return nil, fmt.Errorf("failed to update sync status: %w", err)
	}

	// Handle conflicts
	if len(resp.Conflicts) > 0 {
		log.Printf("Push completed with %d conflicts", len(resp.Conflicts))
		// Mark conflicted secrets with conflict status
		for _, conflict := range resp.Conflicts {
			if err := repo.UpdateSyncStatus(ctx, conflict.SecretId, storage.SyncStatusConflict, 0); err != nil {
				log.Printf("Warning: failed to mark secret %s as conflict: %v", conflict.SecretId, err)
			}
		}
	}

	log.Printf("Push successful: %d accepted, %d conflicts, %d failed",
		len(result.AcceptedSecretIDs), len(result.Conflicts), len(result.FailedSecretIDs))

	return result, nil
}

// convertToProtoSecret converts a LocalSecret to a proto Secret.
func convertToProtoSecret(local *storage.LocalSecret) (*pb.Secret, error) {
	// Convert encrypted data to base64 string
	encryptedDataB64 := base64.StdEncoding.EncodeToString(local.EncryptedData)

	// Parse metadata JSON to proto Metadata
	var metadata *pb.Metadata
	if local.Metadata != "" {
		metadata = &pb.Metadata{}
		if err := json.Unmarshal([]byte(local.Metadata), metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	// Build proto Secret
	return &pb.Secret{
		Id:            local.ID,
		Title:         local.Name,
		Type:          local.Type,
		EncryptedData: encryptedDataB64,
		Metadata:      metadata,
		Version:       local.Version,
		IsDeleted:     local.IsDeleted,
		CreatedAt:     timestamppb.New(local.CreatedAt),
		UpdatedAt:     timestamppb.New(local.UpdatedAt),
	}, nil
}

// updateSyncStatusAfterPush updates the sync status of successfully pushed secrets.
func updateSyncStatusAfterPush(ctx context.Context, repo storage.Repository, acceptedIDs []string, newVersion int64) error {
	for _, id := range acceptedIDs {
		if err := repo.UpdateSyncStatus(ctx, id, storage.SyncStatusSynced, newVersion); err != nil {
			// Log warning but don't fail the entire operation
			log.Printf("Warning: failed to update sync status for %s: %v", id, err)
		}
	}
	return nil
}

// PushWithRetry attempts to push local changes with automatic conflict resolution and retry logic.
// If the server reports conflicts, it will:
// 1. Pull the latest server state to merge changes
// 2. Retry the push operation
// 3. Use exponential backoff between retry attempts (max 3 retries)
// 4. Mark secrets as 'conflict' status if all retries fail
func PushWithRetry(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository) (*PushResult, error) {
	const maxRetries = 3
	const baseDelay = 1 * time.Second

	var lastResult *PushResult
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Attempt push
		result, err := Push(ctx, cfg, sess, repo)
		if err != nil {
			lastErr = err
			log.Printf("Push attempt %d failed: %v", attempt+1, err)

			// If this is the last attempt, return the error
			if attempt == maxRetries {
				return nil, fmt.Errorf("push failed after %d attempts: %w", maxRetries+1, lastErr)
			}

			// Wait before retrying with exponential backoff
			delay := baseDelay * time.Duration(1<<uint(attempt))
			log.Printf("Retrying push in %v...", delay)
			time.Sleep(delay)
			continue
		}

		lastResult = result

		// Check if there are conflicts
		if len(result.Conflicts) == 0 {
			// Success - no conflicts
			if attempt > 0 {
				log.Printf("Push successful after %d retry attempts", attempt)
			}
			return result, nil
		}

		// Conflicts detected
		log.Printf("Push attempt %d: detected %d conflicts", attempt+1, len(result.Conflicts))

		// If this is the last attempt, don't retry - just return the result with conflicts
		if attempt == maxRetries {
			log.Printf("Max retry attempts (%d) reached. Conflicts remain unresolved.", maxRetries+1)
			return result, nil
		}

		// Log each conflict
		for _, conflict := range result.Conflicts {
			log.Printf("Conflict on secret %s: %s", conflict.SecretId, conflict.Description)
		}

		// Trigger Pull to fetch latest server state and merge
		log.Printf("Triggering pull to fetch latest server state and resolve conflicts...")
		if err := PullAndSync(ctx, cfg, sess, repo); err != nil {
			log.Printf("Warning: Pull failed during conflict resolution: %v", err)
			// Continue with retry anyway - the local state might still be valid
		} else {
			log.Printf("Pull completed successfully - conflicts resolved with latest server state")
		}

		// Wait before retrying with exponential backoff
		if attempt < maxRetries {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			log.Printf("Waiting %v before retry attempt %d...", delay, attempt+2)
			time.Sleep(delay)
		}
	}

	// This should not be reachable due to the loop logic, but handle it anyway
	if lastResult != nil {
		return lastResult, nil
	}
	return nil, fmt.Errorf("push failed after %d attempts: %w", maxRetries+1, lastErr)
}

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/repository"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// SyncService implements the SyncService gRPC service.
type SyncService struct {
	pb.UnimplementedSyncServiceServer

	secretRepo *postgres.SecretRepository
	transactor *postgres.Transactor
}

// NewSyncService creates a new SyncService instance.
func NewSyncService(secretRepo *postgres.SecretRepository, transactor *postgres.Transactor) *SyncService {
	return &SyncService{
		secretRepo: secretRepo,
		transactor: transactor,
	}
}

// getUserID extracts and validates user ID from context.
func (s *SyncService) getUserID(ctx context.Context) (uuid.UUID, error) {
	userIDStr, err := auth.GetUserIDFromContext(ctx)
	if err != nil {
		return uuid.Nil, err
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, status.Errorf(codes.Internal, "invalid user_id in context: %v", err)
	}

	return userID, nil
}

// decodeEncryptedData decodes base64 encrypted data and extracts nonce and ciphertext.
// The encrypted data format is: nonce (12 bytes) + ciphertext.
func decodeEncryptedData(encryptedDataB64 string) (nonce, ciphertext []byte, err error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedDataB64)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "invalid base64 encrypted_data: %v", err)
	}

	if len(encryptedBytes) < 12 {
		return nil, nil, status.Error(codes.InvalidArgument, "encrypted_data too short (must include nonce)")
	}

	return encryptedBytes[:12], encryptedBytes[12:], nil
}

// serializeMetadata serializes metadata to JSON bytes.
func serializeMetadata(metadata *pb.Metadata) ([]byte, error) {
	if metadata == nil {
		return nil, nil
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to serialize metadata: %v", err)
	}

	return metadataJSON, nil
}

// Pull retrieves changes from the server since last sync.
func (s *SyncService) Pull(ctx context.Context, req *pb.PullRequest) (*pb.PullResponse, error) {
	// Extract user ID from context (set by auth interceptor).
	userID, err := s.getUserID(ctx)
	if err != nil {
		return nil, err
	}

	// Extract device ID for logging.
	deviceID := auth.GetDeviceIDFromContext(ctx)
	log.Printf("[SyncService.Pull] user_id=%s device_id=%s last_sync_time=%v", userID, deviceID, req.LastSyncTime)

	// Get last sync time from request.
	lastSyncTime := req.LastSyncTime.AsTime()

	// Retrieve all secrets modified since last sync (includes deleted).
	// Use a reasonable limit to prevent overwhelming responses.
	const maxSecrets = 1000
	modifiedSecrets, err := s.secretRepo.ListModifiedSince(ctx, userID, lastSyncTime, maxSecrets)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve modified secrets: %v", err)
	}

	// Separate deleted secrets from active secrets.
	var secrets []*pb.Secret
	var deletedSecretIDs []string

	for _, secret := range modifiedSecrets {
		if secret.IsDeleted {
			// Add to tombstone list.
			deletedSecretIDs = append(deletedSecretIDs, secret.ID.String())
		} else {
			// Convert active secret to proto.
			pbSecret, err := convertSecretToProto(secret)
			if err != nil {
				log.Printf("[SyncService.Pull] failed to convert secret %s: %v", secret.ID, err)
				return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
			}
			secrets = append(secrets, pbSecret)
		}
	}

	log.Printf("[SyncService.Pull] returning %d secrets, %d deleted for user %s", len(secrets), len(deletedSecretIDs), userID)

	return &pb.PullResponse{
		Secrets:          secrets,
		DeletedSecretIds: deletedSecretIDs,
		SyncTime:         timestamppb.Now(),
	}, nil
}

// Push sends local changes to the server.
func (s *SyncService) Push(ctx context.Context, req *pb.PushRequest) (*pb.PushResponse, error) {
	// Extract user ID from context.
	userID, err := s.getUserID(ctx)
	if err != nil {
		return nil, err
	}

	// Extract device ID for logging.
	deviceID := auth.GetDeviceIDFromContext(ctx)
	log.Printf("[SyncService.Push] user_id=%s device_id=%s pushing %d secrets, %d deletes",
		userID, deviceID, len(req.Secrets), len(req.DeletedSecretIds))

	// Track accepted IDs and conflicts.
	var acceptedIDs []string
	var conflicts []*pb.Conflict

	// Process all changes within a transaction for atomicity.
	err = s.transactor.WithTransaction(ctx, func(txCtx context.Context) error {
		// Process secret updates/creates.
		for _, pbSecret := range req.Secrets {
			secretID, err := uuid.Parse(pbSecret.Id)
			if err != nil {
				// Skip invalid IDs but continue processing.
				log.Printf("[SyncService.Push] invalid secret_id: %s", pbSecret.Id)
				continue
			}

			// Check if secret exists on server.
			existingSecret, err := s.secretRepo.Get(txCtx, secretID)
			if err != nil && !errors.Is(err, repository.ErrNotFound) {
				return fmt.Errorf("failed to check existing secret: %w", err)
			}

			// Secret doesn't exist - this is a create operation.
			if errors.Is(err, repository.ErrNotFound) {
				created, createErr := s.createSecret(txCtx, userID, pbSecret)
				if createErr != nil {
					return createErr
				}
				acceptedIDs = append(acceptedIDs, created.ID.String())
				log.Printf("[SyncService.Push] created secret %s version %d", created.ID, created.Version)
				continue
			}

			// Secret exists - check for version conflict (last-write-wins).
			if existingSecret.Version != pbSecret.Version {
				// Version mismatch - reject with conflict.
				serverVersion, convErr := convertSecretToProto(existingSecret)
				if convErr != nil {
					log.Printf("[SyncService.Push] failed to convert server secret for conflict: %v", convErr)
				}

				clientVersion := pbSecret
				conflicts = append(conflicts, &pb.Conflict{
					SecretId:      pbSecret.Id,
					Type:          pb.ConflictType_CONFLICT_TYPE_VERSION_MISMATCH,
					ServerVersion: serverVersion,
					ClientVersion: clientVersion,
					Description:   fmt.Sprintf("version mismatch: client has v%d, server has v%d", pbSecret.Version, existingSecret.Version),
				})
				log.Printf("[SyncService.Push] conflict detected for secret %s: client v%d, server v%d",
					secretID, pbSecret.Version, existingSecret.Version)
				continue
			}

			// Versions match - accept update.
			updated, updateErr := s.updateSecret(txCtx, existingSecret, pbSecret)
			if updateErr != nil {
				if errors.Is(updateErr, repository.ErrVersionConflict) {
					// Concurrent modification - add to conflicts.
					serverVersion, convErr := convertSecretToProto(existingSecret)
					if convErr != nil {
						log.Printf("[SyncService.Push] failed to convert server secret for conflict: %v", convErr)
					}

					conflicts = append(conflicts, &pb.Conflict{
						SecretId:      pbSecret.Id,
						Type:          pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
						ServerVersion: serverVersion,
						ClientVersion: pbSecret,
						Description:   "concurrent modification detected",
					})
					continue
				}
				return updateErr
			}

			acceptedIDs = append(acceptedIDs, updated.ID.String())
			log.Printf("[SyncService.Push] updated secret %s to version %d", updated.ID, updated.Version)
		}

		// Process deletions.
		for _, secretIDStr := range req.DeletedSecretIds {
			secretID, err := uuid.Parse(secretIDStr)
			if err != nil {
				log.Printf("[SyncService.Push] invalid deleted_secret_id: %s", secretIDStr)
				continue
			}

			// Get current version for optimistic locking.
			existingSecret, err := s.secretRepo.Get(txCtx, secretID)
			if err != nil {
				if errors.Is(err, repository.ErrNotFound) {
					// Already deleted - consider this successful.
					acceptedIDs = append(acceptedIDs, secretIDStr)
					log.Printf("[SyncService.Push] secret %s already deleted", secretID)
					continue
				}
				return fmt.Errorf("failed to check secret for deletion: %w", err)
			}

			// Verify ownership.
			if existingSecret.UserID != userID {
				log.Printf("[SyncService.Push] permission denied: user %s tried to delete secret %s owned by %s",
					userID, secretID, existingSecret.UserID)
				continue
			}

			// Perform soft delete with optimistic locking.
			if err := s.secretRepo.Delete(txCtx, secretID, existingSecret.Version); err != nil {
				if errors.Is(err, repository.ErrVersionConflict) {
					// Concurrent modification - add to conflicts.
					serverVersion, convErr := convertSecretToProto(existingSecret)
					if convErr != nil {
						log.Printf("[SyncService.Push] failed to convert server secret for conflict: %v", convErr)
					}

					conflicts = append(conflicts, &pb.Conflict{
						SecretId:      secretIDStr,
						Type:          pb.ConflictType_CONFLICT_TYPE_DELETED_MODIFIED,
						ServerVersion: serverVersion,
						Description:   "secret was modified on server while client attempted deletion",
					})
					continue
				}
				return fmt.Errorf("failed to delete secret: %w", err)
			}

			acceptedIDs = append(acceptedIDs, secretIDStr)
			log.Printf("[SyncService.Push] deleted secret %s", secretID)
		}

		return nil
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to push changes: %v", err)
	}

	message := fmt.Sprintf("Pushed %d changes successfully", len(acceptedIDs))
	if len(conflicts) > 0 {
		message = fmt.Sprintf("Pushed %d changes with %d conflicts", len(acceptedIDs), len(conflicts))
	}

	log.Printf("[SyncService.Push] completed: %d accepted, %d conflicts", len(acceptedIDs), len(conflicts))

	return &pb.PushResponse{
		SyncTime:          timestamppb.Now(),
		AcceptedSecretIds: acceptedIDs,
		Conflicts:         conflicts,
		Message:           message,
	}, nil
}

// GetSyncStatus retrieves current sync status.
func (s *SyncService) GetSyncStatus(ctx context.Context, _ *pb.GetSyncStatusRequest) (*pb.GetSyncStatusResponse, error) {
	// Extract user ID from context.
	userID, err := s.getUserID(ctx)
	if err != nil {
		return nil, err
	}

	// Extract device ID for logging.
	deviceID := auth.GetDeviceIDFromContext(ctx)
	log.Printf("[SyncService.GetSyncStatus] user_id=%s device_id=%s", userID, deviceID)

	// Get count of user's secrets (non-deleted only).
	totalCount, err := s.secretRepo.CountByUser(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to count secrets: %v", err)
	}

	log.Printf("[SyncService.GetSyncStatus] user %s has %d secrets", userID, totalCount)

	return &pb.GetSyncStatusResponse{
		LastSyncTime:   timestamppb.Now(),
		TotalSecrets:   totalCount,
		PendingChanges: 0, // Client-side concept, always 0 from server perspective.
	}, nil
}

// createSecret creates a new secret from proto message.
func (s *SyncService) createSecret(ctx context.Context, userID uuid.UUID, pbSecret *pb.Secret) (*repository.Secret, error) {
	// Parse the secret ID from the client.
	secretID, err := uuid.Parse(pbSecret.Id)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid secret id: %v", err)
	}

	// Decode base64 encrypted data and extract nonce and ciphertext.
	nonce, ciphertext, err := decodeEncryptedData(pbSecret.EncryptedData)
	if err != nil {
		return nil, err
	}

	// Serialize metadata to JSON.
	metadataJSON, err := serializeMetadata(pbSecret.Metadata)
	if err != nil {
		return nil, err
	}

	// Create secret entity with client-provided ID.
	secret := &repository.Secret{
		ID:            secretID,
		UserID:        userID,
		Name:          pbSecret.Title,
		Type:          int32(pbSecret.Type),
		EncryptedData: ciphertext,
		Nonce:         nonce,
		Metadata:      metadataJSON,
	}

	// Store in database (version will be set to 1).
	created, err := s.secretRepo.Create(ctx, secret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}

	return created, nil
}

// updateSecret updates an existing secret from proto message.
func (s *SyncService) updateSecret(ctx context.Context, existing *repository.Secret, pbSecret *pb.Secret) (*repository.Secret, error) {
	// Decode base64 encrypted data and extract nonce and ciphertext.
	nonce, ciphertext, err := decodeEncryptedData(pbSecret.EncryptedData)
	if err != nil {
		return nil, err
	}

	// Serialize metadata to JSON.
	metadataJSON, err := serializeMetadata(pbSecret.Metadata)
	if err != nil {
		return nil, err
	}

	// Update fields.
	existing.Name = pbSecret.Title
	existing.Type = int32(pbSecret.Type)
	existing.EncryptedData = ciphertext
	existing.Nonce = nonce
	existing.Metadata = metadataJSON

	// Update in database (uses optimistic locking, increments version).
	updated, err := s.secretRepo.Update(ctx, existing)
	if err != nil {
		return nil, err
	}

	return updated, nil
}

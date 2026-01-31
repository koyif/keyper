package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/config"
	"github.com/koyif/keyper/internal/server/repository"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// SyncSecretRepository defines the interface for secret data access in sync operations.
// Interfaces are defined at the point of use following Go best practices.
type SyncSecretRepository interface {
	Create(ctx context.Context, secret *repository.Secret) (*repository.Secret, error)
	Get(ctx context.Context, id uuid.UUID) (*repository.Secret, error)
	Update(ctx context.Context, secret *repository.Secret) (*repository.Secret, error)
	Delete(ctx context.Context, id uuid.UUID, version int64) error
	ListModifiedSince(ctx context.Context, userID uuid.UUID, since time.Time, limit int) ([]*repository.Secret, error)
	CountByUser(ctx context.Context, userID uuid.UUID) (int32, error)
}

// Transactor defines the interface for transaction management.
type Transactor interface {
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}

type SyncService struct {
	pb.UnimplementedSyncServiceServer

	secretRepo SyncSecretRepository
	transactor Transactor
	limits     config.Limits
}

func NewSyncService(secretRepo SyncSecretRepository, transactor Transactor, limits config.Limits) *SyncService {
	return &SyncService{
		secretRepo: secretRepo,
		transactor: transactor,
		limits:     limits,
	}
}

func decodeEncryptedData(encryptedDataB64 string, nonceSize int) (nonce, ciphertext []byte, err error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedDataB64)
	if err != nil {
		return nil, nil, status.Errorf(codes.InvalidArgument, "invalid base64 encrypted_data: %v", err)
	}

	if len(encryptedBytes) < nonceSize {
		return nil, nil, status.Error(codes.InvalidArgument, "encrypted_data too short (must include nonce)") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	return encryptedBytes[:nonceSize], encryptedBytes[nonceSize:], nil
}

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

func (s *SyncService) Pull(ctx context.Context, req *pb.PullRequest) (*pb.PullResponse, error) {
	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	deviceID := auth.GetDeviceIDFromContext(ctx)
	zap.L().Debug("Pull sync request",
		zap.String("user_id", userID.String()),
		zap.String("device_id", deviceID),
		zap.Time("last_sync_time", req.LastSyncTime.AsTime()))

	lastSyncTime := req.LastSyncTime.AsTime()

	modifiedSecrets, err := s.secretRepo.ListModifiedSince(ctx, userID, lastSyncTime, s.limits.MaxSyncSecrets)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve modified secrets: %v", err)
	}

	var (
		secrets          []*pb.Secret
		deletedSecretIDs []string
	)

	for _, secret := range modifiedSecrets {
		if secret.IsDeleted {
			deletedSecretIDs = append(deletedSecretIDs, secret.ID.String())
		} else {
			pbSecret, err := convertSecretToProto(secret)
			if err != nil {
				zap.L().Error("Failed to convert secret",
					zap.String("secret_id", secret.ID.String()),
					zap.Error(err))

				return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
			}

			secrets = append(secrets, pbSecret)
		}
	}

	zap.L().Debug("Pull sync response",
		zap.Int("secrets_count", len(secrets)),
		zap.Int("deleted_count", len(deletedSecretIDs)),
		zap.String("user_id", userID.String()))

	return &pb.PullResponse{
		Secrets:          secrets,
		DeletedSecretIds: deletedSecretIDs,
		SyncTime:         timestamppb.Now(),
	}, nil
}

func (s *SyncService) Push(ctx context.Context, req *pb.PushRequest) (*pb.PushResponse, error) {
	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	deviceID := auth.GetDeviceIDFromContext(ctx)
	zap.L().Debug("Push sync request",
		zap.String("user_id", userID.String()),
		zap.String("device_id", deviceID),
		zap.Int("secrets_count", len(req.Secrets)),
		zap.Int("deletes_count", len(req.DeletedSecretIds)))

	var (
		acceptedIDs []string
		conflicts   []*pb.Conflict
	)

	err = s.transactor.WithTransaction(ctx, func(txCtx context.Context) error {
		return s.executeOperations(txCtx, userID, req, &acceptedIDs, &conflicts)
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to push changes: %v", err)
	}

	message := fmt.Sprintf("Pushed %d changes successfully", len(acceptedIDs))
	if len(conflicts) > 0 {
		message = fmt.Sprintf("Pushed %d changes with %d conflicts", len(acceptedIDs), len(conflicts))
	}

	zap.L().Debug("Push sync completed",
		zap.Int("accepted_count", len(acceptedIDs)),
		zap.Int("conflicts_count", len(conflicts)))

	return &pb.PushResponse{
		SyncTime:          timestamppb.Now(),
		AcceptedSecretIds: acceptedIDs,
		Conflicts:         conflicts,
		Message:           message,
	}, nil
}

func (s *SyncService) executeOperations(
	ctx context.Context,
	userID uuid.UUID,
	req *pb.PushRequest,
	acceptedIDs *[]string,
	conflicts *[]*pb.Conflict,
) error {
	for _, pbSecret := range req.Secrets {
		result, err := s.processSecret(ctx, userID, pbSecret)
		if err != nil {
			return err
		}

		if result != nil {
			if result.Accepted {
				*acceptedIDs = append(*acceptedIDs, result.SecretID)
			} else if result.Conflict != nil {
				*conflicts = append(*conflicts, result.Conflict)
			}
		}
	}

	for _, secretIDStr := range req.DeletedSecretIds {
		result, err := s.processDelete(ctx, userID, secretIDStr)
		if err != nil {
			return err
		}

		if result != nil {
			if result.Accepted {
				*acceptedIDs = append(*acceptedIDs, result.SecretID)
			} else if result.Conflict != nil {
				*conflicts = append(*conflicts, result.Conflict)
			}
		}
	}

	return nil
}

func (s *SyncService) processSecret(ctx context.Context, userID uuid.UUID, pbSecret *pb.Secret) (*OperationResult, error) {
	secretID, err := uuid.Parse(pbSecret.Id)
	if err != nil {
		zap.L().Warn("Invalid secret_id in push request", zap.String("secret_id", pbSecret.Id))
		return nil, nil
	}

	existingSecret, err := s.secretRepo.Get(ctx, secretID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("failed to check existing secret: %w", err)
	}

	var operation SyncOperation
	if errors.Is(err, repository.ErrNotFound) {
		operation = NewCreateOperation(s.secretRepo, pbSecret, s.limits.NonceSize)
	} else {
		operation = NewUpdateOperation(s.secretRepo, pbSecret, existingSecret, s.limits.NonceSize)
	}

	result, err := operation.Execute(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to execute sync operation: %w", err) //nolint:wrapcheck // operation error wrapped
	}

	return result, nil
}

func (s *SyncService) processDelete(ctx context.Context, userID uuid.UUID, secretIDStr string) (*OperationResult, error) {
	secretID, err := uuid.Parse(secretIDStr)
	if err != nil {
		zap.L().Warn("Invalid deleted_secret_id in push request", zap.String("secret_id", secretIDStr))
		return nil, nil
	}

	existingSecret, err := s.secretRepo.Get(ctx, secretID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return nil, fmt.Errorf("failed to check secret for deletion: %w", err)
	}

	operation := NewDeleteOperation(s.secretRepo, secretID, existingSecret)

	result, err := operation.Execute(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to execute delete operation: %w", err) //nolint:wrapcheck // operation error wrapped
	}

	return result, nil
}

func (s *SyncService) GetSyncStatus(ctx context.Context, _ *pb.GetSyncStatusRequest) (*pb.GetSyncStatusResponse, error) {
	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	deviceID := auth.GetDeviceIDFromContext(ctx)
	zap.L().Debug("GetSyncStatus request",
		zap.String("user_id", userID.String()),
		zap.String("device_id", deviceID))

	totalCount, err := s.secretRepo.CountByUser(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to count secrets: %v", err)
	}

	zap.L().Debug("GetSyncStatus response",
		zap.String("user_id", userID.String()),
		zap.Int32("total_secrets", totalCount))

	return &pb.GetSyncStatusResponse{
		LastSyncTime:   timestamppb.Now(),
		TotalSecrets:   totalCount,
		PendingChanges: 0,
	}, nil
}

package handlers

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/koyif/keyper/internal/server/repository"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// SecretCreator defines the interface for creating secrets.
type SecretCreator interface {
	Create(ctx context.Context, secret *repository.Secret) (*repository.Secret, error)
}

// SecretUpdater defines the interface for updating secrets.
type SecretUpdater interface {
	Update(ctx context.Context, secret *repository.Secret) (*repository.Secret, error)
}

// SecretDeleter defines the interface for deleting secrets.
type SecretDeleter interface {
	Delete(ctx context.Context, id uuid.UUID, version int64) error
}

type SyncOperation interface {
	Execute(ctx context.Context, userID uuid.UUID) (*OperationResult, error)
}

type OperationResult struct {
	SecretID  string
	Accepted  bool
	Conflict  *pb.Conflict
	Operation string
}

func createConflict(secretID string, conflictType pb.ConflictType, description string,
	serverSecret *repository.Secret, clientSecret *pb.Secret) *pb.Conflict {
	serverVersion, err := convertSecretToProto(serverSecret)
	if err != nil {
		zap.L().Warn("Failed to convert server secret for conflict",
			zap.String("secret_id", secretID),
			zap.Error(err))
	}

	return &pb.Conflict{
		SecretId:      secretID,
		Type:          conflictType,
		ServerVersion: serverVersion,
		ClientVersion: clientSecret,
		Description:   description,
	}
}

type CreateOperation struct {
	secretRepo SecretCreator
	pbSecret   *pb.Secret
	nonceSize  int
}

func NewCreateOperation(repo SecretCreator, pbSecret *pb.Secret, nonceSize int) *CreateOperation {
	return &CreateOperation{
		secretRepo: repo,
		pbSecret:   pbSecret,
		nonceSize:  nonceSize,
	}
}

func (op *CreateOperation) Execute(ctx context.Context, userID uuid.UUID) (*OperationResult, error) {
	secretID, err := uuid.Parse(op.pbSecret.Id)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid secret id: %v", err)
	}

	nonce, ciphertext, err := decodeEncryptedData(op.pbSecret.EncryptedData, op.nonceSize)
	if err != nil {
		return nil, err
	}

	metadataJSON, err := serializeMetadata(op.pbSecret.Metadata)
	if err != nil {
		return nil, err
	}

	secret := &repository.Secret{
		ID:            secretID,
		UserID:        userID,
		Name:          op.pbSecret.Title,
		Type:          int32(op.pbSecret.Type),
		EncryptedData: ciphertext,
		Nonce:         nonce,
		Metadata:      metadataJSON,
	}

	created, err := op.secretRepo.Create(ctx, secret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}

	zap.L().Debug("Created secret",
		zap.String("secret_id", created.ID.String()),
		zap.Int64("version", created.Version))

	return &OperationResult{
		SecretID:  created.ID.String(),
		Accepted:  true,
		Operation: "create",
	}, nil
}

type UpdateOperation struct {
	secretRepo     SecretUpdater
	pbSecret       *pb.Secret
	existingSecret *repository.Secret
	nonceSize      int
}

func NewUpdateOperation(repo SecretUpdater, pbSecret *pb.Secret, existing *repository.Secret, nonceSize int) *UpdateOperation {
	return &UpdateOperation{
		secretRepo:     repo,
		pbSecret:       pbSecret,
		existingSecret: existing,
		nonceSize:      nonceSize,
	}
}

func (op *UpdateOperation) checkVersionConflict() *OperationResult {
	if op.existingSecret.Version == op.pbSecret.Version {
		return nil
	}

	description := fmt.Sprintf("version mismatch: client has v%d, server has v%d",
		op.pbSecret.Version, op.existingSecret.Version)

	conflict := createConflict(
		op.pbSecret.Id,
		pb.ConflictType_CONFLICT_TYPE_VERSION_MISMATCH,
		description,
		op.existingSecret,
		op.pbSecret,
	)

	zap.L().Debug("Conflict detected for secret",
		zap.String("secret_id", op.existingSecret.ID.String()),
		zap.Int64("client_version", op.pbSecret.Version),
		zap.Int64("server_version", op.existingSecret.Version))

	return &OperationResult{
		SecretID:  op.pbSecret.Id,
		Accepted:  false,
		Conflict:  conflict,
		Operation: "update",
	}
}

func (op *UpdateOperation) Execute(ctx context.Context, userID uuid.UUID) (*OperationResult, error) {
	if conflict := op.checkVersionConflict(); conflict != nil {
		return conflict, nil
	}

	nonce, ciphertext, err := decodeEncryptedData(op.pbSecret.EncryptedData, op.nonceSize)
	if err != nil {
		return nil, err
	}

	metadataJSON, err := serializeMetadata(op.pbSecret.Metadata)
	if err != nil {
		return nil, err
	}

	op.existingSecret.Name = op.pbSecret.Title
	op.existingSecret.Type = int32(op.pbSecret.Type)
	op.existingSecret.EncryptedData = ciphertext
	op.existingSecret.Nonce = nonce
	op.existingSecret.Metadata = metadataJSON

	updated, err := op.secretRepo.Update(ctx, op.existingSecret)
	if err != nil {
		if errors.Is(err, repository.ErrVersionConflict) {
			conflict := createConflict(
				op.pbSecret.Id,
				pb.ConflictType_CONFLICT_TYPE_MODIFIED_MODIFIED,
				"concurrent modification detected",
				op.existingSecret,
				op.pbSecret,
			)

			return &OperationResult{
				SecretID:  op.pbSecret.Id,
				Accepted:  false,
				Conflict:  conflict,
				Operation: "update",
			}, nil
		}

		return nil, fmt.Errorf("failed to update secret: %w", err) //nolint:wrapcheck // repository error wrapped
	}

	zap.L().Debug("Updated secret",
		zap.String("secret_id", updated.ID.String()),
		zap.Int64("version", updated.Version))

	return &OperationResult{
		SecretID:  updated.ID.String(),
		Accepted:  true,
		Operation: "update",
	}, nil
}

type DeleteOperation struct {
	secretRepo     SecretDeleter
	secretID       uuid.UUID
	existingSecret *repository.Secret
}

func NewDeleteOperation(repo SecretDeleter, secretID uuid.UUID, existing *repository.Secret) *DeleteOperation {
	return &DeleteOperation{
		secretRepo:     repo,
		secretID:       secretID,
		existingSecret: existing,
	}
}

func (op *DeleteOperation) Execute(ctx context.Context, userID uuid.UUID) (*OperationResult, error) {
	if op.existingSecret == nil {
		zap.L().Debug("Secret already deleted", zap.String("secret_id", op.secretID.String()))
		return &OperationResult{
			SecretID:  op.secretID.String(),
			Accepted:  true,
			Operation: "delete",
		}, nil
	}

	if op.existingSecret.UserID != userID {
		zap.L().Warn("Permission denied: user tried to delete secret owned by another user",
			zap.String("user_id", userID.String()),
			zap.String("secret_id", op.secretID.String()),
			zap.String("owner_id", op.existingSecret.UserID.String()))
		return &OperationResult{
			SecretID:  op.secretID.String(),
			Accepted:  false,
			Operation: "delete",
		}, nil
	}

	if err := op.secretRepo.Delete(ctx, op.secretID, op.existingSecret.Version); err != nil {
		if errors.Is(err, repository.ErrVersionConflict) {
			conflict := createConflict(
				op.secretID.String(),
				pb.ConflictType_CONFLICT_TYPE_DELETED_MODIFIED,
				"secret was modified on server while client attempted deletion",
				op.existingSecret,
				nil, // DeleteOperation has no client secret
			)

			return &OperationResult{
				SecretID:  op.secretID.String(),
				Accepted:  false,
				Conflict:  conflict,
				Operation: "delete",
			}, nil
		}
		return nil, fmt.Errorf("failed to delete secret: %w", err)
	}

	zap.L().Debug("Deleted secret", zap.String("secret_id", op.secretID.String()))

	return &OperationResult{
		SecretID:  op.secretID.String(),
		Accepted:  true,
		Operation: "delete",
	}, nil
}

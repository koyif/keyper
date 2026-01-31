package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"
	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/config"
	"github.com/koyif/keyper/internal/server/repository"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// SecretRepository defines the interface for secret data access.
// Interfaces are defined at the point of use following Go best practices.
type SecretRepository interface {
	Create(ctx context.Context, secret *repository.Secret) (*repository.Secret, error)
	Get(ctx context.Context, id uuid.UUID) (*repository.Secret, error)
	Update(ctx context.Context, secret *repository.Secret) (*repository.Secret, error)
	Delete(ctx context.Context, id uuid.UUID, version int64) error
	ListByUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]*repository.Secret, error)
	Search(ctx context.Context, params postgres.SearchParams) ([]*repository.Secret, error)
}

type SecretsService struct {
	pb.UnimplementedSecretsServiceServer

	secretRepo SecretRepository
	limits     config.Limits
}

func NewSecretsService(secretRepo SecretRepository, limits config.Limits) *SecretsService {
	return &SecretsService{
		secretRepo: secretRepo,
		limits:     limits,
	}
}

func (s *SecretsService) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.CreateSecretResponse, error) {
	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	if req.Title == "" {
		return nil, status.Error(codes.InvalidArgument, "title is required")
	}
	if req.EncryptedData == "" {
		return nil, status.Error(codes.InvalidArgument, "encrypted_data is required")
	}
	if req.Type == pb.SecretType_SECRET_TYPE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "secret type must be specified")
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid base64 encrypted_data: %v", err)
	}

	if len(encryptedBytes) < s.limits.NonceSize {
		return nil, status.Error(codes.InvalidArgument, "encrypted_data too short (must include nonce)")
	}
	nonce := encryptedBytes[:s.limits.NonceSize]
	ciphertext := encryptedBytes[s.limits.NonceSize:]

	var metadataJSON []byte
	if req.Metadata != nil {
		metadataJSON, err = json.Marshal(req.Metadata)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to serialize metadata: %v", err)
		}
	}

	secret := &repository.Secret{
		UserID:        userID,
		Name:          req.Title,
		Type:          int32(req.Type),
		EncryptedData: ciphertext,
		Nonce:         nonce,
		Metadata:      metadataJSON,
	}

	created, err := s.secretRepo.Create(ctx, secret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}

	pbSecret, err := convertSecretToProto(created)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
	}

	return &pb.CreateSecretResponse{
		Secret:  pbSecret,
		Message: "Secret created successfully",
	}, nil
}

func (s *SecretsService) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	if req.SecretId == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid secret_id format: %v", err)
	}

	secret, err := s.secretRepo.Get(ctx, secretID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve secret: %v", err)
	}

	if secret.UserID != userID {
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	pbSecret, err := convertSecretToProto(secret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
	}

	return &pb.GetSecretResponse{
		Secret: pbSecret,
	}, nil
}

func (s *SecretsService) UpdateSecret(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.UpdateSecretResponse, error) {
	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	if req.SecretId == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}
	if req.Title == "" {
		return nil, status.Error(codes.InvalidArgument, "title is required")
	}
	if req.EncryptedData == "" {
		return nil, status.Error(codes.InvalidArgument, "encrypted_data is required")
	}
	if req.Version <= 0 {
		return nil, status.Error(codes.InvalidArgument, "version must be provided for optimistic locking")
	}

	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid secret_id format: %v", err)
	}

	existing, err := s.secretRepo.Get(ctx, secretID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve secret: %v", err)
	}

	if existing.UserID != userID {
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	encryptedBytes, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid base64 encrypted_data: %v", err)
	}

	if len(encryptedBytes) < s.limits.NonceSize {
		return nil, status.Error(codes.InvalidArgument, "encrypted_data too short (must include nonce)")
	}
	nonce := encryptedBytes[:s.limits.NonceSize]
	ciphertext := encryptedBytes[s.limits.NonceSize:]

	var metadataJSON []byte
	if req.Metadata != nil {
		metadataJSON, err = json.Marshal(req.Metadata)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to serialize metadata: %v", err)
		}
	}

	existing.Name = req.Title
	existing.EncryptedData = ciphertext
	existing.Nonce = nonce
	existing.Metadata = metadataJSON
	existing.Version = req.Version

	updated, err := s.secretRepo.Update(ctx, existing)
	if err != nil {
		if errors.Is(err, repository.ErrVersionConflict) {
			return nil, status.Error(codes.FailedPrecondition, "version conflict: secret was modified by another process")
		}
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to update secret: %v", err)
	}

	pbSecret, err := convertSecretToProto(updated)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
	}

	return &pb.UpdateSecretResponse{
		Secret:  pbSecret,
		Message: "Secret updated successfully",
	}, nil
}

func (s *SecretsService) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	if req.SecretId == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid secret_id format: %v", err)
	}

	secret, err := s.secretRepo.Get(ctx, secretID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve secret: %v", err)
	}

	if secret.UserID != userID {
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	if err := s.secretRepo.Delete(ctx, secretID, secret.Version); err != nil {
		if errors.Is(err, repository.ErrVersionConflict) {
			return nil, status.Error(codes.FailedPrecondition, "version conflict: secret was modified by another process")
		}
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to delete secret: %v", err)
	}

	return &pb.DeleteSecretResponse{
		Message: "Secret deleted successfully",
	}, nil
}

func (s *SecretsService) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	limit := int(req.PageSize)
	if limit <= 0 {
		limit = s.limits.DefaultPageSize
	}
	if limit > s.limits.MaxPageSize {
		limit = s.limits.MaxPageSize
	}

	offset := 0
	if req.PageToken != "" {
		fmt.Sscanf(req.PageToken, "%d", &offset)
	}

	secrets, err := s.secretRepo.ListByUser(ctx, userID, limit+1, offset)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list secrets: %v", err)
	}

	var nextPageToken string
	if len(secrets) > limit {
		secrets = secrets[:limit]
		nextPageToken = fmt.Sprintf("%d", offset+limit)
	}

	pbSecrets := make([]*pb.Secret, 0, len(secrets))
	for _, secret := range secrets {
		pbSecret, err := convertSecretToProto(secret)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
		}
		pbSecrets = append(pbSecrets, pbSecret)
	}

	return &pb.ListSecretsResponse{
		Secrets:       pbSecrets,
		NextPageToken: nextPageToken,
		TotalCount:    int32(len(pbSecrets)), //nolint:gosec // G115: len(pbSecrets) is limited by request limit
	}, nil
}

func (s *SecretsService) SearchSecrets(ctx context.Context, req *pb.SearchSecretsRequest) (*pb.SearchSecretsResponse, error) {
	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	searchParams := postgres.SearchParams{
		UserID:   userID,
		Query:    req.Query,
		Limit:    s.limits.MaxPageSize,
		Offset:   0,
		Tags:     req.Tags,
		Category: req.Category,
	}

	if req.Type != pb.SecretType_SECRET_TYPE_UNSPECIFIED {
		typeValue := int32(req.Type)
		searchParams.Type = &typeValue
	}

	if req.FavoritesOnly {
		favorite := true
		searchParams.IsFavorite = &favorite
	}

	secrets, err := s.secretRepo.Search(ctx, searchParams)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to search secrets: %v", err)
	}

	pbSecrets := make([]*pb.Secret, 0, len(secrets))
	for _, secret := range secrets {
		pbSecret, err := convertSecretToProto(secret)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
		}
		pbSecrets = append(pbSecrets, pbSecret)
	}

	return &pb.SearchSecretsResponse{
		Secrets:    pbSecrets,
		TotalCount: int32(len(pbSecrets)), //nolint:gosec // G115: len(pbSecrets) is limited by search limit
	}, nil
}

func convertSecretToProto(secret *repository.Secret) (*pb.Secret, error) {
	fullEncrypted := append(secret.Nonce, secret.EncryptedData...)
	encryptedDataB64 := base64.StdEncoding.EncodeToString(fullEncrypted)

	var metadata pb.Metadata
	if len(secret.Metadata) > 0 {
		if err := json.Unmarshal(secret.Metadata, &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &pb.Secret{
		Id:            secret.ID.String(),
		UserId:        secret.UserID.String(),
		Type:          pb.SecretType(secret.Type),
		Title:         secret.Name,
		EncryptedData: encryptedDataB64,
		Metadata:      &metadata,
		CreatedAt:     timestamppb.New(secret.CreatedAt),
		UpdatedAt:     timestamppb.New(secret.UpdatedAt),
		Version:       secret.Version,
		IsDeleted:     secret.IsDeleted,
	}, nil
}

package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"
	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/repository"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// SecretsService implements the SecretsService gRPC service.
type SecretsService struct {
	pb.UnimplementedSecretsServiceServer

	secretRepo *postgres.SecretRepository
}

// NewSecretsService creates a new SecretsService instance.
func NewSecretsService(secretRepo *postgres.SecretRepository) *SecretsService {
	return &SecretsService{
		secretRepo: secretRepo,
	}
}

// CreateSecret creates a new secret.
func (s *SecretsService) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.CreateSecretResponse, error) {
	// Extract user ID from context (set by auth interceptor).
	userIDStr, err := auth.GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid user_id in context: %v", err)
	}

	// Validate input.
	if req.Title == "" {
		return nil, status.Error(codes.InvalidArgument, "title is required")
	}
	if req.EncryptedData == "" {
		return nil, status.Error(codes.InvalidArgument, "encrypted_data is required")
	}
	if req.Type == pb.SecretType_SECRET_TYPE_UNSPECIFIED {
		return nil, status.Error(codes.InvalidArgument, "secret type must be specified")
	}

	// Decode base64 encrypted data.
	encryptedBytes, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid base64 encrypted_data: %v", err)
	}

	// Extract nonce (first 12 bytes of encrypted data).
	if len(encryptedBytes) < 12 {
		return nil, status.Error(codes.InvalidArgument, "encrypted_data too short (must include nonce)")
	}
	nonce := encryptedBytes[:12]
	ciphertext := encryptedBytes[12:]

	// Serialize metadata to JSON.
	var metadataJSON []byte
	if req.Metadata != nil {
		metadataJSON, err = json.Marshal(req.Metadata)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to serialize metadata: %v", err)
		}
	}

	// Create secret entity.
	secret := &repository.Secret{
		UserID:        userID,
		Name:          req.Title,
		Type:          int32(req.Type),
		EncryptedData: ciphertext,
		Nonce:         nonce,
		Metadata:      metadataJSON,
	}

	// Store in database.
	created, err := s.secretRepo.Create(ctx, secret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create secret: %v", err)
	}

	// Convert to proto.
	pbSecret, err := convertSecretToProto(created)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
	}

	return &pb.CreateSecretResponse{
		Secret:  pbSecret,
		Message: "Secret created successfully",
	}, nil
}

// GetSecret retrieves a specific secret by ID.
func (s *SecretsService) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.GetSecretResponse, error) {
	// Extract user ID from context.
	userIDStr, err := auth.GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid user_id in context: %v", err)
	}

	// Validate input.
	if req.SecretId == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid secret_id format: %v", err)
	}

	// Retrieve secret.
	secret, err := s.secretRepo.Get(ctx, secretID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve secret: %v", err)
	}

	// Verify ownership.
	if secret.UserID != userID {
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	// Convert to proto.
	pbSecret, err := convertSecretToProto(secret)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
	}

	return &pb.GetSecretResponse{
		Secret: pbSecret,
	}, nil
}

// UpdateSecret updates an existing secret.
func (s *SecretsService) UpdateSecret(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.UpdateSecretResponse, error) {
	// Extract user ID from context.
	userIDStr, err := auth.GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid user_id in context: %v", err)
	}

	// Validate input.
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

	// Retrieve existing secret to verify ownership.
	existing, err := s.secretRepo.Get(ctx, secretID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve secret: %v", err)
	}

	// Verify ownership.
	if existing.UserID != userID {
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	// Decode base64 encrypted data.
	encryptedBytes, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid base64 encrypted_data: %v", err)
	}

	// Extract nonce.
	if len(encryptedBytes) < 12 {
		return nil, status.Error(codes.InvalidArgument, "encrypted_data too short (must include nonce)")
	}
	nonce := encryptedBytes[:12]
	ciphertext := encryptedBytes[12:]

	// Serialize metadata to JSON.
	var metadataJSON []byte
	if req.Metadata != nil {
		metadataJSON, err = json.Marshal(req.Metadata)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to serialize metadata: %v", err)
		}
	}

	// Update secret fields.
	existing.Name = req.Title
	existing.EncryptedData = ciphertext
	existing.Nonce = nonce
	existing.Metadata = metadataJSON
	existing.Version = req.Version

	// Update in database (uses optimistic locking).
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

	// Convert to proto.
	pbSecret, err := convertSecretToProto(updated)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
	}

	return &pb.UpdateSecretResponse{
		Secret:  pbSecret,
		Message: "Secret updated successfully",
	}, nil
}

// DeleteSecret soft-deletes a secret.
func (s *SecretsService) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.DeleteSecretResponse, error) {
	// Extract user ID from context.
	userIDStr, err := auth.GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid user_id in context: %v", err)
	}

	// Validate input.
	if req.SecretId == "" {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	secretID, err := uuid.Parse(req.SecretId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid secret_id format: %v", err)
	}

	// Retrieve secret to verify ownership.
	secret, err := s.secretRepo.Get(ctx, secretID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "secret not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve secret: %v", err)
	}

	// Verify ownership.
	if secret.UserID != userID {
		return nil, status.Error(codes.PermissionDenied, "access denied")
	}

	// Soft delete (uses optimistic locking).
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

// ListSecrets retrieves all secrets for the authenticated user.
func (s *SecretsService) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	// Extract user ID from context.
	userIDStr, err := auth.GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid user_id in context: %v", err)
	}

	// Set default pagination.
	limit := int(req.PageSize)
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	// For simplicity, we're using offset-based pagination.
	// In production, consider cursor-based pagination for better performance.
	offset := 0
	if req.PageToken != "" {
		// Parse page token as offset (in real implementation, use secure tokens).
		fmt.Sscanf(req.PageToken, "%d", &offset)
	}

	// Retrieve secrets from database.
	secrets, err := s.secretRepo.ListByUser(ctx, userID, limit+1, offset)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list secrets: %v", err)
	}

	// Check if there are more results.
	var nextPageToken string
	if len(secrets) > limit {
		secrets = secrets[:limit]
		nextPageToken = fmt.Sprintf("%d", offset+limit)
	}

	// Convert to proto.
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
		TotalCount:    int32(len(pbSecrets)),
	}, nil
}

// SearchSecrets searches secrets by title, tags, or category.
func (s *SecretsService) SearchSecrets(ctx context.Context, req *pb.SearchSecretsRequest) (*pb.SearchSecretsResponse, error) {
	// Extract user ID from context.
	userIDStr, err := auth.GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid user_id in context: %v", err)
	}

	// For now, retrieve all secrets and filter in memory.
	// In production, implement database-level search with full-text search or similar.
	secrets, err := s.secretRepo.ListByUser(ctx, userID, 10000, 0)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list secrets: %v", err)
	}

	// Filter based on search criteria.
	var filtered []*repository.Secret
	query := strings.ToLower(req.Query)

	for _, secret := range secrets {
		// Type filter.
		if req.Type != pb.SecretType_SECRET_TYPE_UNSPECIFIED && secret.Type != int32(req.Type) {
			continue
		}

		// Parse metadata for filtering.
		var metadata pb.Metadata
		if len(secret.Metadata) > 0 {
			if err := json.Unmarshal(secret.Metadata, &metadata); err != nil {
				// Skip secrets with invalid metadata.
				continue
			}
		}

		// Category filter.
		if req.Category != "" && metadata.Category != req.Category {
			continue
		}

		// Favorites filter.
		if req.FavoritesOnly && !metadata.IsFavorite {
			continue
		}

		// Tags filter.
		if len(req.Tags) > 0 {
			hasAllTags := true
			for _, reqTag := range req.Tags {
				if !slices.Contains(metadata.Tags, reqTag) {
					hasAllTags = false
					break
				}
			}
			if !hasAllTags {
				continue
			}
		}

		// Query search (title, tags, notes).
		if query != "" {
			match := false

			// Search in title.
			if strings.Contains(strings.ToLower(secret.Name), query) {
				match = true
			}

			// Search in tags.
			if !match {
				for _, tag := range metadata.Tags {
					if strings.Contains(strings.ToLower(tag), query) {
						match = true
						break
					}
				}
			}

			// Search in notes.
			if !match && strings.Contains(strings.ToLower(metadata.Notes), query) {
				match = true
			}

			if !match {
				continue
			}
		}

		filtered = append(filtered, secret)
	}

	// Convert to proto.
	pbSecrets := make([]*pb.Secret, 0, len(filtered))
	for _, secret := range filtered {
		pbSecret, err := convertSecretToProto(secret)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to convert secret: %v", err)
		}
		pbSecrets = append(pbSecrets, pbSecret)
	}

	return &pb.SearchSecretsResponse{
		Secrets:    pbSecrets,
		TotalCount: int32(len(pbSecrets)),
	}, nil
}

// convertSecretToProto converts a repository.Secret to pb.Secret.
func convertSecretToProto(secret *repository.Secret) (*pb.Secret, error) {
	// Combine nonce and ciphertext, then encode as base64.
	fullEncrypted := append(secret.Nonce, secret.EncryptedData...)
	encryptedDataB64 := base64.StdEncoding.EncodeToString(fullEncrypted)

	// Parse metadata.
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

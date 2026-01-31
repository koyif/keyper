package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"
	"github.com/koyif/keyper/internal/crypto"
	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/repository"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// UserRepository defines the interface for user data access.
// Interfaces are defined at the point of use following Go best practices.
type UserRepository interface {
	CreateUser(ctx context.Context, username string, passwordHash, encryptionKeyVerifier, salt []byte) (*repository.User, error)
	GetUserByEmail(ctx context.Context, email string) (*repository.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*repository.User, error)
	Update(ctx context.Context, user *repository.User) error
}

// RefreshTokenRepository defines the interface for refresh token management.
type RefreshTokenRepository interface {
	Create(ctx context.Context, userID uuid.UUID, tokenHash []byte, deviceID *string, expiresAt time.Time) (*repository.RefreshToken, error)
	GetByTokenHash(ctx context.Context, tokenHash []byte) (*repository.RefreshToken, error)
	DeleteByID(ctx context.Context, id uuid.UUID) error
}

type AuthService struct {
	pb.UnimplementedAuthServiceServer

	userRepo         UserRepository
	refreshTokenRepo RefreshTokenRepository
	jwtManager       *auth.JWTManager
	tokenBlacklist   *auth.TokenBlacklist
}

func NewAuthService(
	userRepo UserRepository,
	refreshTokenRepo RefreshTokenRepository,
	jwtManager *auth.JWTManager,
	tokenBlacklist *auth.TokenBlacklist,
) *AuthService {
	return &AuthService{
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		jwtManager:       jwtManager,
		tokenBlacklist:   tokenBlacklist,
	}
}

func (s *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required") //nolint:wrapcheck // gRPC status error is the correct format
	}

	if req.MasterPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "master_password is required") //nolint:wrapcheck // gRPC status error is the correct format
	}

	salt, err := crypto.GenerateSalt(crypto.SaltLength)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate salt: %v", err)
	}

	passwordHash := crypto.HashMasterPassword(req.MasterPassword, salt)

	// Encryption key never sent to server, only used for verifier
	encryptionKey := crypto.DeriveKey(req.MasterPassword, salt)

	verifierStr, _, err := crypto.GenerateEncryptionKeyVerifier(encryptionKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate encryption key verifier: %v", err)
	}

	verifierBytes, err := base64.StdEncoding.DecodeString(verifierStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode verifier: %v", err)
	}

	user, err := s.userRepo.CreateUser(ctx, req.Username, passwordHash, verifierBytes, salt)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			return nil, status.Error(codes.AlreadyExists, "user with this username already exists") //nolint:wrapcheck // gRPC status errors should not be wrapped
		}

		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	accessToken, refreshToken, expiresAt, err := s.jwtManager.GenerateTokenPair(user.ID, req.DeviceInfo)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens: %v", err)
	}

	tokenHash := []byte(auth.HashRefreshToken(refreshToken))

	var deviceID *string
	if req.DeviceInfo != "" {
		deviceID = &req.DeviceInfo
	}

	_, err = s.refreshTokenRepo.Create(ctx, user.ID, tokenHash, deviceID, expiresAt.Add(auth.RefreshTokenExpiry))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store refresh token: %v", err)
	}

	return &pb.RegisterResponse{
		UserId:       user.ID.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    timestamppb.New(expiresAt),
		Message:      "User registered successfully",
	}, nil
}

func (s *AuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	if req.MasterPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "master_password is required") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	user, err := s.userRepo.GetUserByEmail(ctx, req.Username)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials") //nolint:wrapcheck // gRPC status errors should not be wrapped
		}

		return nil, status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}

	if !crypto.VerifyMasterPassword(req.MasterPassword, user.Salt, user.PasswordHash) {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	accessToken, refreshToken, expiresAt, err := s.jwtManager.GenerateTokenPair(user.ID, req.DeviceInfo)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens: %v", err)
	}

	tokenHash := []byte(auth.HashRefreshToken(refreshToken))

	var deviceID *string
	if req.DeviceInfo != "" {
		deviceID = &req.DeviceInfo
	}

	_, err = s.refreshTokenRepo.Create(ctx, user.ID, tokenHash, deviceID, expiresAt.Add(auth.RefreshTokenExpiry))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store refresh token: %v", err)
	}

	return &pb.LoginResponse{
		UserId:       user.ID.String(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    timestamppb.New(expiresAt),
		Message:      "Login successful",
	}, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	if s.tokenBlacklist.IsBlacklisted(req.RefreshToken) {
		return nil, status.Error(codes.Unauthenticated, "token has been revoked") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	claims, err := s.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token: %v", err)
	}

	tokenHash := []byte(auth.HashRefreshToken(req.RefreshToken))

	storedToken, err := s.refreshTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.Unauthenticated, "refresh token not found or expired") //nolint:wrapcheck // gRPC status errors should not be wrapped
		}

		return nil, status.Errorf(codes.Internal, "failed to verify refresh token: %v", err)
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid user_id in token: %v", err)
	}

	if storedToken.UserID != userID {
		return nil, status.Error(codes.Unauthenticated, "token user mismatch") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	newAccessToken, expiresAt, err := s.jwtManager.GenerateAccessToken(userID, claims.DeviceID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate access token: %v", err)
	}

	return &pb.RefreshTokenResponse{
		AccessToken: newAccessToken,
		ExpiresAt:   timestamppb.New(expiresAt),
		Message:     "Token refreshed successfully",
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	s.tokenBlacklist.Add(req.RefreshToken, time.Now().Add(auth.RefreshTokenExpiry))

	tokenHash := []byte(auth.HashRefreshToken(req.RefreshToken))

	storedToken, err := s.refreshTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return &pb.LogoutResponse{
				Message: "Logged out successfully",
			}, nil
		}

		return nil, status.Errorf(codes.Internal, "failed to retrieve refresh token: %v", err)
	}

	if err := s.refreshTokenRepo.DeleteByID(ctx, storedToken.ID); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete refresh token: %v", err)
	}

	return &pb.LogoutResponse{
		Message: "Logged out successfully",
	}, nil
}

func (s *AuthService) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	if req.OldPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "old_password is required") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	if req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password is required") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	userID, err := auth.GetUserIDAsUUID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err) //nolint:wrapcheck // auth package error wrapped
	}

	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "user not found") //nolint:wrapcheck // gRPC status errors should not be wrapped
		}

		return nil, status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}

	if !crypto.VerifyMasterPassword(req.OldPassword, user.Salt, user.PasswordHash) {
		return nil, status.Error(codes.Unauthenticated, "old password is incorrect") //nolint:wrapcheck // gRPC status errors should not be wrapped
	}

	newSalt, err := crypto.GenerateSalt(crypto.SaltLength)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate salt: %v", err)
	}

	newPasswordHash := crypto.HashMasterPassword(req.NewPassword, newSalt)

	newEncryptionKey := crypto.DeriveKey(req.NewPassword, newSalt)

	verifierStr, _, err := crypto.GenerateEncryptionKeyVerifier(newEncryptionKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate encryption key verifier: %v", err)
	}

	verifierBytes, err := base64.StdEncoding.DecodeString(verifierStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode verifier: %v", err)
	}

	user.PasswordHash = newPasswordHash
	user.EncryptionKeyVerifier = verifierBytes
	user.Salt = newSalt

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update password: %v", err)
	}

	deviceID := auth.GetDeviceIDFromContext(ctx)

	accessToken, refreshToken, expiresAt, err := s.jwtManager.GenerateTokenPair(userID, deviceID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens: %v", err)
	}

	tokenHash := []byte(auth.HashRefreshToken(refreshToken))

	var deviceIDPtr *string
	if deviceID != "" {
		deviceIDPtr = &deviceID
	}

	_, err = s.refreshTokenRepo.Create(ctx, userID, tokenHash, deviceIDPtr, expiresAt.Add(auth.RefreshTokenExpiry))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store refresh token: %v", err)
	}

	return &pb.ChangePasswordResponse{
		Message:      "Password changed successfully",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    timestamppb.New(expiresAt),
	}, nil
}

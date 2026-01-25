package handlers

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"
	"github.com/koyif/keyper/internal/crypto"
	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/repository"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// AuthService implements the AuthService gRPC service.
type AuthService struct {
	pb.UnimplementedAuthServiceServer

	userRepo         *postgres.UserRepository
	refreshTokenRepo *postgres.RefreshTokenRepository
	jwtManager       *auth.JWTManager
	tokenBlacklist   *auth.TokenBlacklist
}

// NewAuthService creates a new AuthService instance.
func NewAuthService(
	userRepo *postgres.UserRepository,
	refreshTokenRepo *postgres.RefreshTokenRepository,
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

// Register creates a new user account.
func (s *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Validate input.
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.MasterPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "master_password is required")
	}

	// Generate salt for password hashing.
	salt, err := crypto.GenerateSalt(crypto.SaltLength)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate salt: %v", err)
	}

	// Derive password hash for authentication.
	passwordHash := crypto.HashMasterPassword(req.MasterPassword, salt)

	// Derive encryption key (never sent to server, only used for verifier).
	encryptionKey := crypto.DeriveKey(req.MasterPassword, salt)

	// Generate encryption key verifier.
	verifierStr, _, err := crypto.GenerateEncryptionKeyVerifier(encryptionKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate encryption key verifier: %v", err)
	}

	// Decode the base64 verifier for storage.
	verifierBytes, err := base64.StdEncoding.DecodeString(verifierStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode verifier: %v", err)
	}

	// Create user in database.
	user, err := s.userRepo.CreateUser(ctx, req.Username, passwordHash, verifierBytes, salt)
	if err != nil {
		if errors.Is(err, repository.ErrDuplicate) {
			return nil, status.Error(codes.AlreadyExists, "user with this username already exists")
		}
		return nil, status.Errorf(codes.Internal, "failed to create user: %v", err)
	}

	// Generate JWT tokens.
	accessToken, refreshToken, expiresAt, err := s.jwtManager.GenerateTokenPair(user.ID, req.DeviceInfo)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens: %v", err)
	}

	// Store refresh token hash in database.
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

// Login authenticates a user and returns access/refresh tokens.
func (s *AuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Validate input.
	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username is required")
	}
	if req.MasterPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "master_password is required")
	}

	// Retrieve user by username (email).
	user, err := s.userRepo.GetUserByEmail(ctx, req.Username)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}

	// Verify password.
	if !crypto.VerifyMasterPassword(req.MasterPassword, user.Salt, user.PasswordHash) {
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}

	// Generate JWT tokens.
	accessToken, refreshToken, expiresAt, err := s.jwtManager.GenerateTokenPair(user.ID, req.DeviceInfo)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens: %v", err)
	}

	// Store refresh token hash in database.
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

// RefreshToken generates a new access token using a refresh token.
func (s *AuthService) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	// Validate input.
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	// Check if token is blacklisted.
	if s.tokenBlacklist.IsBlacklisted(req.RefreshToken) {
		return nil, status.Error(codes.Unauthenticated, "token has been revoked")
	}

	// Validate refresh token.
	claims, err := s.jwtManager.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token: %v", err)
	}

	// Verify refresh token exists in database.
	tokenHash := []byte(auth.HashRefreshToken(req.RefreshToken))
	storedToken, err := s.refreshTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.Unauthenticated, "refresh token not found or expired")
		}
		return nil, status.Errorf(codes.Internal, "failed to verify refresh token: %v", err)
	}

	// Parse user ID.
	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid user_id in token: %v", err)
	}

	// Verify user ID matches.
	if storedToken.UserID != userID {
		return nil, status.Error(codes.Unauthenticated, "token user mismatch")
	}

	// Generate new access token.
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

// Logout revokes the current refresh token.
func (s *AuthService) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	// Validate input.
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	// Add token to blacklist (for immediate invalidation of access tokens).
	s.tokenBlacklist.Add(req.RefreshToken, time.Now().Add(auth.RefreshTokenExpiry))

	// Delete refresh token from database.
	tokenHash := []byte(auth.HashRefreshToken(req.RefreshToken))
	storedToken, err := s.refreshTokenRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Token already doesn't exist, consider logout successful.
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

// ChangePassword allows authenticated users to change their password.
func (s *AuthService) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	// Validate input.
	if req.OldPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "old_password is required")
	}
	if req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "new_password is required")
	}

	// Extract user ID from context (set by auth interceptor).
	userIDStr, err := auth.GetUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid user_id in context: %v", err)
	}

	// Retrieve user.
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve user: %v", err)
	}

	// Verify old password.
	if !crypto.VerifyMasterPassword(req.OldPassword, user.Salt, user.PasswordHash) {
		return nil, status.Error(codes.Unauthenticated, "old password is incorrect")
	}

	// Generate new salt.
	newSalt, err := crypto.GenerateSalt(crypto.SaltLength)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate salt: %v", err)
	}

	// Derive new password hash.
	newPasswordHash := crypto.HashMasterPassword(req.NewPassword, newSalt)

	// Derive new encryption key and generate verifier.
	newEncryptionKey := crypto.DeriveKey(req.NewPassword, newSalt)
	verifierStr, _, err := crypto.GenerateEncryptionKeyVerifier(newEncryptionKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate encryption key verifier: %v", err)
	}

	// Decode the base64 verifier for storage.
	verifierBytes, err := base64.StdEncoding.DecodeString(verifierStr)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode verifier: %v", err)
	}

	// Update user with new password and verifier.
	user.PasswordHash = newPasswordHash
	user.EncryptionKeyVerifier = verifierBytes
	user.Salt = newSalt

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update password: %v", err)
	}

	// Generate new tokens (password change should invalidate old sessions).
	deviceID := auth.GetDeviceIDFromContext(ctx)
	accessToken, refreshToken, expiresAt, err := s.jwtManager.GenerateTokenPair(userID, deviceID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate tokens: %v", err)
	}

	// Store new refresh token.
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

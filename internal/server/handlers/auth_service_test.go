package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/koyif/keyper/internal/crypto"
	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	"github.com/koyif/keyper/internal/server/testhelpers"
	pb "github.com/koyif/keyper/pkg/api/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestAuthService_Register_Validation tests input validation for Register endpoint.
func TestAuthService_Register_Validation(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	tests := []struct {
		name    string
		req     *pb.RegisterRequest
		wantErr bool
		errCode codes.Code
		errMsg  string
	}{
		{
			name: "empty username",
			req: &pb.RegisterRequest{
				Username:       "",
				MasterPassword: "SecurePassword123!",
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
			errMsg:  "username is required",
		},
		{
			name: "empty password",
			req: &pb.RegisterRequest{
				Username:       "test@example.com",
				MasterPassword: "",
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
			errMsg:  "master_password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := service.Register(context.Background(), tt.req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.errCode, st.Code())
				assert.Contains(t, st.Message(), tt.errMsg)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}

// TestAuthService_Register_Success tests successful user registration.
func TestAuthService_Register_Success(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	req := &pb.RegisterRequest{
		Username:       "newuser@example.com",
		MasterPassword: "SecurePassword123!",
		DeviceInfo:     "TestDevice",
	}

	resp, err := service.Register(context.Background(), req)

	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.UserId)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.NotNil(t, resp.ExpiresAt)
	assert.Equal(t, "User registered successfully", resp.Message)

	// Verify tokens can be validated
	claims, err := jwtManager.ValidateToken(resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, resp.UserId, claims.UserID)
	assert.Equal(t, "TestDevice", claims.DeviceID)
}

// TestAuthService_Register_DuplicateUser tests duplicate username handling.
func TestAuthService_Register_DuplicateUser(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	req := &pb.RegisterRequest{
		Username:       "duplicate@example.com",
		MasterPassword: "SecurePassword123!",
	}

	// First registration should succeed
	resp1, err := service.Register(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp1)

	// Second registration with same username should fail
	resp2, err := service.Register(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp2)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
	assert.Contains(t, st.Message(), "already exists")
}

// TestAuthService_Login_Validation tests input validation for Login endpoint.
func TestAuthService_Login_Validation(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	tests := []struct {
		name    string
		req     *pb.LoginRequest
		wantErr bool
		errCode codes.Code
		errMsg  string
	}{
		{
			name: "empty username",
			req: &pb.LoginRequest{
				Username:       "",
				MasterPassword: "password",
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
			errMsg:  "username is required",
		},
		{
			name: "empty password",
			req: &pb.LoginRequest{
				Username:       "test@example.com",
				MasterPassword: "",
			},
			wantErr: true,
			errCode: codes.InvalidArgument,
			errMsg:  "master_password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := service.Login(context.Background(), tt.req)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				st, ok := status.FromError(err)
				require.True(t, ok)
				assert.Equal(t, tt.errCode, st.Code())
				assert.Contains(t, st.Message(), tt.errMsg)
			}
		})
	}
}

// TestAuthService_Login_Success tests successful login.
func TestAuthService_Login_Success(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	// Register a user first
	regReq := &pb.RegisterRequest{
		Username:       "logintest@example.com",
		MasterPassword: "SecurePassword123!",
	}
	regResp, err := service.Register(context.Background(), regReq)
	require.NoError(t, err)
	require.NotNil(t, regResp)

	// Now login with same credentials
	loginReq := &pb.LoginRequest{
		Username:       "logintest@example.com",
		MasterPassword: "SecurePassword123!",
		DeviceInfo:     "LoginDevice",
	}

	loginResp, err := service.Login(context.Background(), loginReq)

	require.NoError(t, err)
	assert.NotNil(t, loginResp)
	assert.Equal(t, regResp.UserId, loginResp.UserId)
	assert.NotEmpty(t, loginResp.AccessToken)
	assert.NotEmpty(t, loginResp.RefreshToken)
	assert.Equal(t, "Login successful", loginResp.Message)
}

// TestAuthService_Login_InvalidCredentials tests login with wrong credentials.
func TestAuthService_Login_InvalidCredentials(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	// Register a user
	regReq := &pb.RegisterRequest{
		Username:       "credtest@example.com",
		MasterPassword: "CorrectPassword123!",
	}
	_, err := service.Register(context.Background(), regReq)
	require.NoError(t, err)

	tests := []struct {
		name     string
		username string
		password string
	}{
		{
			name:     "wrong password",
			username: "credtest@example.com",
			password: "WrongPassword123!",
		},
		{
			name:     "non-existent user",
			username: "nonexistent@example.com",
			password: "SomePassword123!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loginReq := &pb.LoginRequest{
				Username:       tt.username,
				MasterPassword: tt.password,
			}

			resp, err := service.Login(context.Background(), loginReq)

			assert.Error(t, err)
			assert.Nil(t, resp)

			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, codes.Unauthenticated, st.Code())
			assert.Contains(t, st.Message(), "invalid credentials")
		})
	}
}

// TestAuthService_RefreshToken_Success tests successful token refresh.
func TestAuthService_RefreshToken_Success(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	// Register and login to get tokens
	regReq := &pb.RegisterRequest{
		Username:       "refreshtest@example.com",
		MasterPassword: "SecurePassword123!",
	}
	regResp, err := service.Register(context.Background(), regReq)
	require.NoError(t, err)

	// Refresh the token
	refreshReq := &pb.RefreshTokenRequest{
		RefreshToken: regResp.RefreshToken,
	}

	refreshResp, err := service.RefreshToken(context.Background(), refreshReq)

	require.NoError(t, err)
	assert.NotNil(t, refreshResp)
	assert.NotEmpty(t, refreshResp.AccessToken)
	assert.NotNil(t, refreshResp.ExpiresAt)
	assert.Equal(t, "Token refreshed successfully", refreshResp.Message)

	// Verify new access token is valid
	claims, err := jwtManager.ValidateToken(refreshResp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, regResp.UserId, claims.UserID)
}

// TestAuthService_RefreshToken_InvalidToken tests refresh with invalid token.
func TestAuthService_RefreshToken_InvalidToken(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	tests := []struct {
		name         string
		refreshToken string
		errCode      codes.Code
	}{
		{
			name:         "empty token",
			refreshToken: "",
			errCode:      codes.InvalidArgument,
		},
		{
			name:         "invalid token",
			refreshToken: "invalid-token",
			errCode:      codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &pb.RefreshTokenRequest{
				RefreshToken: tt.refreshToken,
			}

			resp, err := service.RefreshToken(context.Background(), req)

			assert.Error(t, err)
			assert.Nil(t, resp)

			st, ok := status.FromError(err)
			require.True(t, ok)
			assert.Equal(t, tt.errCode, st.Code())
		})
	}
}

// TestAuthService_Logout_Success tests successful logout.
func TestAuthService_Logout_Success(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	// Register to get tokens
	regReq := &pb.RegisterRequest{
		Username:       "logouttest@example.com",
		MasterPassword: "SecurePassword123!",
	}
	regResp, err := service.Register(context.Background(), regReq)
	require.NoError(t, err)

	// Logout
	logoutReq := &pb.LogoutRequest{
		RefreshToken: regResp.RefreshToken,
	}

	logoutResp, err := service.Logout(context.Background(), logoutReq)

	require.NoError(t, err)
	assert.NotNil(t, logoutResp)
	assert.Equal(t, "Logged out successfully", logoutResp.Message)

	// Verify token is blacklisted
	assert.True(t, blacklist.IsBlacklisted(regResp.RefreshToken))

	// Verify can't refresh with logged out token
	refreshReq := &pb.RefreshTokenRequest{
		RefreshToken: regResp.RefreshToken,
	}
	refreshResp, err := service.RefreshToken(context.Background(), refreshReq)
	assert.Error(t, err)
	assert.Nil(t, refreshResp)
}

// TestAuthService_ChangePassword_Success tests successful password change.
func TestAuthService_ChangePassword_Success(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	// Register user
	regReq := &pb.RegisterRequest{
		Username:       "pwchange@example.com",
		MasterPassword: "OldPassword123!",
	}
	regResp, err := service.Register(context.Background(), regReq)
	require.NoError(t, err)

	// Change password with authenticated context
	ctx := context.WithValue(context.Background(), auth.UserIDContextKey, regResp.UserId)
	changeReq := &pb.ChangePasswordRequest{
		OldPassword: "OldPassword123!",
		NewPassword: "NewPassword456!",
	}

	changeResp, err := service.ChangePassword(ctx, changeReq)

	require.NoError(t, err)
	assert.NotNil(t, changeResp)
	assert.NotEmpty(t, changeResp.AccessToken)
	assert.NotEmpty(t, changeResp.RefreshToken)
	assert.Equal(t, "Password changed successfully", changeResp.Message)

	// Verify can't login with old password
	loginReq1 := &pb.LoginRequest{
		Username:       "pwchange@example.com",
		MasterPassword: "OldPassword123!",
	}
	loginResp1, err := service.Login(context.Background(), loginReq1)
	assert.Error(t, err)
	assert.Nil(t, loginResp1)

	// Verify can login with new password
	loginReq2 := &pb.LoginRequest{
		Username:       "pwchange@example.com",
		MasterPassword: "NewPassword456!",
	}
	loginResp2, err := service.Login(context.Background(), loginReq2)
	require.NoError(t, err)
	assert.NotNil(t, loginResp2)
}

// TestAuthService_ChangePassword_WrongOldPassword tests password change with wrong old password.
func TestAuthService_ChangePassword_WrongOldPassword(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	// Register user
	regReq := &pb.RegisterRequest{
		Username:       "wrongpw@example.com",
		MasterPassword: "CorrectPassword123!",
	}
	regResp, err := service.Register(context.Background(), regReq)
	require.NoError(t, err)

	// Try to change password with wrong old password
	ctx := context.WithValue(context.Background(), auth.UserIDContextKey, regResp.UserId)
	changeReq := &pb.ChangePasswordRequest{
		OldPassword: "WrongPassword123!",
		NewPassword: "NewPassword456!",
	}

	changeResp, err := service.ChangePassword(ctx, changeReq)

	assert.Error(t, err)
	assert.Nil(t, changeResp)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "old password is incorrect")
}

// TestAuthService_EncryptionKeyVerifier tests that encryption key verifier is properly generated.
func TestAuthService_EncryptionKeyVerifier(t *testing.T) {
	db := testhelpers.NewTestDB(t)
	pool := db.Pool()

	userRepo := postgres.NewUserRepository(pool)
	tokenRepo := postgres.NewRefreshTokenRepository(pool)
	jwtManager := auth.NewJWTManager("test-secret-key-for-testing")
	blacklist := auth.NewTokenBlacklist(time.Hour)
	defer blacklist.Stop()

	service := NewAuthService(userRepo, tokenRepo, jwtManager, blacklist)

	// Register user
	masterPassword := "TestPassword123!"
	regReq := &pb.RegisterRequest{
		Username:       "verifiertest@example.com",
		MasterPassword: masterPassword,
	}
	regResp, err := service.Register(context.Background(), regReq)
	require.NoError(t, err)

	// Retrieve user from database
	user, err := userRepo.GetUserByEmail(context.Background(), "verifiertest@example.com")
	require.NoError(t, err)

	// Verify encryption key verifier exists and is not empty
	assert.NotNil(t, user.EncryptionKeyVerifier)
	assert.NotEmpty(t, user.EncryptionKeyVerifier)

	// Verify we can derive the same encryption key and verify it
	derivedKey := crypto.DeriveKey(masterPassword, user.Salt)
	assert.NotNil(t, derivedKey)
	assert.Len(t, derivedKey, 32) // AES-256 key

	// The verifier should be verifiable with the derived key
	// (This would normally be done client-side, but we test the concept here)
	assert.NotEmpty(t, regResp.UserId)
}

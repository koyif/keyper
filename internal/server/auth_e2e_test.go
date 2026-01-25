// Package server_test contains E2E integration tests for the Keyper server.
// These tests use real gRPC client connections and PostgreSQL testcontainers
// to validate the complete authentication flow.
package server

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/handlers"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	"github.com/koyif/keyper/internal/server/testhelpers"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

const (
	testJWTSecret = "test-secret-key-for-jwt-signing-must-be-long-enough"
	testTimeout   = 10 * time.Second
)

// testServer holds the gRPC server and related resources for E2E testing.
type testServer struct {
	grpcServer     *grpc.Server
	authClient     pb.AuthServiceClient
	listener       net.Listener
	tokenBlacklist *auth.TokenBlacklist
	cleanup        func()
}

// setupTestServer creates a gRPC server with all auth-related services on a random port.
func setupTestServer(t *testing.T, tc *testhelpers.TestContainer) *testServer {
	t.Helper()

	// Initialize repositories.
	userRepo := postgres.NewUserRepository(tc.Pool())
	refreshTokenRepo := postgres.NewRefreshTokenRepository(tc.Pool())

	// Initialize JWT manager with test secret.
	jwtManager := auth.NewJWTManager(testJWTSecret)

	// Initialize token blacklist with short cleanup interval for testing.
	tokenBlacklist := auth.NewTokenBlacklist(100 * time.Millisecond)

	// Create gRPC server with auth interceptor.
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(auth.UnaryAuthInterceptorWithBlacklist(jwtManager, tokenBlacklist)),
	)

	// Initialize and register auth service.
	authService := handlers.NewAuthService(userRepo, refreshTokenRepo, jwtManager, tokenBlacklist)
	pb.RegisterAuthServiceServer(grpcServer, authService)

	// Listen on random available port.
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "failed to create listener")

	// Start server in background.
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("Server stopped: %v", err)
		}
	}()

	// Create client connection.
	addr := listener.Addr().String()
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err, "failed to create client connection")

	// Create auth client.
	authClient := pb.NewAuthServiceClient(conn)

	t.Logf("Test gRPC server started on %s", addr)

	// Cleanup function.
	cleanup := func() {
		conn.Close()
		grpcServer.GracefulStop()
		listener.Close()
		tokenBlacklist.Stop()
	}

	t.Cleanup(cleanup)

	return &testServer{
		grpcServer:     grpcServer,
		authClient:     authClient,
		listener:       listener,
		tokenBlacklist: tokenBlacklist,
		cleanup:        cleanup,
	}
}

// TestAuthFlow_RegisterAndLogin tests the complete registration and login flow.
func TestAuthFlow_RegisterAndLogin(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupTestServer(t, tc)

	// Test data.
	username := "test@example.com"
	password := "secure-master-password"
	deviceInfo := "test-device"

	t.Run("Register new user", func(t *testing.T) {
		req := &pb.RegisterRequest{
			Username:       username,
			MasterPassword: password,
			DeviceInfo:     deviceInfo,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.Register(ctx, req)
		require.NoError(t, err, "register should succeed")
		require.NotNil(t, resp)

		// Verify response contains required fields.
		assert.NotEmpty(t, resp.UserId, "user_id should not be empty")
		assert.NotEmpty(t, resp.AccessToken, "access_token should not be empty")
		assert.NotEmpty(t, resp.RefreshToken, "refresh_token should not be empty")
		assert.NotNil(t, resp.ExpiresAt, "expires_at should not be nil")
		assert.Equal(t, "User registered successfully", resp.Message)

		// Verify access token expiration is in the future.
		assert.True(t, resp.ExpiresAt.AsTime().After(time.Now()))

		t.Logf("User registered successfully with ID: %s", resp.UserId)
	})

	t.Run("Register duplicate user fails", func(t *testing.T) {
		req := &pb.RegisterRequest{
			Username:       username,
			MasterPassword: password,
			DeviceInfo:     deviceInfo,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.Register(ctx, req)
		require.Error(t, err, "duplicate registration should fail")
		assert.Nil(t, resp)

		// Verify error code.
		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status")
		assert.Equal(t, codes.AlreadyExists, st.Code())
		assert.Contains(t, st.Message(), "already exists")
	})

	t.Run("Login with valid credentials", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username:       username,
			MasterPassword: password,
			DeviceInfo:     deviceInfo,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.Login(ctx, req)
		require.NoError(t, err, "login should succeed")
		require.NotNil(t, resp)

		// Verify response contains required fields.
		assert.NotEmpty(t, resp.UserId, "user_id should not be empty")
		assert.NotEmpty(t, resp.AccessToken, "access_token should not be empty")
		assert.NotEmpty(t, resp.RefreshToken, "refresh_token should not be empty")
		assert.NotNil(t, resp.ExpiresAt, "expires_at should not be nil")
		assert.Equal(t, "Login successful", resp.Message)

		t.Logf("User logged in successfully")
	})

	t.Run("Login with invalid password fails", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username:       username,
			MasterPassword: "wrong-password",
			DeviceInfo:     deviceInfo,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.Login(ctx, req)
		require.Error(t, err, "login with wrong password should fail")
		assert.Nil(t, resp)

		// Verify error code.
		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status")
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "invalid credentials")
	})

	t.Run("Login with non-existent user fails", func(t *testing.T) {
		req := &pb.LoginRequest{
			Username:       "nonexistent@example.com",
			MasterPassword: password,
			DeviceInfo:     deviceInfo,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.Login(ctx, req)
		require.Error(t, err, "login with non-existent user should fail")
		assert.Nil(t, resp)

		// Verify error code.
		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status")
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "invalid credentials")
	})
}

// TestAuthFlow_RefreshTokenRotation tests refresh token generation and rotation.
func TestAuthFlow_RefreshTokenRotation(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupTestServer(t, tc)

	// Register a test user.
	username := "refresh-test@example.com"
	password := "secure-master-password"

	registerReq := &pb.RegisterRequest{
		Username:       username,
		MasterPassword: password,
		DeviceInfo:     "test-device",
	}

	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	registerResp, err := server.authClient.Register(ctx, registerReq)
	require.NoError(t, err)
	require.NotNil(t, registerResp)

	oldRefreshToken := registerResp.RefreshToken
	oldAccessToken := registerResp.AccessToken

	t.Run("Refresh token generates new access token", func(t *testing.T) {
		// Wait at least 1 second to ensure JWT timestamp difference (JWT uses second precision).
		time.Sleep(1100 * time.Millisecond)

		req := &pb.RefreshTokenRequest{
			RefreshToken: oldRefreshToken,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.RefreshToken(ctx, req)
		require.NoError(t, err, "refresh token should succeed")
		require.NotNil(t, resp)

		// Verify response.
		assert.NotEmpty(t, resp.AccessToken, "access_token should not be empty")
		assert.NotNil(t, resp.ExpiresAt, "expires_at should not be nil")
		assert.Equal(t, "Token refreshed successfully", resp.Message)

		// New access token should be different from old one due to timestamp difference.
		assert.NotEqual(t, oldAccessToken, resp.AccessToken, "new access token should be different")

		t.Logf("Token refreshed successfully")
	})

	t.Run("Invalid refresh token fails", func(t *testing.T) {
		req := &pb.RefreshTokenRequest{
			RefreshToken: "invalid-token",
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.RefreshToken(ctx, req)
		require.Error(t, err, "invalid refresh token should fail")
		assert.Nil(t, resp)

		// Verify error code.
		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status")
		assert.Equal(t, codes.Unauthenticated, st.Code())
	})

	t.Run("Refresh token works multiple times", func(t *testing.T) {
		refreshToken := oldRefreshToken
		var accessTokens []string

		// Perform multiple refresh operations with sufficient time between them.
		for i := 0; i < 3; i++ {
			// Wait at least 1 second for JWT timestamp precision.
			time.Sleep(1100 * time.Millisecond)

			req := &pb.RefreshTokenRequest{
				RefreshToken: refreshToken,
			}

			ctx, cancel := context.WithTimeout(ctx, testTimeout)
			resp, err := server.authClient.RefreshToken(ctx, req)
			cancel()

			require.NoError(t, err, fmt.Sprintf("refresh %d should succeed", i+1))
			require.NotNil(t, resp)

			accessTokens = append(accessTokens, resp.AccessToken)
		}

		// All access tokens should be different due to timestamp differences.
		for i := 0; i < len(accessTokens); i++ {
			for j := i + 1; j < len(accessTokens); j++ {
				assert.NotEqual(t, accessTokens[i], accessTokens[j],
					"access tokens %d and %d should be different", i, j)
			}
		}

		t.Logf("Multiple token refreshes successful, generated %d unique access tokens", len(accessTokens))
	})
}

// TestAuthFlow_Logout tests logout functionality and token invalidation.
func TestAuthFlow_Logout(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupTestServer(t, tc)

	// Register and login a test user.
	username := "logout-test@example.com"
	password := "secure-master-password"

	registerReq := &pb.RegisterRequest{
		Username:       username,
		MasterPassword: password,
		DeviceInfo:     "test-device",
	}

	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	registerResp, err := server.authClient.Register(ctx, registerReq)
	require.NoError(t, err)
	require.NotNil(t, registerResp)

	refreshToken := registerResp.RefreshToken

	t.Run("Logout succeeds with valid refresh token", func(t *testing.T) {
		req := &pb.LogoutRequest{
			RefreshToken: refreshToken,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.Logout(ctx, req)
		require.NoError(t, err, "logout should succeed")
		require.NotNil(t, resp)

		assert.Equal(t, "Logged out successfully", resp.Message)

		t.Logf("Logout successful")
	})

	t.Run("Refresh token is invalidated after logout", func(t *testing.T) {
		// Wait for blacklist to propagate.
		time.Sleep(150 * time.Millisecond)

		req := &pb.RefreshTokenRequest{
			RefreshToken: refreshToken,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.RefreshToken(ctx, req)
		require.Error(t, err, "refresh should fail after logout")
		assert.Nil(t, resp)

		// Verify error code.
		st, ok := status.FromError(err)
		require.True(t, ok, "error should be a gRPC status")
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "revoked")

		t.Logf("Refresh token correctly invalidated after logout")
	})

	t.Run("Logout with already logged out token succeeds", func(t *testing.T) {
		req := &pb.LogoutRequest{
			RefreshToken: refreshToken,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		// Second logout should still succeed (idempotent).
		resp, err := server.authClient.Logout(ctx, req)
		require.NoError(t, err, "logout should be idempotent")
		require.NotNil(t, resp)

		assert.Equal(t, "Logged out successfully", resp.Message)
	})
}

// TestAuthFlow_ValidationErrors tests input validation for auth operations.
func TestAuthFlow_ValidationErrors(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupTestServer(t, tc)

	testCases := []struct {
		name          string
		operation     string
		request       interface{}
		expectedCode  codes.Code
		expectedError string
	}{
		{
			name:      "Register with empty username",
			operation: "register",
			request: &pb.RegisterRequest{
				Username:       "",
				MasterPassword: "password",
			},
			expectedCode:  codes.InvalidArgument,
			expectedError: "username is required",
		},
		{
			name:      "Register with empty password",
			operation: "register",
			request: &pb.RegisterRequest{
				Username:       "test@example.com",
				MasterPassword: "",
			},
			expectedCode:  codes.InvalidArgument,
			expectedError: "master_password is required",
		},
		{
			name:      "Login with empty username",
			operation: "login",
			request: &pb.LoginRequest{
				Username:       "",
				MasterPassword: "password",
			},
			expectedCode:  codes.InvalidArgument,
			expectedError: "username is required",
		},
		{
			name:      "Login with empty password",
			operation: "login",
			request: &pb.LoginRequest{
				Username:       "test@example.com",
				MasterPassword: "",
			},
			expectedCode:  codes.InvalidArgument,
			expectedError: "master_password is required",
		},
		{
			name:      "RefreshToken with empty token",
			operation: "refresh",
			request: &pb.RefreshTokenRequest{
				RefreshToken: "",
			},
			expectedCode:  codes.InvalidArgument,
			expectedError: "refresh_token is required",
		},
		{
			name:      "Logout with empty token",
			operation: "logout",
			request: &pb.LogoutRequest{
				RefreshToken: "",
			},
			expectedCode:  codes.InvalidArgument,
			expectedError: "refresh_token is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, testTimeout)
			defer cancel()

			var err error
			switch tc.operation {
			case "register":
				_, err = server.authClient.Register(ctx, tc.request.(*pb.RegisterRequest))
			case "login":
				_, err = server.authClient.Login(ctx, tc.request.(*pb.LoginRequest))
			case "refresh":
				_, err = server.authClient.RefreshToken(ctx, tc.request.(*pb.RefreshTokenRequest))
			case "logout":
				_, err = server.authClient.Logout(ctx, tc.request.(*pb.LogoutRequest))
			}

			require.Error(t, err, "operation should fail with validation error")

			st, ok := status.FromError(err)
			require.True(t, ok, "error should be a gRPC status")
			assert.Equal(t, tc.expectedCode, st.Code())
			assert.Contains(t, st.Message(), tc.expectedError)
		})
	}
}

// TestAuthFlow_ConcurrentLogins tests concurrent login attempts for the same user.
func TestAuthFlow_ConcurrentLogins(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupTestServer(t, tc)

	// Register a test user.
	username := "concurrent-test@example.com"
	password := "secure-master-password"

	registerReq := &pb.RegisterRequest{
		Username:       username,
		MasterPassword: password,
		DeviceInfo:     "test-device",
	}

	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	_, err := server.authClient.Register(ctx, registerReq)
	require.NoError(t, err)

	t.Run("Multiple concurrent logins succeed", func(t *testing.T) {
		concurrency := 10
		errChan := make(chan error, concurrency)
		respChan := make(chan *pb.LoginResponse, concurrency)

		// Launch concurrent login requests.
		for i := 0; i < concurrency; i++ {
			go func(deviceNum int) {
				req := &pb.LoginRequest{
					Username:       username,
					MasterPassword: password,
					DeviceInfo:     fmt.Sprintf("device-%d", deviceNum),
				}

				reqCtx, reqCancel := context.WithTimeout(context.Background(), testTimeout)
				defer reqCancel()

				resp, err := server.authClient.Login(reqCtx, req)
				errChan <- err
				respChan <- resp
			}(i)
		}

		// Collect results.
		var successCount int
		var responses []*pb.LoginResponse

		for i := 0; i < concurrency; i++ {
			err := <-errChan
			resp := <-respChan

			if err == nil {
				successCount++
				responses = append(responses, resp)
			} else {
				t.Logf("Login %d failed: %v", i, err)
			}
		}

		// All logins should succeed.
		assert.Equal(t, concurrency, successCount, "all concurrent logins should succeed")

		// All refresh tokens should be unique.
		tokenSet := make(map[string]bool)
		for _, resp := range responses {
			assert.NotContains(t, tokenSet, resp.RefreshToken, "refresh tokens should be unique")
			tokenSet[resp.RefreshToken] = true
		}

		t.Logf("Successfully processed %d concurrent logins with unique tokens", successCount)
	})
}

// TestAuthFlow_TokenBlacklist tests token blacklist functionality.
func TestAuthFlow_TokenBlacklist(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupTestServer(t, tc)

	// Register and login a test user.
	username := "blacklist-test@example.com"
	password := "secure-master-password"

	registerReq := &pb.RegisterRequest{
		Username:       username,
		MasterPassword: password,
		DeviceInfo:     "test-device",
	}

	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	registerResp, err := server.authClient.Register(ctx, registerReq)
	require.NoError(t, err)
	require.NotNil(t, registerResp)

	refreshToken := registerResp.RefreshToken

	t.Run("Token works before logout", func(t *testing.T) {
		req := &pb.RefreshTokenRequest{
			RefreshToken: refreshToken,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.RefreshToken(ctx, req)
		require.NoError(t, err, "refresh should work before logout")
		assert.NotNil(t, resp)
	})

	t.Run("Token is blacklisted after logout", func(t *testing.T) {
		// Logout to blacklist the token.
		logoutReq := &pb.LogoutRequest{
			RefreshToken: refreshToken,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		_, err := server.authClient.Logout(ctx, logoutReq)
		require.NoError(t, err)

		// Wait for blacklist to be updated.
		time.Sleep(150 * time.Millisecond)

		// Verify token is in blacklist.
		assert.True(t, server.tokenBlacklist.IsBlacklisted(refreshToken),
			"token should be in blacklist after logout")
	})

	t.Run("Blacklisted token cannot be used", func(t *testing.T) {
		req := &pb.RefreshTokenRequest{
			RefreshToken: refreshToken,
		}

		ctx, cancel := context.WithTimeout(ctx, testTimeout)
		defer cancel()

		resp, err := server.authClient.RefreshToken(ctx, req)
		require.Error(t, err, "blacklisted token should be rejected")
		assert.Nil(t, resp)

		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Unauthenticated, st.Code())
		assert.Contains(t, st.Message(), "revoked")
	})
}

// TestAuthFlow_TokenExpiry tests token expiration handling.
func TestAuthFlow_TokenExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping token expiry test in short mode")
	}

	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupTestServer(t, tc)

	// Register a test user.
	username := "expiry-test@example.com"
	password := "secure-master-password"

	registerReq := &pb.RegisterRequest{
		Username:       username,
		MasterPassword: password,
		DeviceInfo:     "test-device",
	}

	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	registerResp, err := server.authClient.Register(ctx, registerReq)
	require.NoError(t, err)
	require.NotNil(t, registerResp)

	accessToken := registerResp.AccessToken
	expiresAt := registerResp.ExpiresAt.AsTime()

	t.Run("Access token is valid before expiry", func(t *testing.T) {
		// Calculate time until expiry.
		timeUntilExpiry := time.Until(expiresAt)
		assert.Positive(t, timeUntilExpiry, "token should not be expired yet")

		// Verify token structure (just parse it).
		jwtManager := auth.NewJWTManager(testJWTSecret)
		claims, err := jwtManager.ValidateToken(accessToken)
		require.NoError(t, err, "token should be valid before expiry")
		assert.NotNil(t, claims)
		assert.NotEmpty(t, claims.UserID, "user ID should be present in claims")
		assert.Equal(t, registerResp.UserId, claims.UserID, "user ID in token should match registered user")

		t.Logf("Access token is valid, expires in %v", timeUntilExpiry)
	})

	t.Run("Token expiry is set correctly", func(t *testing.T) {
		// Verify expiry is approximately 15 minutes from now (access token expiry).
		expectedExpiry := time.Now().Add(auth.AccessTokenExpiry)
		timeDiff := expiresAt.Sub(expectedExpiry).Abs()

		// Allow 5 second tolerance for test execution time.
		assert.Less(t, timeDiff, 5*time.Second,
			"expiry time should be approximately 15 minutes from now")
	})
}

// TestAuthFlow_MultipleDevices tests handling multiple devices for the same user.
func TestAuthFlow_MultipleDevices(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupTestServer(t, tc)

	// Register a test user.
	username := "multidevice-test@example.com"
	password := "secure-master-password"

	registerReq := &pb.RegisterRequest{
		Username:       username,
		MasterPassword: password,
		DeviceInfo:     "device-1",
	}

	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	_, err := server.authClient.Register(ctx, registerReq)
	require.NoError(t, err)

	t.Run("User can login from multiple devices", func(t *testing.T) {
		devices := []string{"device-2", "device-3", "device-4"}
		var refreshTokens []string

		for _, device := range devices {
			loginReq := &pb.LoginRequest{
				Username:       username,
				MasterPassword: password,
				DeviceInfo:     device,
			}

			reqCtx, reqCancel := context.WithTimeout(context.Background(), testTimeout)
			resp, err := server.authClient.Login(reqCtx, loginReq)
			reqCancel()

			require.NoError(t, err, "login from %s should succeed", device)
			require.NotNil(t, resp)

			refreshTokens = append(refreshTokens, resp.RefreshToken)
		}

		// All refresh tokens should be unique.
		tokenSet := make(map[string]bool)
		for _, token := range refreshTokens {
			assert.NotContains(t, tokenSet, token, "refresh tokens should be unique across devices")
			tokenSet[token] = true
		}

		t.Logf("User successfully logged in from %d devices with unique tokens", len(devices))
	})

	t.Run("Logging out from one device does not affect others", func(t *testing.T) {
		// Login from two devices.
		device1Req := &pb.LoginRequest{
			Username:       username,
			MasterPassword: password,
			DeviceInfo:     "logout-device-1",
		}

		ctx1, cancel1 := context.WithTimeout(context.Background(), testTimeout)
		device1Resp, err := server.authClient.Login(ctx1, device1Req)
		cancel1()
		require.NoError(t, err)

		device2Req := &pb.LoginRequest{
			Username:       username,
			MasterPassword: password,
			DeviceInfo:     "logout-device-2",
		}

		ctx2, cancel2 := context.WithTimeout(context.Background(), testTimeout)
		device2Resp, err := server.authClient.Login(ctx2, device2Req)
		cancel2()
		require.NoError(t, err)

		// Logout from device 1.
		logoutReq := &pb.LogoutRequest{
			RefreshToken: device1Resp.RefreshToken,
		}

		ctx3, cancel3 := context.WithTimeout(context.Background(), testTimeout)
		_, err = server.authClient.Logout(ctx3, logoutReq)
		cancel3()
		require.NoError(t, err)

		// Wait for blacklist update.
		time.Sleep(150 * time.Millisecond)

		// Device 1 token should not work.
		ctx4, cancel4 := context.WithTimeout(context.Background(), testTimeout)
		_, err = server.authClient.RefreshToken(ctx4, &pb.RefreshTokenRequest{
			RefreshToken: device1Resp.RefreshToken,
		})
		cancel4()
		require.Error(t, err, "device 1 token should be invalidated")

		// Device 2 token should still work.
		ctx5, cancel5 := context.WithTimeout(context.Background(), testTimeout)
		device2Refresh, err := server.authClient.RefreshToken(ctx5, &pb.RefreshTokenRequest{
			RefreshToken: device2Resp.RefreshToken,
		})
		cancel5()
		require.NoError(t, err, "device 2 token should still be valid")
		assert.NotNil(t, device2Refresh)

		t.Logf("Device isolation working correctly")
	})
}

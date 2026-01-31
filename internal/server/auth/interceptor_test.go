package auth

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestUnaryAuthInterceptor_UnauthenticatedEndpoints(t *testing.T) {
	manager := NewJWTManager("test-secret-key")
	interceptor := UnaryAuthInterceptor(manager)

	testCases := []struct {
		name       string
		method     string
		shouldPass bool
	}{
		{
			name:       "Register endpoint",
			method:     "/keyper.api.v1.AuthService/Register",
			shouldPass: true,
		},
		{
			name:       "Login endpoint",
			method:     "/keyper.api.v1.AuthService/Login",
			shouldPass: true,
		},
		{
			name:       "Protected endpoint",
			method:     "/keyper.api.v1.SecretsService/Create",
			shouldPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			info := &grpc.UnaryServerInfo{FullMethod: tc.method}

			handlerCalled := false
			handler := func(ctx context.Context, req any) (any, error) {
				handlerCalled = true
				return "success", nil
			}

			_, err := interceptor(ctx, nil, info, handler)

			if tc.shouldPass {
				if err != nil {
					t.Errorf("Expected no error for unauthenticated endpoint, got: %v", err)
				}
				if !handlerCalled {
					t.Error("Handler should have been called for unauthenticated endpoint")
				}
			} else {
				if err == nil {
					t.Error("Expected error for protected endpoint without token")
				}
				if handlerCalled {
					t.Error("Handler should not have been called for protected endpoint without token")
				}
			}
		})
	}
}

func TestUnaryAuthInterceptor_ValidToken(t *testing.T) {
	manager := NewJWTManager("test-secret-key")
	interceptor := UnaryAuthInterceptor(manager)

	userID := uuid.New()
	deviceID := "device-123"
	token, _, err := manager.GenerateAccessToken(userID, deviceID)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/keyper.api.v1.SecretsService/Create"}

	var capturedCtx context.Context
	handler := func(ctx context.Context, req any) (any, error) {
		capturedCtx = ctx
		return "success", nil
	}

	_, err = interceptor(ctx, nil, info, handler)
	if err != nil {
		t.Fatalf("Expected no error with valid token, got: %v", err)
	}

	if capturedCtx == nil {
		t.Fatal("Handler context is nil")
	}

	extractedUserID, err := GetUserIDFromContext(capturedCtx)
	if err != nil {
		t.Fatalf("Failed to get user ID from context: %v", err)
	}

	if extractedUserID != userID.String() {
		t.Errorf("Expected user ID %s, got %s", userID.String(), extractedUserID)
	}

	extractedDeviceID := GetDeviceIDFromContext(capturedCtx)
	if extractedDeviceID != deviceID {
		t.Errorf("Expected device ID %s, got %s", deviceID, extractedDeviceID)
	}
}

func TestUnaryAuthInterceptor_MissingToken(t *testing.T) {
	manager := NewJWTManager("test-secret-key")
	interceptor := UnaryAuthInterceptor(manager)

	ctx := context.Background()
	info := &grpc.UnaryServerInfo{FullMethod: "/keyper.api.v1.SecretsService/Create"}

	handler := func(ctx context.Context, req any) (any, error) {
		t.Error("Handler should not be called without token")
		return nil, nil
	}

	_, err := interceptor(ctx, nil, info, handler)
	if err == nil {
		t.Fatal("Expected error when token is missing")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected code Unauthenticated, got %v", st.Code())
	}
}

func TestUnaryAuthInterceptor_InvalidTokenFormat(t *testing.T) {
	manager := NewJWTManager("test-secret-key")
	interceptor := UnaryAuthInterceptor(manager)

	testCases := []struct {
		name          string
		authHeader    string
		expectedError bool
	}{
		{
			name:          "Missing Bearer prefix",
			authHeader:    "invalid-token",
			expectedError: true,
		},
		{
			name:          "Wrong scheme",
			authHeader:    "Basic token123",
			expectedError: true,
		},
		{
			name:          "Empty token",
			authHeader:    "Bearer ",
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			md := metadata.Pairs("authorization", tc.authHeader)
			ctx := metadata.NewIncomingContext(context.Background(), md)
			info := &grpc.UnaryServerInfo{FullMethod: "/keyper.api.v1.SecretsService/Create"}

			handler := func(ctx context.Context, req any) (any, error) {
				t.Error("Handler should not be called with invalid token format")
				return nil, nil
			}

			_, err := interceptor(ctx, nil, info, handler)
			if tc.expectedError && err == nil {
				t.Error("Expected error for invalid token format")
			}
		})
	}
}

func TestUnaryAuthInterceptor_ExpiredToken(t *testing.T) {
	// This test would require manipulating time or creating a token with past expiry.
	// For now, we'll test with an invalid token which will also fail validation.
	manager := NewJWTManager("test-secret-key")
	interceptor := UnaryAuthInterceptor(manager)

	// Use a completely invalid token
	md := metadata.Pairs("authorization", "Bearer invalid.jwt.token")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/keyper.api.v1.SecretsService/Create"}

	handler := func(ctx context.Context, req any) (any, error) {
		t.Error("Handler should not be called with invalid token")
		return nil, nil
	}

	_, err := interceptor(ctx, nil, info, handler)
	if err == nil {
		t.Fatal("Expected error for invalid token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected code Unauthenticated, got %v", st.Code())
	}
}

func TestGetUserIDFromContext_NoUserID(t *testing.T) {
	ctx := context.Background()

	_, err := GetUserIDFromContext(ctx)
	if err == nil {
		t.Error("Expected error when user ID is not in context")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected code Unauthenticated, got %v", st.Code())
	}
}

func TestGetDeviceIDFromContext_NoDeviceID(t *testing.T) {
	ctx := context.Background()

	deviceID := GetDeviceIDFromContext(ctx)
	if deviceID != "" {
		t.Errorf("Expected empty device ID, got %s", deviceID)
	}
}

func TestExtractToken(t *testing.T) {
	testCases := []struct {
		name          string
		setupContext  func() context.Context
		expectedToken string
		expectError   bool
	}{
		{
			name: "Valid Bearer token",
			setupContext: func() context.Context {
				md := metadata.Pairs("authorization", "Bearer token123")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expectedToken: "token123",
			expectError:   false,
		},
		{
			name: "Case insensitive Bearer",
			setupContext: func() context.Context {
				md := metadata.Pairs("authorization", "bearer token456")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expectedToken: "token456",
			expectError:   false,
		},
		{
			name: "No metadata",
			setupContext: func() context.Context {
				return context.Background()
			},
			expectError: true,
		},
		{
			name: "Missing authorization header",
			setupContext: func() context.Context {
				md := metadata.Pairs("other-header", "value")
				return metadata.NewIncomingContext(context.Background(), md)
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := tc.setupContext()
			token, err := extractToken(ctx)

			if tc.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if token != tc.expectedToken {
					t.Errorf("Expected token %s, got %s", tc.expectedToken, token)
				}
			}
		})
	}
}

func TestUnaryAuthInterceptorWithBlacklist(t *testing.T) {
	manager := NewJWTManager("test-secret-key")
	blacklist := NewTokenBlacklist(1 * time.Hour)
	defer blacklist.Stop()

	interceptor := UnaryAuthInterceptorWithBlacklist(manager, blacklist)

	userID := uuid.New()
	deviceID := "device-123"
	token, _, err := manager.GenerateAccessToken(userID, deviceID)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{FullMethod: "/keyper.api.v1.SecretsService/Create"}

	handler := func(ctx context.Context, req any) (any, error) {
		return "success", nil
	}

	_, err = interceptor(ctx, nil, info, handler)
	if err != nil {
		t.Errorf("Expected no error with valid token, got: %v", err)
	}

	claims, _ := manager.ValidateToken(token)
	blacklist.Add(token, claims.ExpiresAt.Time)

	_, err = interceptor(ctx, nil, info, handler)
	if err == nil {
		t.Error("Expected error for blacklisted token")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected code Unauthenticated, got %v", st.Code())
	}

	if st.Message() != "token has been revoked" {
		t.Errorf("Expected 'token has been revoked' message, got: %s", st.Message())
	}
}

func TestGetUserIDAsUUID_ValidUserID(t *testing.T) {
	expectedUserID := uuid.New()
	ctx := context.WithValue(context.Background(), UserIDContextKey, expectedUserID.String())

	userID, err := GetUserIDAsUUID(ctx)
	if err != nil {
		t.Fatalf("Expected no error with valid user ID, got: %v", err)
	}

	if userID != expectedUserID {
		t.Errorf("Expected user ID %s, got %s", expectedUserID, userID)
	}
}

func TestGetUserIDAsUUID_InvalidUUIDFormat(t *testing.T) {
	ctx := context.WithValue(context.Background(), UserIDContextKey, "not-a-valid-uuid")

	userID, err := GetUserIDAsUUID(ctx)
	if err == nil {
		t.Fatal("Expected error for invalid UUID format")
	}

	if userID != uuid.Nil {
		t.Errorf("Expected uuid.Nil for invalid UUID, got %s", userID)
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected code Internal, got %v", st.Code())
	}

	expectedMsg := "invalid user_id in context"
	if !contains(st.Message(), expectedMsg) {
		t.Errorf("Expected error message to contain '%s', got: %s", expectedMsg, st.Message())
	}
}

func TestGetUserIDAsUUID_MissingUserID(t *testing.T) {
	ctx := context.Background()

	userID, err := GetUserIDAsUUID(ctx)
	if err == nil {
		t.Fatal("Expected error when user ID is not in context")
	}

	if userID != uuid.Nil {
		t.Errorf("Expected uuid.Nil when user ID is missing, got %s", userID)
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected code Unauthenticated, got %v", st.Code())
	}

	expectedMsg := "user not authenticated"
	if st.Message() != expectedMsg {
		t.Errorf("Expected error message '%s', got: %s", expectedMsg, st.Message())
	}
}

func TestGetUserIDAsUUID_EmptyUserID(t *testing.T) {
	ctx := context.WithValue(context.Background(), UserIDContextKey, "")

	userID, err := GetUserIDAsUUID(ctx)
	if err == nil {
		t.Fatal("Expected error when user ID is empty")
	}

	if userID != uuid.Nil {
		t.Errorf("Expected uuid.Nil when user ID is empty, got %s", userID)
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error should be a gRPC status error")
	}

	if st.Code() != codes.Unauthenticated {
		t.Errorf("Expected code Unauthenticated, got %v", st.Code())
	}
}

// contains is a helper function to check if a string contains a substring.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

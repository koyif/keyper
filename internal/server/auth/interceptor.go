package auth

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ContextKey is a type for context keys to avoid collisions.
type ContextKey string

const (
	// UserIDContextKey is the context key for storing authenticated user ID.
	UserIDContextKey ContextKey = "user_id"

	// DeviceIDContextKey is the context key for storing device ID.
	DeviceIDContextKey ContextKey = "device_id"
)

var (
	// UnauthenticatedMethods are gRPC methods that don't require authentication.
	UnauthenticatedMethods = map[string]bool{
		"/keyper.api.v1.AuthService/Register": true,
		"/keyper.api.v1.AuthService/Login":    true,
	}
)

// UnaryAuthInterceptor creates a unary server interceptor for JWT authentication.
func UnaryAuthInterceptor(jwtManager *JWTManager) grpc.UnaryServerInterceptor {
	return UnaryAuthInterceptorWithBlacklist(jwtManager, nil)
}

// UnaryAuthInterceptorWithBlacklist creates a unary server interceptor for JWT authentication with token blacklist support.
func UnaryAuthInterceptorWithBlacklist(jwtManager *JWTManager, blacklist *TokenBlacklist) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// Allow unauthenticated access to specific endpoints
		if UnauthenticatedMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract token from metadata
		token, err := extractToken(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "authentication required: %v", err)
		}

		// Check if token is blacklisted (if blacklist is provided)
		if blacklist != nil && blacklist.IsBlacklisted(token) {
			return nil, status.Error(codes.Unauthenticated, "token has been revoked")
		}

		// Validate token and extract claims
		claims, err := jwtManager.ValidateToken(token)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}

		// Inject user_id and device_id into context
		ctx = context.WithValue(ctx, UserIDContextKey, claims.UserID)
		if claims.DeviceID != "" {
			ctx = context.WithValue(ctx, DeviceIDContextKey, claims.DeviceID)
		}

		// Call the handler with the enriched context
		return handler(ctx, req)
	}
}

// extractToken extracts the JWT token from the gRPC metadata.
func extractToken(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "missing metadata")
	}

	// Try to get token from "authorization" header
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return "", status.Error(codes.Unauthenticated, "missing authorization header")
	}

	// Expected format: "Bearer <token>"
	authHeader := authHeaders[0]
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", status.Error(codes.Unauthenticated, "invalid authorization header format")
	}

	return parts[1], nil
}

// GetUserIDFromContext retrieves the authenticated user ID from context.
func GetUserIDFromContext(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(UserIDContextKey).(string)
	if !ok || userID == "" {
		return "", status.Error(codes.Unauthenticated, "user not authenticated")
	}
	return userID, nil
}

// GetDeviceIDFromContext retrieves the device ID from context if present.
func GetDeviceIDFromContext(ctx context.Context) string {
	deviceID, ok := ctx.Value(DeviceIDContextKey).(string)
	if !ok {
		return ""
	}
	return deviceID
}

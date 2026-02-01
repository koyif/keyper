package grpcutil

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// NewConnection creates a gRPC client connection with standard configuration.
// It sets up the connection with insecure credentials and optionally adds
// authentication metadata if an access token is provided.
func NewConnection(ctx context.Context, serverAddr string, accessToken string) (*grpc.ClientConn, context.Context, error) {
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	// Add authentication token to context if provided
	if accessToken != "" {
		md := metadata.New(map[string]string{
			"authorization": "Bearer " + accessToken,
		})
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	return conn, ctx, nil
}

// NewAuthenticatedConnection creates a gRPC connection with authentication metadata.
// It includes both the access token and device ID in the request metadata.
func NewAuthenticatedConnection(ctx context.Context, serverAddr string, accessToken string, deviceID string) (*grpc.ClientConn, context.Context, error) {
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	// Add authentication token and device ID to context
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + accessToken,
		"device-id":     deviceID,
	})
	ctx = metadata.NewOutgoingContext(ctx, md)

	return conn, ctx, nil
}

// NewUnauthenticatedConnection creates a gRPC connection without authentication metadata.
// Used for registration and login where no token exists yet.
func NewUnauthenticatedConnection(serverAddr string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	return conn, nil
}

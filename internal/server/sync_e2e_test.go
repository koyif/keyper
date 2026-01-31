// Package server contains E2E integration tests for the Keyper server.
// These tests validate multi-client synchronization and conflict resolution.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/koyif/keyper/internal/crypto"
	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/config"
	"github.com/koyif/keyper/internal/server/handlers"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	"github.com/koyif/keyper/internal/server/testhelpers"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// testSyncServer holds the gRPC server and related resources for sync E2E testing.
type testSyncServer struct {
	grpcServer     *grpc.Server
	authClient     pb.AuthServiceClient
	secretsClient  pb.SecretsServiceClient
	syncClient     pb.SyncServiceClient
	listener       net.Listener
	tokenBlacklist *auth.TokenBlacklist
	pool           *testhelpers.TestContainer
	cleanup        func()
}

// setupSyncTestServer creates a gRPC server with auth, secrets, and sync services.
func setupSyncTestServer(t *testing.T, tc *testhelpers.TestContainer) *testSyncServer {
	t.Helper()

	// Initialize repositories.
	userRepo := postgres.NewUserRepository(tc.Pool())
	refreshTokenRepo := postgres.NewRefreshTokenRepository(tc.Pool())
	secretRepo := postgres.NewSecretRepository(tc.Pool())
	transactor := postgres.NewTransactor(tc.Pool())

	// Initialize JWT manager with test secret.
	jwtManager := auth.NewJWTManager(testJWTSecret)

	// Initialize token blacklist with short cleanup interval for testing.
	tokenBlacklist := auth.NewTokenBlacklist(100 * time.Millisecond)

	// Create gRPC server with auth interceptor.
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(auth.UnaryAuthInterceptorWithBlacklist(jwtManager, tokenBlacklist)),
	)

	// Initialize and register services.
	authService := handlers.NewAuthService(userRepo, refreshTokenRepo, jwtManager, tokenBlacklist)
	pb.RegisterAuthServiceServer(grpcServer, authService)

	secretsService := handlers.NewSecretsService(secretRepo, config.DefaultLimits())
	pb.RegisterSecretsServiceServer(grpcServer, secretsService)

	syncService := handlers.NewSyncService(secretRepo, transactor, config.DefaultLimits())
	pb.RegisterSyncServiceServer(grpcServer, syncService)

	// Listen on random available port.
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", "localhost:0")
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

	// Create clients.
	authClient := pb.NewAuthServiceClient(conn)
	secretsClient := pb.NewSecretsServiceClient(conn)
	syncClient := pb.NewSyncServiceClient(conn)

	t.Logf("Test gRPC server started on %s", addr)

	// Cleanup function.
	cleanup := func() {
		conn.Close()
		grpcServer.GracefulStop()
		listener.Close()
		tokenBlacklist.Stop()
	}

	t.Cleanup(cleanup)

	return &testSyncServer{
		grpcServer:     grpcServer,
		authClient:     authClient,
		secretsClient:  secretsClient,
		syncClient:     syncClient,
		listener:       listener,
		tokenBlacklist: tokenBlacklist,
		pool:           tc,
		cleanup:        cleanup,
	}
}

// clientSession represents a client session with authentication context and device info.
type clientSession struct {
	authCtx       context.Context
	deviceID      string
	encryptionKey []byte
	userID        string
}

// createClientSession registers a user and creates an authenticated session for a device.
func createClientSession(t *testing.T, server *testSyncServer, username, password, deviceID string) *clientSession {
	t.Helper()

	ctx := context.Background()

	// Register user (or login if already exists).
	registerReq := &pb.RegisterRequest{
		Username:       username,
		MasterPassword: password,
		DeviceInfo:     deviceID,
	}

	ctx, cancel := context.WithTimeout(ctx, testTimeout)
	defer cancel()

	registerResp, err := server.authClient.Register(ctx, registerReq)

	// If user already exists, login instead.
	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.AlreadyExists {
			loginReq := &pb.LoginRequest{
				Username:       username,
				MasterPassword: password,
				DeviceInfo:     deviceID,
			}
			loginResp, loginErr := server.authClient.Login(ctx, loginReq)
			require.NoError(t, loginErr, "login should succeed")

			// Convert LoginResponse to RegisterResponse-like structure.
			registerResp = &pb.RegisterResponse{
				UserId:       loginResp.UserId,
				AccessToken:  loginResp.AccessToken,
				RefreshToken: loginResp.RefreshToken,
				ExpiresAt:    loginResp.ExpiresAt,
				Message:      loginResp.Message,
			}
		} else {
			require.NoError(t, err, "register should succeed")
		}
	}

	require.NotNil(t, registerResp)

	// Create authenticated context with access token and device ID.
	authCtx := metadata.AppendToOutgoingContext(
		context.Background(),
		"authorization", "Bearer "+registerResp.AccessToken,
		"x-device-id", deviceID,
	)

	// Derive encryption key from master password (client-side operation).
	salt, err := crypto.GenerateSalt(crypto.SaltLength)
	require.NoError(t, err)
	encryptionKey := crypto.DeriveKey(password, salt)

	return &clientSession{
		authCtx:       authCtx,
		deviceID:      deviceID,
		encryptionKey: encryptionKey,
		userID:        registerResp.UserId,
	}
}

// encryptTestData encrypts test data using the client's encryption key.
func encryptTestData(t *testing.T, data interface{}, encryptionKey []byte) string {
	t.Helper()

	plaintext, err := json.Marshal(data)
	require.NoError(t, err, "failed to marshal data")

	encrypted, err := crypto.Encrypt(plaintext, encryptionKey)
	require.NoError(t, err, "failed to encrypt data")

	return encrypted
}

// TestSyncFlow_TwoClientsLastWriteWins tests last-write-wins conflict resolution.
func TestSyncFlow_TwoClientsLastWriteWins(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create two client sessions for the same user.
	username := "sync-user-lww@example.com"
	password := "secure-password"

	client1 := createClientSession(t, server, username, password, "device-1")
	client2 := createClientSession(t, server, username, password, "device-2")

	// Both clients are authenticated as the same user.
	assert.Equal(t, client1.userID, client2.userID, "both clients should be the same user")

	t.Run("Both clients create secrets, then one updates (last-write-wins)", func(t *testing.T) {
		// Client 1 creates secret.
		data1 := &pb.TextData{Content: "Client 1 data"}
		encrypted1 := encryptTestData(t, data1, client1.encryptionKey)

		secret1 := &pb.Secret{
			Id:            uuid.New().String(),
			Title:         "Client 1 Secret",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encrypted1,
			Version:       0, // New secret.
		}

		// Client 1 pushes first.
		pushReq1 := &pb.PushRequest{
			Secrets: []*pb.Secret{secret1},
		}

		pushResp1, err := server.syncClient.Push(client1.authCtx, pushReq1)
		require.NoError(t, err, "client 1 push should succeed")
		assert.Len(t, pushResp1.AcceptedSecretIds, 1, "client 1 secret should be accepted")
		assert.Empty(t, pushResp1.Conflicts, "client 1 should have no conflicts")

		// Get the server-assigned ID for the secret.
		serverSecretID := pushResp1.AcceptedSecretIds[0]

		// Wait a moment to ensure different timestamps.
		time.Sleep(100 * time.Millisecond)

		// Client 2 pulls to get the secret.
		pullReq2 := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}
		pullResp2, err := server.syncClient.Pull(client2.authCtx, pullReq2)
		require.NoError(t, err)

		// Client 2 should see the secret from client 1.
		require.Len(t, pullResp2.Secrets, 1)
		syncedSecret := pullResp2.Secrets[0]
		assert.Equal(t, serverSecretID, syncedSecret.Id)

		// Now client 2 updates with its own data (last-write-wins).
		data2 := &pb.TextData{Content: "Client 2 data overwrites"}
		encrypted2 := encryptTestData(t, data2, client2.encryptionKey)

		secret2 := &pb.Secret{
			Id:            syncedSecret.Id,
			Title:         "Updated by Client 2",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encrypted2,
			Version:       syncedSecret.Version,
		}

		pushReq2Updated := &pb.PushRequest{
			Secrets: []*pb.Secret{secret2},
		}

		pushResp2, err := server.syncClient.Push(client2.authCtx, pushReq2Updated)
		require.NoError(t, err, "client 2 push should succeed")
		assert.Len(t, pushResp2.AcceptedSecretIds, 1, "client 2 secret should be accepted")
		assert.Empty(t, pushResp2.Conflicts)

		// Verify the update succeeded.
		pullReq3 := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}
		pullResp3, err := server.syncClient.Pull(client1.authCtx, pullReq3)
		require.NoError(t, err)

		require.Len(t, pullResp3.Secrets, 1)
		finalSecret := pullResp3.Secrets[0]
		assert.Equal(t, "Updated by Client 2", finalSecret.Title)
		assert.Equal(t, int64(2), finalSecret.Version, "version should be 2 after update")

		t.Logf("Last-write-wins: Client 2 successfully overwrote Client 1's data (version %d)", finalSecret.Version)
	})
}

// TestSyncFlow_VersionConflictDetection tests version conflict detection and rejection.
func TestSyncFlow_VersionConflictDetection(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create two client sessions for the same user.
	username := "sync-user-conflict@example.com"
	password := "secure-password"

	clientA := createClientSession(t, server, username, password, "device-A")
	clientB := createClientSession(t, server, username, password, "device-B")

	// Create initial secret.
	secretID := uuid.New()
	initialData := &pb.TextData{Content: "Initial data"}
	encryptedInitial := encryptTestData(t, initialData, clientA.encryptionKey)

	createReq := &pb.CreateSecretRequest{
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
		Title:         "Test Secret",
		EncryptedData: encryptedInitial,
	}

	createResp, err := server.secretsClient.CreateSecret(clientA.authCtx, createReq)
	require.NoError(t, err)
	secretID = uuid.MustParse(createResp.Secret.Id)
	currentVersion := createResp.Secret.Version

	t.Run("Client A updates to version 2", func(t *testing.T) {
		updatedData := &pb.TextData{Content: "Client A update"}
		encrypted := encryptTestData(t, updatedData, clientA.encryptionKey)

		secret := &pb.Secret{
			Id:            secretID.String(),
			Title:         "Updated by A",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encrypted,
			Version:       currentVersion, // Version 1
		}

		pushReq := &pb.PushRequest{
			Secrets: []*pb.Secret{secret},
		}

		pushResp, err := server.syncClient.Push(clientA.authCtx, pushReq)
		require.NoError(t, err)
		assert.Len(t, pushResp.AcceptedSecretIds, 1)
		assert.Empty(t, pushResp.Conflicts)

		// Verify version is now 2.
		getReq := &pb.GetSecretRequest{SecretId: secretID.String()}
		getResp, err := server.secretsClient.GetSecret(clientA.authCtx, getReq)
		require.NoError(t, err)
		assert.Equal(t, int64(2), getResp.Secret.Version)

		currentVersion = getResp.Secret.Version
		t.Logf("Client A updated secret to version %d", currentVersion)
	})

	t.Run("Client B tries to update version 1 - conflict detected", func(t *testing.T) {
		updatedData := &pb.TextData{Content: "Client B update"}
		encrypted := encryptTestData(t, updatedData, clientB.encryptionKey)

		secret := &pb.Secret{
			Id:            secretID.String(),
			Title:         "Updated by B",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encrypted,
			Version:       1, // Stale version.
		}

		pushReq := &pb.PushRequest{
			Secrets: []*pb.Secret{secret},
		}

		pushResp, err := server.syncClient.Push(clientB.authCtx, pushReq)
		require.NoError(t, err, "push should succeed but with conflicts")

		// Client B's update should be rejected with conflict.
		assert.Empty(t, pushResp.AcceptedSecretIds, "stale update should not be accepted")
		assert.Len(t, pushResp.Conflicts, 1, "should have 1 conflict")

		conflict := pushResp.Conflicts[0]
		assert.Equal(t, secretID.String(), conflict.SecretId)
		assert.Equal(t, pb.ConflictType_CONFLICT_TYPE_VERSION_MISMATCH, conflict.Type)
		assert.NotNil(t, conflict.ServerVersion)
		assert.Equal(t, int64(2), conflict.ServerVersion.Version, "conflict should report server version 2")
		assert.Contains(t, conflict.Description, "version mismatch")

		t.Logf("Conflict detected: Client B tried to update v1, server has v%d", conflict.ServerVersion.Version)
	})

	t.Run("Client B pulls changes and updates successfully", func(t *testing.T) {
		// Client B pulls to get latest version.
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(clientB.authCtx, pullReq)
		require.NoError(t, err)
		require.Len(t, pullResp.Secrets, 1)

		latestSecret := pullResp.Secrets[0]
		assert.Equal(t, int64(2), latestSecret.Version)
		assert.Equal(t, "Updated by A", latestSecret.Title)

		t.Logf("Client B pulled latest version: v%d", latestSecret.Version)

		// Now Client B can update with correct version.
		updatedData := &pb.TextData{Content: "Client B update after pull"}
		encrypted := encryptTestData(t, updatedData, clientB.encryptionKey)

		secret := &pb.Secret{
			Id:            secretID.String(),
			Title:         "Updated by B (resolved)",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encrypted,
			Version:       latestSecret.Version, // Correct version.
		}

		pushReq := &pb.PushRequest{
			Secrets: []*pb.Secret{secret},
		}

		pushResp, err := server.syncClient.Push(clientB.authCtx, pushReq)
		require.NoError(t, err)
		assert.Len(t, pushResp.AcceptedSecretIds, 1, "update should succeed")
		assert.Empty(t, pushResp.Conflicts)

		t.Logf("Client B successfully updated after resolving conflict")
	})
}

// TestSyncFlow_PullFiltersByTimestamp tests Pull operation with last_sync_time filtering.
func TestSyncFlow_PullFiltersByTimestamp(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create client session.
	client := createClientSession(t, server, "sync-user-timestamp@example.com", "password", "device-1")

	// Create initial secret.
	data1 := &pb.TextData{Content: "Secret 1"}
	encrypted1 := encryptTestData(t, data1, client.encryptionKey)

	createReq1 := &pb.CreateSecretRequest{
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
		Title:         "Secret 1",
		EncryptedData: encrypted1,
	}

	createResp1, err := server.secretsClient.CreateSecret(client.authCtx, createReq1)
	require.NoError(t, err)
	secret1Created := createResp1.Secret.CreatedAt.AsTime()

	t.Run("Pull returns all secrets with epoch timestamp", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(client.authCtx, pullReq)
		require.NoError(t, err)

		assert.Len(t, pullResp.Secrets, 1, "should return 1 secret")
		assert.Equal(t, "Secret 1", pullResp.Secrets[0].Title)
		assert.Empty(t, pullResp.DeletedSecretIds)

		t.Logf("Pull with epoch returned %d secrets", len(pullResp.Secrets))
	})

	// Wait and record sync time.
	time.Sleep(100 * time.Millisecond)
	lastSyncTime := time.Now()
	time.Sleep(100 * time.Millisecond)

	// Create second secret after sync time.
	data2 := &pb.TextData{Content: "Secret 2"}
	encrypted2 := encryptTestData(t, data2, client.encryptionKey)

	createReq2 := &pb.CreateSecretRequest{
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
		Title:         "Secret 2",
		EncryptedData: encrypted2,
	}

	createResp2, err := server.secretsClient.CreateSecret(client.authCtx, createReq2)
	require.NoError(t, err)
	secret2Created := createResp2.Secret.CreatedAt.AsTime()

	t.Run("Pull with last_sync_time returns only new secrets", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(lastSyncTime),
		}

		pullResp, err := server.syncClient.Pull(client.authCtx, pullReq)
		require.NoError(t, err)

		// Should only return Secret 2 (created after lastSyncTime).
		assert.Len(t, pullResp.Secrets, 1, "should return only new secret")
		assert.Equal(t, "Secret 2", pullResp.Secrets[0].Title)
		assert.True(t, secret2Created.After(lastSyncTime))
		assert.True(t, secret1Created.Before(lastSyncTime))

		t.Logf("Pull with timestamp filter returned %d secrets (filtered out older ones)", len(pullResp.Secrets))
	})

	t.Run("Pull with future timestamp returns nothing", func(t *testing.T) {
		futureTime := time.Now().Add(1 * time.Hour)
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(futureTime),
		}

		pullResp, err := server.syncClient.Pull(client.authCtx, pullReq)
		require.NoError(t, err)

		assert.Empty(t, pullResp.Secrets, "should return no secrets")
		assert.Empty(t, pullResp.DeletedSecretIds)

		t.Logf("Pull with future timestamp correctly returned empty result")
	})
}

// TestSyncFlow_DeletedItemsSync tests sync of deleted items (tombstones).
func TestSyncFlow_DeletedItemsSync(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create two client sessions for the same user.
	username := "sync-user-delete@example.com"
	password := "secure-password"

	client1 := createClientSession(t, server, username, password, "device-1")
	client2 := createClientSession(t, server, username, password, "device-2")

	// Client 1 creates a secret.
	data := &pb.TextData{Content: "Secret to delete"}
	encrypted := encryptTestData(t, data, client1.encryptionKey)

	createReq := &pb.CreateSecretRequest{
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
		Title:         "To Delete",
		EncryptedData: encrypted,
	}

	createResp, err := server.secretsClient.CreateSecret(client1.authCtx, createReq)
	require.NoError(t, err)
	secretID := createResp.Secret.Id

	// Wait a moment.
	time.Sleep(100 * time.Millisecond)
	syncTimeBefore := time.Now()
	time.Sleep(100 * time.Millisecond)

	t.Run("Client 1 deletes secret", func(t *testing.T) {
		deleteReq := &pb.DeleteSecretRequest{
			SecretId: secretID,
		}

		deleteResp, err := server.secretsClient.DeleteSecret(client1.authCtx, deleteReq)
		require.NoError(t, err)
		assert.Equal(t, "Secret deleted successfully", deleteResp.Message)

		t.Logf("Client 1 deleted secret %s", secretID)
	})

	t.Run("Client 2 pulls and receives deletion", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(syncTimeBefore),
		}

		pullResp, err := server.syncClient.Pull(client2.authCtx, pullReq)
		require.NoError(t, err)

		// Should have no active secrets, but should have the deleted secret ID.
		assert.Empty(t, pullResp.Secrets, "should have no active secrets")
		assert.Len(t, pullResp.DeletedSecretIds, 1, "should have 1 deleted secret")
		assert.Equal(t, secretID, pullResp.DeletedSecretIds[0])

		t.Logf("Client 2 received deletion notification for secret %s", secretID)
	})

	t.Run("Client 2 pushes deletion again (idempotent)", func(t *testing.T) {
		// Client 2 also tries to delete (simulating offline deletion that happened before sync).
		pushReq := &pb.PushRequest{
			DeletedSecretIds: []string{secretID},
		}

		pushResp, err := server.syncClient.Push(client2.authCtx, pushReq)
		require.NoError(t, err)

		// Should accept (idempotent delete).
		assert.Contains(t, pushResp.AcceptedSecretIds, secretID, "idempotent delete should succeed")
		assert.Empty(t, pushResp.Conflicts)

		t.Logf("Client 2's redundant delete request was handled idempotently")
	})
}

// TestSyncFlow_ConcurrentPushes tests concurrent push operations with goroutines.
func TestSyncFlow_ConcurrentPushes(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create client session.
	client := createClientSession(t, server, "sync-user-concurrent@example.com", "password", "device-1")

	const concurrency = 10
	var wg sync.WaitGroup
	type pushResult struct {
		index int
		id    string
		err   error
	}
	results := make(chan pushResult, concurrency)

	t.Run("Concurrent push creates", func(t *testing.T) {
		// Launch concurrent pushes.
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				data := &pb.TextData{Content: fmt.Sprintf("Secret %d", index)}
				encrypted := encryptTestData(t, data, client.encryptionKey)

				secret := &pb.Secret{
					Id:            uuid.New().String(), // Client-provided ID (may not be preserved).
					Title:         fmt.Sprintf("Concurrent Secret %d", index),
					Type:          pb.SecretType_SECRET_TYPE_TEXT,
					EncryptedData: encrypted,
					Version:       0,
				}

				pushReq := &pb.PushRequest{
					Secrets: []*pb.Secret{secret},
				}

				pushResp, err := server.syncClient.Push(client.authCtx, pushReq)
				if err != nil {
					results <- pushResult{index: index, err: err}
					return
				}

				if len(pushResp.AcceptedSecretIds) == 1 {
					results <- pushResult{index: index, id: pushResp.AcceptedSecretIds[0]}
				} else {
					results <- pushResult{index: index, err: fmt.Errorf("no accepted IDs")}
				}
			}(i)
		}

		wg.Wait()
		close(results)

		// Count successes and collect server-assigned IDs.
		successCount := 0
		for result := range results {
			if result.err == nil && result.id != "" {
				successCount++
			} else {
				t.Logf("Push %d failed: %v", result.index, result.err)
			}
		}

		assert.Equal(t, concurrency, successCount, "all concurrent pushes should succeed")
		t.Logf("Successfully completed %d concurrent push operations", successCount)
	})

	t.Run("Verify all secrets were created", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(client.authCtx, pullReq)
		require.NoError(t, err)

		assert.Len(t, pullResp.Secrets, concurrency, "should have all concurrent secrets")

		// Verify all secrets have unique IDs and expected titles.
		returnedIDs := make(map[string]bool)
		titleCount := 0
		for _, secret := range pullResp.Secrets {
			assert.NotContains(t, returnedIDs, secret.Id, "all IDs should be unique")
			returnedIDs[secret.Id] = true

			// Check if title matches expected pattern.
			if len(secret.Title) > len("Concurrent Secret ") {
				titleCount++
			}
		}

		assert.Equal(t, concurrency, titleCount, "all secrets should have expected title pattern")
		t.Logf("Verified all %d concurrent secrets were created successfully with unique IDs", len(pullResp.Secrets))
	})
}

// TestSyncFlow_ConcurrentUpdatesToSameSecret tests race conditions on updates.
func TestSyncFlow_ConcurrentUpdatesToSameSecret(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create client session.
	client := createClientSession(t, server, "sync-user-race@example.com", "password", "device-1")

	// Create initial secret.
	data := &pb.TextData{Content: "Initial"}
	encrypted := encryptTestData(t, data, client.encryptionKey)

	createReq := &pb.CreateSecretRequest{
		Type:          pb.SecretType_SECRET_TYPE_TEXT,
		Title:         "Race Test",
		EncryptedData: encrypted,
	}

	createResp, err := server.secretsClient.CreateSecret(client.authCtx, createReq)
	require.NoError(t, err)
	secretID := createResp.Secret.Id
	initialVersion := createResp.Secret.Version

	t.Run("Concurrent updates to same secret with same version", func(t *testing.T) {
		const concurrency = 5
		var wg sync.WaitGroup
		acceptedCount := 0
		conflictCount := 0
		var mu sync.Mutex

		// Launch concurrent updates with same version.
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				data := &pb.TextData{Content: fmt.Sprintf("Update %d", index)}
				encrypted := encryptTestData(t, data, client.encryptionKey)

				secret := &pb.Secret{
					Id:            secretID,
					Title:         fmt.Sprintf("Updated %d", index),
					Type:          pb.SecretType_SECRET_TYPE_TEXT,
					EncryptedData: encrypted,
					Version:       initialVersion, // All use same version.
				}

				pushReq := &pb.PushRequest{
					Secrets: []*pb.Secret{secret},
				}

				pushResp, err := server.syncClient.Push(client.authCtx, pushReq)
				if err != nil {
					t.Logf("Update %d error: %v", index, err)
					return
				}

				mu.Lock()
				defer mu.Unlock()

				if len(pushResp.AcceptedSecretIds) > 0 {
					acceptedCount++
					t.Logf("Update %d was accepted", index)
				}
				if len(pushResp.Conflicts) > 0 {
					conflictCount++
					t.Logf("Update %d had conflict", index)
				}
			}(i)
		}

		wg.Wait()

		// Only one update should succeed due to optimistic locking.
		assert.Equal(t, 1, acceptedCount, "only one concurrent update should succeed")
		assert.Equal(t, concurrency-1, conflictCount, "others should have conflicts")

		t.Logf("Concurrent update race: %d accepted, %d conflicts (expected 1 accepted, %d conflicts)",
			acceptedCount, conflictCount, concurrency-1)
	})

	t.Run("Verify final version is correct", func(t *testing.T) {
		getReq := &pb.GetSecretRequest{SecretId: secretID}
		getResp, err := server.secretsClient.GetSecret(client.authCtx, getReq)
		require.NoError(t, err)

		// Version should be initial + 1 (only one update succeeded).
		assert.Equal(t, initialVersion+1, getResp.Secret.Version)

		t.Logf("Final version: %d (expected %d)", getResp.Secret.Version, initialVersion+1)
	})
}

// TestSyncFlow_DeviceIDTracking tests device_id tracking in sync operations.
func TestSyncFlow_DeviceIDTracking(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create multiple device sessions for same user.
	username := "sync-user-devices@example.com"
	password := "secure-password"

	laptop := createClientSession(t, server, username, password, "laptop-001")
	phone := createClientSession(t, server, username, password, "phone-002")
	tablet := createClientSession(t, server, username, password, "tablet-003")

	t.Run("Verify all devices are same user", func(t *testing.T) {
		assert.Equal(t, laptop.userID, phone.userID)
		assert.Equal(t, laptop.userID, tablet.userID)

		assert.NotEqual(t, laptop.deviceID, phone.deviceID)
		assert.NotEqual(t, laptop.deviceID, tablet.deviceID)
		assert.NotEqual(t, phone.deviceID, tablet.deviceID)

		t.Logf("All devices authenticated as user %s with different device IDs", laptop.userID)
	})

	t.Run("Laptop creates secret", func(t *testing.T) {
		data := &pb.TextData{Content: "Laptop secret"}
		encrypted := encryptTestData(t, data, laptop.encryptionKey)

		createReq := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			Title:         "Laptop Secret",
			EncryptedData: encrypted,
		}

		createResp, err := server.secretsClient.CreateSecret(laptop.authCtx, createReq)
		require.NoError(t, err)

		t.Logf("Laptop created secret %s", createResp.Secret.Id)
	})

	t.Run("Phone and tablet sync to receive laptop's secret", func(t *testing.T) {
		// Phone pulls.
		pullReqPhone := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullRespPhone, err := server.syncClient.Pull(phone.authCtx, pullReqPhone)
		require.NoError(t, err)
		assert.Len(t, pullRespPhone.Secrets, 1, "phone should receive laptop's secret")
		assert.Equal(t, "Laptop Secret", pullRespPhone.Secrets[0].Title)

		// Tablet pulls.
		pullReqTablet := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullRespTablet, err := server.syncClient.Pull(tablet.authCtx, pullReqTablet)
		require.NoError(t, err)
		assert.Len(t, pullRespTablet.Secrets, 1, "tablet should receive laptop's secret")
		assert.Equal(t, "Laptop Secret", pullRespTablet.Secrets[0].Title)

		t.Logf("Phone and tablet successfully synced laptop's secret")
	})

	t.Run("Each device can push independently", func(t *testing.T) {
		// Each device creates a secret.
		devices := []*clientSession{phone, tablet}
		deviceNames := []string{"Phone", "Tablet"}

		for i, device := range devices {
			data := &pb.TextData{Content: fmt.Sprintf("%s secret", deviceNames[i])}
			encrypted := encryptTestData(t, data, device.encryptionKey)

			secret := &pb.Secret{
				Id:            uuid.New().String(),
				Title:         fmt.Sprintf("%s Secret", deviceNames[i]),
				Type:          pb.SecretType_SECRET_TYPE_TEXT,
				EncryptedData: encrypted,
				Version:       0,
			}

			pushReq := &pb.PushRequest{
				Secrets: []*pb.Secret{secret},
			}

			pushResp, err := server.syncClient.Push(device.authCtx, pushReq)
			require.NoError(t, err, "%s push should succeed", deviceNames[i])
			assert.Len(t, pushResp.AcceptedSecretIds, 1)
		}

		t.Logf("All devices successfully pushed their own secrets")
	})

	t.Run("Verify all devices see all secrets", func(t *testing.T) {
		devices := []*clientSession{laptop, phone, tablet}
		deviceNames := []string{"Laptop", "Phone", "Tablet"}

		for i, device := range devices {
			pullReq := &pb.PullRequest{
				LastSyncTime: timestamppb.New(time.Unix(0, 0)),
			}

			pullResp, err := server.syncClient.Pull(device.authCtx, pullReq)
			require.NoError(t, err, "%s pull should succeed", deviceNames[i])

			// Should see all 3 secrets (laptop, phone, tablet).
			assert.Len(t, pullResp.Secrets, 3, "%s should see all 3 secrets", deviceNames[i])
		}

		t.Logf("All devices successfully synced and see all secrets")
	})
}

// TestSyncFlow_GetSyncStatus tests the GetSyncStatus operation.
func TestSyncFlow_GetSyncStatus(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create client session.
	client := createClientSession(t, server, "sync-user-status@example.com", "password", "device-1")

	t.Run("GetSyncStatus with no secrets", func(t *testing.T) {
		req := &pb.GetSyncStatusRequest{}

		resp, err := server.syncClient.GetSyncStatus(client.authCtx, req)
		require.NoError(t, err)

		assert.Equal(t, int32(0), resp.TotalSecrets)
		assert.Equal(t, int32(0), resp.PendingChanges)
		assert.NotNil(t, resp.LastSyncTime)

		t.Logf("Sync status with 0 secrets: %+v", resp)
	})

	// Create some secrets.
	for i := 0; i < 5; i++ {
		data := &pb.TextData{Content: fmt.Sprintf("Secret %d", i)}
		encrypted := encryptTestData(t, data, client.encryptionKey)

		createReq := &pb.CreateSecretRequest{
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			Title:         fmt.Sprintf("Secret %d", i),
			EncryptedData: encrypted,
		}

		_, err := server.secretsClient.CreateSecret(client.authCtx, createReq)
		require.NoError(t, err)
	}

	t.Run("GetSyncStatus with secrets", func(t *testing.T) {
		req := &pb.GetSyncStatusRequest{}

		resp, err := server.syncClient.GetSyncStatus(client.authCtx, req)
		require.NoError(t, err)

		assert.Equal(t, int32(5), resp.TotalSecrets)
		assert.NotNil(t, resp.LastSyncTime)

		t.Logf("Sync status with 5 secrets: %+v", resp)
	})
}

// TestSyncFlow_CompleteMultiDeviceScenario tests a comprehensive multi-device sync scenario.
func TestSyncFlow_CompleteMultiDeviceScenario(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create devices.
	username := "sync-user-complete@example.com"
	password := "secure-password"

	deviceA := createClientSession(t, server, username, password, "device-A")
	deviceB := createClientSession(t, server, username, password, "device-B")

	t.Run("Device A creates secrets offline", func(t *testing.T) {
		for i := 1; i <= 3; i++ {
			data := &pb.TextData{Content: fmt.Sprintf("Device A Secret %d", i)}
			encrypted := encryptTestData(t, data, deviceA.encryptionKey)

			secret := &pb.Secret{
				Id:            uuid.New().String(),
				Title:         fmt.Sprintf("A-Secret-%d", i),
				Type:          pb.SecretType_SECRET_TYPE_TEXT,
				EncryptedData: encrypted,
				Version:       0,
			}

			pushReq := &pb.PushRequest{
				Secrets: []*pb.Secret{secret},
			}

			_, err := server.syncClient.Push(deviceA.authCtx, pushReq)
			require.NoError(t, err)
		}

		t.Logf("Device A created 3 secrets")
	})

	// Record sync point.
	time.Sleep(100 * time.Millisecond)
	syncPoint1 := time.Now()
	time.Sleep(100 * time.Millisecond)

	t.Run("Device B pulls Device A's secrets", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(deviceB.authCtx, pullReq)
		require.NoError(t, err)

		assert.Len(t, pullResp.Secrets, 3, "Device B should see Device A's secrets")

		t.Logf("Device B synced and received 3 secrets from Device A")
	})

	t.Run("Device B creates and modifies secrets", func(t *testing.T) {
		// Device B creates new secret.
		data := &pb.TextData{Content: "Device B Secret"}
		encrypted := encryptTestData(t, data, deviceB.encryptionKey)

		secret := &pb.Secret{
			Id:            uuid.New().String(),
			Title:         "B-Secret-1",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encrypted,
			Version:       0,
		}

		pushReq := &pb.PushRequest{
			Secrets: []*pb.Secret{secret},
		}

		_, err := server.syncClient.Push(deviceB.authCtx, pushReq)
		require.NoError(t, err)

		t.Logf("Device B created 1 new secret")
	})

	// Record another sync point.
	time.Sleep(100 * time.Millisecond)
	syncPoint2 := time.Now()
	time.Sleep(100 * time.Millisecond)

	t.Run("Device A pulls Device B's changes incrementally", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(syncPoint1),
		}

		pullResp, err := server.syncClient.Pull(deviceA.authCtx, pullReq)
		require.NoError(t, err)

		// Should only see Device B's new secret (created after syncPoint1).
		assert.Len(t, pullResp.Secrets, 1, "Device A should see Device B's new secret")
		assert.Equal(t, "B-Secret-1", pullResp.Secrets[0].Title)

		t.Logf("Device A incrementally synced Device B's changes")
	})

	// One device deletes a secret.
	var deletedSecretID string

	t.Run("Device A deletes a secret", func(t *testing.T) {
		// Get one of Device A's secrets.
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(deviceA.authCtx, pullReq)
		require.NoError(t, err)
		require.NotEmpty(t, pullResp.Secrets)

		// Find a Device A secret.
		for _, secret := range pullResp.Secrets {
			if secret.Title[:2] == "A-" {
				deletedSecretID = secret.Id
				break
			}
		}

		require.NotEmpty(t, deletedSecretID, "should find a Device A secret to delete")

		// Delete it.
		pushReq := &pb.PushRequest{
			DeletedSecretIds: []string{deletedSecretID},
		}

		_, err = server.syncClient.Push(deviceA.authCtx, pushReq)
		require.NoError(t, err)

		t.Logf("Device A deleted secret %s", deletedSecretID)
	})

	t.Run("Device B pulls deletion", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(syncPoint2),
		}

		pullResp, err := server.syncClient.Pull(deviceB.authCtx, pullReq)
		require.NoError(t, err)

		// Should see the deletion.
		assert.Contains(t, pullResp.DeletedSecretIds, deletedSecretID, "Device B should receive deletion")

		t.Logf("Device B synced deletion notification")
	})

	t.Run("Final state verification", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(deviceA.authCtx, pullReq)
		require.NoError(t, err)

		// Should have 3 active secrets (2 from A + 1 from B).
		assert.Len(t, pullResp.Secrets, 3, "should have 3 active secrets")

		// Verify the deleted secret is not in the list.
		for _, secret := range pullResp.Secrets {
			assert.NotEqual(t, deletedSecretID, secret.Id, "deleted secret should not be in active list")
		}

		t.Logf("Final state: %d active secrets", len(pullResp.Secrets))
	})
}

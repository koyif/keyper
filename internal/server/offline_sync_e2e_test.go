// Package server contains E2E integration tests for the Keyper server.
// These tests validate offline sync scenarios and batch operations.
package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/koyif/keyper/internal/server/testhelpers"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// TestOfflineSync_BatchCreateWhileOffline tests creating multiple secrets locally
// while offline, then pushing them all in a batch when coming back online.
func TestOfflineSync_BatchCreateWhileOffline(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create user and device.
	user := CreateTestUser(t, server.authClient, "offline-batch@example.com", "password123")

	t.Run("Client creates multiple secrets while offline", func(t *testing.T) {
		// Simulate creating secrets locally while offline.
		// In a real scenario, these would be stored locally in SQLite.
		offlineSecrets := make([]*pb.Secret, 0, 5)

		// Create 5 different types of secrets offline.
		credData := &pb.CredentialData{
			Username: "offline-user",
			Password: "offline-pass",
			Email:    "offline@example.com",
		}
		offlineSecrets = append(offlineSecrets, CreateTestSecretForSync(t, user, pb.SecretType_SECRET_TYPE_CREDENTIAL, credData))

		textData := &pb.TextData{Content: "Offline note"}
		offlineSecrets = append(offlineSecrets, CreateTestSecretForSync(t, user, pb.SecretType_SECRET_TYPE_TEXT, textData))

		binaryData := &pb.BinaryData{
			Filename: "offline-file.bin",
			MimeType: "application/octet-stream",
			Data:     randomBytes(512),
		}
		offlineSecrets = append(offlineSecrets, CreateTestSecretForSync(t, user, pb.SecretType_SECRET_TYPE_BINARY, binaryData))

		cardData := &pb.BankCardData{
			CardholderName: "Offline User",
			CardNumber:     "4532-1234-5678-9010",
			Cvv:            "123",
		}
		offlineSecrets = append(offlineSecrets, CreateTestSecretForSync(t, user, pb.SecretType_SECRET_TYPE_BANK_CARD, cardData))

		textData2 := &pb.TextData{Content: "Another offline note"}
		offlineSecrets = append(offlineSecrets, CreateTestSecretForSync(t, user, pb.SecretType_SECRET_TYPE_TEXT, textData2))

		assert.Len(t, offlineSecrets, 5, "should have 5 offline secrets ready to sync")
		t.Logf("Created %d secrets while 'offline'", len(offlineSecrets))

		// Now "come back online" and batch push all secrets.
		pushReq := &pb.PushRequest{
			Secrets: offlineSecrets,
		}

		pushResp, err := server.syncClient.Push(user.AuthCtx, pushReq)
		require.NoError(t, err, "batch push should succeed")

		// Verify all secrets were accepted.
		assert.Len(t, pushResp.AcceptedSecretIds, 5, "all 5 secrets should be accepted")
		assert.Empty(t, pushResp.Conflicts, "should have no conflicts")

		t.Logf("Successfully pushed %d secrets in a single batch", len(pushResp.AcceptedSecretIds))
	})

	t.Run("Verify all offline secrets are now on server", func(t *testing.T) {
		// Pull all secrets to verify they were synced.
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(user.AuthCtx, pullReq)
		require.NoError(t, err, "pull should succeed")

		// Should have all 5 secrets.
		assert.Len(t, pullResp.Secrets, 5, "should have all 5 secrets on server")

		// Verify secret types are correct.
		typeCount := make(map[pb.SecretType]int)
		for _, secret := range pullResp.Secrets {
			typeCount[secret.Type]++
			assert.Equal(t, int64(1), secret.Version, "all new secrets should have version 1")
			assert.False(t, secret.IsDeleted, "no secrets should be deleted")
		}

		assert.Equal(t, 1, typeCount[pb.SecretType_SECRET_TYPE_CREDENTIAL], "should have 1 credential")
		assert.Equal(t, 2, typeCount[pb.SecretType_SECRET_TYPE_TEXT], "should have 2 text secrets")
		assert.Equal(t, 1, typeCount[pb.SecretType_SECRET_TYPE_BINARY], "should have 1 binary secret")
		assert.Equal(t, 1, typeCount[pb.SecretType_SECRET_TYPE_BANK_CARD], "should have 1 bank card")

		t.Logf("Verified all %d offline secrets successfully synced to server", len(pullResp.Secrets))
	})
}

// TestOfflineSync_BatchUpdateWhileOffline tests updating multiple secrets
// while offline and then syncing changes when back online.
func TestOfflineSync_BatchUpdateWhileOffline(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create user and device.
	user := CreateTestUser(t, server.authClient, "offline-update@example.com", "password123")

	// Create initial secrets while online.
	initialSecrets := BatchCreateSecrets(t, server.secretsClient, user, 3)
	require.Len(t, initialSecrets, 3)

	// Pull to get the server versions.
	pullReq := &pb.PullRequest{
		LastSyncTime: timestamppb.New(time.Unix(0, 0)),
	}
	pullResp, err := server.syncClient.Pull(user.AuthCtx, pullReq)
	require.NoError(t, err)
	require.Len(t, pullResp.Secrets, 3)

	serverSecrets := pullResp.Secrets

	t.Run("Client updates multiple secrets while offline", func(t *testing.T) {
		// Simulate updating all secrets locally while offline.
		updatedSecrets := make([]*pb.Secret, 0, len(serverSecrets))

		for i, secret := range serverSecrets {
			// Create updated data.
			updatedData := &pb.TextData{
				Content: fmt.Sprintf("Updated offline content %d at %s", i, time.Now().Format(time.RFC3339)),
			}

			encryptedData := encryptTestData(t, updatedData, user.EncryptionKey)

			updatedSecret := &pb.Secret{
				Id:            secret.Id,
				UserId:        secret.UserId,
				Title:         fmt.Sprintf("Updated Offline %d", i),
				Type:          pb.SecretType_SECRET_TYPE_TEXT,
				EncryptedData: encryptedData,
				Version:       secret.Version,
				IsDeleted:     false,
			}

			updatedSecrets = append(updatedSecrets, updatedSecret)
		}

		// Batch push all updates.
		pushReq := &pb.PushRequest{
			Secrets: updatedSecrets,
		}

		pushResp, err := server.syncClient.Push(user.AuthCtx, pushReq)
		require.NoError(t, err, "batch update push should succeed")

		assert.Len(t, pushResp.AcceptedSecretIds, 3, "all 3 updates should be accepted")
		assert.Empty(t, pushResp.Conflicts, "should have no conflicts")

		t.Logf("Successfully pushed %d updated secrets in a single batch", len(pushResp.AcceptedSecretIds))
	})

	t.Run("Verify all updates are persisted", func(t *testing.T) {
		// Pull to verify updates.
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(user.AuthCtx, pullReq)
		require.NoError(t, err)

		assert.Len(t, pullResp.Secrets, 3, "should have 3 secrets")

		// All secrets should have version 2 (initial version 1 + 1 update).
		for i, secret := range pullResp.Secrets {
			assert.Equal(t, int64(2), secret.Version, "secret %d should have version 2", i)
			assert.Contains(t, secret.Title, "Updated Offline", "title should reflect update")
			assert.False(t, secret.IsDeleted)
		}

		t.Log("Verified all updates persisted correctly with version increments")
	})
}

// TestOfflineSync_MixedOperationsWhileOffline tests a mix of creates, updates,
// and deletes performed while offline, then synced in a single batch.
func TestOfflineSync_MixedOperationsWhileOffline(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create user and device.
	user := CreateTestUser(t, server.authClient, "offline-mixed@example.com", "password123")

	// Create some initial secrets while online.
	initialSecrets := BatchCreateSecrets(t, server.secretsClient, user, 2)
	require.Len(t, initialSecrets, 2)

	// Pull to get server versions.
	pullReq := &pb.PullRequest{
		LastSyncTime: timestamppb.New(time.Unix(0, 0)),
	}
	pullResp, err := server.syncClient.Pull(user.AuthCtx, pullReq)
	require.NoError(t, err)
	require.Len(t, pullResp.Secrets, 2)

	existingSecret1 := pullResp.Secrets[0]
	existingSecret2 := pullResp.Secrets[1]

	t.Run("Client performs mixed operations while offline", func(t *testing.T) {
		// 1. Create a new secret.
		newSecretData := &pb.TextData{Content: "Brand new offline secret"}
		newSecret := CreateTestSecretForSync(t, user, pb.SecretType_SECRET_TYPE_TEXT, newSecretData)

		// 2. Update an existing secret.
		updatedData := &pb.TextData{Content: "Updated existing secret while offline"}
		encryptedUpdated := encryptTestData(t, updatedData, user.EncryptionKey)
		updatedSecret := &pb.Secret{
			Id:            existingSecret1.Id,
			UserId:        existingSecret1.UserId,
			Title:         "Updated While Offline",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encryptedUpdated,
			Version:       existingSecret1.Version,
			IsDeleted:     false,
		}

		// 3. Delete another existing secret.
		deletedSecretID := existingSecret2.Id

		// Batch push: new + update + delete.
		pushReq := &pb.PushRequest{
			Secrets:          []*pb.Secret{newSecret, updatedSecret},
			DeletedSecretIds: []string{deletedSecretID},
		}

		pushResp, err := server.syncClient.Push(user.AuthCtx, pushReq)
		require.NoError(t, err, "mixed operations batch push should succeed")

		// Verify results.
		// Should accept 3 IDs: newSecret, updatedSecret, deletedSecret.
		assert.Len(t, pushResp.AcceptedSecretIds, 3, "should accept all 3 operations")
		assert.Empty(t, pushResp.Conflicts, "should have no conflicts")

		t.Logf("Successfully pushed mixed batch: 1 create, 1 update, 1 delete")
	})

	t.Run("Verify final server state", func(t *testing.T) {
		// Pull to verify final state.
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(user.AuthCtx, pullReq)
		require.NoError(t, err)

		// Should have 2 active secrets:
		// - The newly created secret (version 1)
		// - The updated existing secret (version 2)
		// The deleted secret should not be in the active list.
		assert.Len(t, pullResp.Secrets, 2, "should have 2 active secrets")

		// Find and verify the new secret.
		var foundNew, foundUpdated bool
		for _, secret := range pullResp.Secrets {
			if secret.Version == 1 && secret.Title != "Updated While Offline" {
				foundNew = true
				assert.Equal(t, int64(1), secret.Version, "new secret should have version 1")
			}
			if secret.Title == "Updated While Offline" {
				foundUpdated = true
				assert.Equal(t, int64(2), secret.Version, "updated secret should have version 2")
			}

			// Verify the deleted secret is not present.
			assert.NotEqual(t, existingSecret2.Id, secret.Id, "deleted secret should not be in active list")
		}

		assert.True(t, foundNew, "should find the newly created secret")
		assert.True(t, foundUpdated, "should find the updated secret")

		t.Log("Verified mixed operations batch synced correctly")
	})
}

// TestOfflineSync_ConflictResolutionAfterOffline tests conflict detection
// when two clients make conflicting changes while offline.
func TestOfflineSync_ConflictResolutionAfterOffline(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create user with two devices.
	username := "offline-conflict@example.com"
	password := "password123"
	device1 := CreateTestUserWithDevice(t, server.authClient, username, password, "device-1")
	device2 := LoginTestUserWithDevice(t, server.authClient, username, password, "device-2")

	// Create initial secret.
	_ = CreateTextSecret(t, server.secretsClient, device1)

	// Both devices pull to get the secret.
	pullReq := &pb.PullRequest{
		LastSyncTime: timestamppb.New(time.Unix(0, 0)),
	}
	pullResp1, err := server.syncClient.Pull(device1.AuthCtx, pullReq)
	require.NoError(t, err)
	require.Len(t, pullResp1.Secrets, 1)

	pullResp2, err := server.syncClient.Pull(device2.AuthCtx, pullReq)
	require.NoError(t, err)
	require.Len(t, pullResp2.Secrets, 1)

	serverSecret := pullResp1.Secrets[0]

	t.Run("Device 1 updates while offline and syncs first", func(t *testing.T) {
		// Device 1 updates.
		updatedData := &pb.TextData{Content: "Device 1 offline update"}
		encryptedData := encryptTestData(t, updatedData, device1.EncryptionKey)

		updatedSecret := &pb.Secret{
			Id:            serverSecret.Id,
			UserId:        serverSecret.UserId,
			Title:         "Updated by Device 1",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encryptedData,
			Version:       serverSecret.Version,
			IsDeleted:     false,
		}

		pushReq := &pb.PushRequest{
			Secrets: []*pb.Secret{updatedSecret},
		}

		pushResp, err := server.syncClient.Push(device1.AuthCtx, pushReq)
		require.NoError(t, err)
		assert.Len(t, pushResp.AcceptedSecretIds, 1, "device 1 update should be accepted")
		assert.Empty(t, pushResp.Conflicts)

		t.Log("Device 1 successfully synced its update first")
	})

	t.Run("Device 2 tries to update with stale version - conflict detected", func(t *testing.T) {
		// Device 2 also has an update based on the same original version.
		updatedData := &pb.TextData{Content: "Device 2 offline update"}
		encryptedData := encryptTestData(t, updatedData, device2.EncryptionKey)

		updatedSecret := &pb.Secret{
			Id:            serverSecret.Id,
			UserId:        serverSecret.UserId,
			Title:         "Updated by Device 2",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encryptedData,
			Version:       serverSecret.Version, // Stale version.
			IsDeleted:     false,
		}

		pushReq := &pb.PushRequest{
			Secrets: []*pb.Secret{updatedSecret},
		}

		pushResp, err := server.syncClient.Push(device2.AuthCtx, pushReq)
		require.NoError(t, err, "push should succeed but with conflicts")

		// Device 2's update should be rejected with version conflict.
		assert.Empty(t, pushResp.AcceptedSecretIds, "stale update should not be accepted")
		assert.Len(t, pushResp.Conflicts, 1, "should have 1 conflict")

		conflict := pushResp.Conflicts[0]
		assert.Equal(t, serverSecret.Id, conflict.SecretId)
		assert.Equal(t, pb.ConflictType_CONFLICT_TYPE_VERSION_MISMATCH, conflict.Type)
		assert.NotNil(t, conflict.ServerVersion)
		assert.Equal(t, int64(2), conflict.ServerVersion.Version, "server should be at version 2")

		t.Logf("Device 2 conflict detected: tried v%d, server at v%d", serverSecret.Version, conflict.ServerVersion.Version)
	})

	t.Run("Device 2 pulls latest version and resolves conflict", func(t *testing.T) {
		// Device 2 pulls to get the latest version.
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(device2.AuthCtx, pullReq)
		require.NoError(t, err)
		require.Len(t, pullResp.Secrets, 1)

		latestSecret := pullResp.Secrets[0]
		assert.Equal(t, int64(2), latestSecret.Version)
		assert.Equal(t, "Updated by Device 1", latestSecret.Title)

		t.Log("Device 2 pulled latest version and can now resolve conflict")

		// Device 2 can now update with the correct version.
		// In a real scenario, the app would merge changes or let the user choose.
		// Here we simulate device 2 accepting device 1's changes and making a new update.
		resolvedData := &pb.TextData{Content: "Device 2 update after conflict resolution"}
		encryptedData := encryptTestData(t, resolvedData, device2.EncryptionKey)

		resolvedSecret := &pb.Secret{
			Id:            latestSecret.Id,
			UserId:        latestSecret.UserId,
			Title:         "Resolved by Device 2",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encryptedData,
			Version:       latestSecret.Version, // Correct version.
			IsDeleted:     false,
		}

		pushReq := &pb.PushRequest{
			Secrets: []*pb.Secret{resolvedSecret},
		}

		pushResp, err := server.syncClient.Push(device2.AuthCtx, pushReq)
		require.NoError(t, err)
		assert.Len(t, pushResp.AcceptedSecretIds, 1, "resolved update should be accepted")
		assert.Empty(t, pushResp.Conflicts)

		t.Log("Device 2 successfully resolved conflict and synced update")
	})

	t.Run("Verify final state has resolved version", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(device1.AuthCtx, pullReq)
		require.NoError(t, err)
		require.Len(t, pullResp.Secrets, 1)

		finalSecret := pullResp.Secrets[0]
		assert.Equal(t, int64(3), finalSecret.Version, "final version should be 3")
		assert.Equal(t, "Resolved by Device 2", finalSecret.Title)

		t.Logf("Final state: version %d with resolved changes", finalSecret.Version)
	})
}

// TestOfflineSync_PullChangesFromOtherDevices tests that when a device comes
// back online, it correctly pulls changes made by other devices during the offline period.
func TestOfflineSync_PullChangesFromOtherDevices(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create user with two devices.
	username := "offline-pull@example.com"
	password := "password123"
	deviceA := CreateTestUserWithDevice(t, server.authClient, username, password, "device-A")
	deviceB := LoginTestUserWithDevice(t, server.authClient, username, password, "device-B")

	// Both devices start with initial sync.
	initialSecret := CreateTextSecret(t, server.secretsClient, deviceA)

	// Both devices sync.
	pullReq := &pb.PullRequest{
		LastSyncTime: timestamppb.New(time.Unix(0, 0)),
	}
	pullRespA, err := server.syncClient.Pull(deviceA.AuthCtx, pullReq)
	require.NoError(t, err)
	require.Len(t, pullRespA.Secrets, 1)

	pullRespB, err := server.syncClient.Pull(deviceB.AuthCtx, pullReq)
	require.NoError(t, err)
	require.Len(t, pullRespB.Secrets, 1)

	// Record sync time for device A before it goes offline.
	time.Sleep(100 * time.Millisecond)
	deviceALastSync := time.Now()
	time.Sleep(100 * time.Millisecond)

	t.Run("Device B makes multiple changes while Device A is offline", func(t *testing.T) {
		// Device B creates new secrets.
		for i := 0; i < 3; i++ {
			CreateTextSecret(t, server.secretsClient, deviceB)
		}

		// Device B updates the initial secret.
		serverSecret := pullRespB.Secrets[0]
		updatedData := &pb.TextData{Content: "Updated by Device B while A is offline"}
		encryptedData := encryptTestData(t, updatedData, deviceB.EncryptionKey)

		updatedSecret := &pb.Secret{
			Id:            serverSecret.Id,
			UserId:        serverSecret.UserId,
			Title:         "Updated by B",
			Type:          pb.SecretType_SECRET_TYPE_TEXT,
			EncryptedData: encryptedData,
			Version:       serverSecret.Version,
			IsDeleted:     false,
		}

		pushReq := &pb.PushRequest{
			Secrets: []*pb.Secret{updatedSecret},
		}

		pushResp, err := server.syncClient.Push(deviceB.AuthCtx, pushReq)
		require.NoError(t, err)
		assert.Len(t, pushResp.AcceptedSecretIds, 1)

		t.Log("Device B made 3 creates and 1 update while Device A was offline")
	})

	t.Run("Device A comes back online and pulls changes", func(t *testing.T) {
		// Device A pulls changes since its last sync.
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(deviceALastSync),
		}

		pullResp, err := server.syncClient.Pull(deviceA.AuthCtx, pullReq)
		require.NoError(t, err)

		// Should see:
		// - 3 new secrets created by Device B
		// - 1 updated secret (the initial one)
		// Total of 4 secrets in the response.
		assert.Len(t, pullResp.Secrets, 4, "should pull 3 new + 1 updated secret")

		// Verify version of the updated secret.
		var foundUpdated bool
		for _, secret := range pullResp.Secrets {
			if secret.Id == initialSecret.ID {
				foundUpdated = true
				assert.Equal(t, int64(2), secret.Version, "updated secret should have version 2")
				assert.Equal(t, "Updated by B", secret.Title)
			}
		}
		assert.True(t, foundUpdated, "should find the updated initial secret")

		t.Logf("Device A successfully pulled %d changes made while offline", len(pullResp.Secrets))
	})

	t.Run("Verify Device A now has all secrets", func(t *testing.T) {
		// Full pull to verify complete state.
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(deviceA.AuthCtx, pullReq)
		require.NoError(t, err)

		// Should have 4 total secrets: 1 original (updated) + 3 new.
		assert.Len(t, pullResp.Secrets, 4, "Device A should have all 4 secrets")

		t.Log("Device A fully synced and has all secrets")
	})
}

// TestOfflineSync_LargeOfflineBatch tests pushing a large batch of changes
// accumulated during an extended offline period.
func TestOfflineSync_LargeOfflineBatch(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create user.
	user := CreateTestUser(t, server.authClient, "offline-large@example.com", "password123")

	const batchSize = 50

	t.Run("Client creates large batch of secrets offline", func(t *testing.T) {
		offlineSecrets := make([]*pb.Secret, 0, batchSize)

		for i := 0; i < batchSize; i++ {
			// Create different types of secrets.
			var data interface{}
			var secretType pb.SecretType

			switch i % 4 {
			case 0:
				data = &pb.CredentialData{
					Username: fmt.Sprintf("user-%d", i),
					Password: randomString(16),
				}
				secretType = pb.SecretType_SECRET_TYPE_CREDENTIAL
			case 1:
				data = &pb.TextData{
					Content: fmt.Sprintf("Note content %d", i),
				}
				secretType = pb.SecretType_SECRET_TYPE_TEXT
			case 2:
				data = &pb.BinaryData{
					Filename: fmt.Sprintf("file-%d.bin", i),
					Data:     randomBytes(256),
				}
				secretType = pb.SecretType_SECRET_TYPE_BINARY
			case 3:
				data = &pb.BankCardData{
					CardholderName: fmt.Sprintf("User %d", i),
					CardNumber:     randomNumString(16),
				}
				secretType = pb.SecretType_SECRET_TYPE_BANK_CARD
			}

			secret := CreateTestSecretForSync(t, user, secretType, data)
			offlineSecrets = append(offlineSecrets, secret)
		}

		assert.Len(t, offlineSecrets, batchSize)
		t.Logf("Created %d secrets ready for batch sync", batchSize)

		// Batch push all secrets.
		pushReq := &pb.PushRequest{
			Secrets: offlineSecrets,
		}

		pushResp, err := server.syncClient.Push(user.AuthCtx, pushReq)
		require.NoError(t, err, "large batch push should succeed")

		assert.Len(t, pushResp.AcceptedSecretIds, batchSize, "all secrets should be accepted")
		assert.Empty(t, pushResp.Conflicts)

		t.Logf("Successfully pushed batch of %d secrets", len(pushResp.AcceptedSecretIds))
	})

	t.Run("Verify all secrets synced correctly", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(user.AuthCtx, pullReq)
		require.NoError(t, err)

		assert.Len(t, pullResp.Secrets, batchSize, "should have all secrets on server")

		// Verify distribution of secret types.
		typeCount := make(map[pb.SecretType]int)
		for _, secret := range pullResp.Secrets {
			typeCount[secret.Type]++
			assert.Equal(t, int64(1), secret.Version, "all should be version 1")
		}

		// We created 50 secrets with 4 types, so distribution should be roughly equal.
		expectedPerType := batchSize / 4
		for secretType, count := range typeCount {
			assert.GreaterOrEqual(t, count, expectedPerType, "type %s should have at least %d secrets", secretType, expectedPerType)
		}

		t.Logf("Verified %d secrets synced with correct distribution", len(pullResp.Secrets))
	})
}

// TestOfflineSync_DeletedSecretsWhileOffline tests syncing deletions
// performed while offline.
func TestOfflineSync_DeletedSecretsWhileOffline(t *testing.T) {
	ctx := context.Background()

	// Setup test database container.
	tc := testhelpers.NewTestContainer(ctx, t)

	// Setup gRPC test server.
	server := setupSyncTestServer(t, tc)

	// Create user with two devices.
	username := "offline-delete@example.com"
	password := "password123"
	device1 := CreateTestUserWithDevice(t, server.authClient, username, password, "device-1")
	device2 := LoginTestUserWithDevice(t, server.authClient, username, password, "device-2")

	// Create initial secrets.
	secrets := BatchCreateSecrets(t, server.secretsClient, device1, 5)
	require.Len(t, secrets, 5)

	// Both devices sync to get secrets.
	pullReq := &pb.PullRequest{
		LastSyncTime: timestamppb.New(time.Unix(0, 0)),
	}
	pullResp1, err := server.syncClient.Pull(device1.AuthCtx, pullReq)
	require.NoError(t, err)
	require.Len(t, pullResp1.Secrets, 5)

	pullResp2, err := server.syncClient.Pull(device2.AuthCtx, pullReq)
	require.NoError(t, err)
	require.Len(t, pullResp2.Secrets, 5)

	// Record sync time for device 2.
	time.Sleep(100 * time.Millisecond)
	device2LastSync := time.Now()
	time.Sleep(100 * time.Millisecond)

	t.Run("Device 1 deletes multiple secrets while Device 2 is offline", func(t *testing.T) {
		// Device 1 deletes 3 out of 5 secrets.
		deletedIDs := []string{
			pullResp1.Secrets[0].Id,
			pullResp1.Secrets[2].Id,
			pullResp1.Secrets[4].Id,
		}

		pushReq := &pb.PushRequest{
			DeletedSecretIds: deletedIDs,
		}

		pushResp, err := server.syncClient.Push(device1.AuthCtx, pushReq)
		require.NoError(t, err)
		assert.Len(t, pushResp.AcceptedSecretIds, 3, "all deletions should be accepted")

		t.Logf("Device 1 deleted %d secrets while Device 2 was offline", len(deletedIDs))
	})

	t.Run("Device 2 comes online and pulls deletion notifications", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(device2LastSync),
		}

		pullResp, err := server.syncClient.Pull(device2.AuthCtx, pullReq)
		require.NoError(t, err)

		// Should receive deletion notifications.
		assert.Empty(t, pullResp.Secrets, "should have no new/updated secrets")
		assert.Len(t, pullResp.DeletedSecretIds, 3, "should receive 3 deletion notifications")

		// Verify the deleted IDs match.
		deletedSet := make(map[string]bool)
		for _, id := range pullResp.DeletedSecretIds {
			deletedSet[id] = true
		}

		assert.True(t, deletedSet[pullResp1.Secrets[0].Id])
		assert.True(t, deletedSet[pullResp1.Secrets[2].Id])
		assert.True(t, deletedSet[pullResp1.Secrets[4].Id])

		t.Logf("Device 2 received %d deletion notifications", len(pullResp.DeletedSecretIds))
	})

	t.Run("Verify only non-deleted secrets remain", func(t *testing.T) {
		pullReq := &pb.PullRequest{
			LastSyncTime: timestamppb.New(time.Unix(0, 0)),
		}

		pullResp, err := server.syncClient.Pull(device1.AuthCtx, pullReq)
		require.NoError(t, err)

		// Should have 2 remaining secrets (5 - 3 deleted).
		assert.Len(t, pullResp.Secrets, 2, "should have 2 remaining secrets")

		// Verify the remaining secrets are the correct ones.
		remainingIDs := make(map[string]bool)
		for _, secret := range pullResp.Secrets {
			remainingIDs[secret.Id] = true
		}

		assert.True(t, remainingIDs[pullResp1.Secrets[1].Id])
		assert.True(t, remainingIDs[pullResp1.Secrets[3].Id])

		t.Log("Verified correct secrets remain after deletions synced")
	})
}

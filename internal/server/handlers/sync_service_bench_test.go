package handlers

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/koyif/keyper/internal/server/repository"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

// createEncryptedData creates base64-encoded encrypted data with nonce for benchmarks.
func createEncryptedData(data string) string {
	nonce := []byte("nonce1234567")
	ciphertext := []byte(data)
	encryptedData := append(nonce, ciphertext...)
	return base64.StdEncoding.EncodeToString(encryptedData)
}

// BenchmarkSyncService_Push_SingleSecret benchmarks pushing a single secret.
func BenchmarkSyncService_Push_SingleSecret(b *testing.B) {
	ts := setupSyncServiceTest(&testing.T{})
	defer ts.pool.Close()

	// Create test user
	user := createTestUser(context.Background(), &testing.T{}, ts.userRepo)
	ctx := setupTestContext(user.ID, "bench-device")

	// Create a test secret for the request
	secret := &pb.Secret{
		Id:            uuid.New().String(),
		Title:         "Benchmark Secret",
		Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
		EncryptedData: createEncryptedData("encrypted_data_benchmark"),
		Version:       0, // New secret
	}

	req := &pb.PushRequest{
		Secrets: []*pb.Secret{secret},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Use a new secret ID for each iteration
		secret.Id = uuid.New().String()
		_, err := ts.syncService.Push(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncService_Push_10Secrets benchmarks pushing 10 secrets.
func BenchmarkSyncService_Push_10Secrets(b *testing.B) {
	ts := setupSyncServiceTest(&testing.T{})
	defer ts.pool.Close()

	user := createTestUser(context.Background(), &testing.T{}, ts.userRepo)
	ctx := setupTestContext(user.ID, "bench-device")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		secrets := make([]*pb.Secret, 10)
		for j := 0; j < 10; j++ {
			secrets[j] = &pb.Secret{
				Id:            uuid.New().String(),
				Title:         fmt.Sprintf("Secret %d", j),
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				EncryptedData: createEncryptedData(fmt.Sprintf("encrypted_data_%d", j)),
				Version:       0,
			}
		}

		req := &pb.PushRequest{Secrets: secrets}
		_, err := ts.syncService.Push(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncService_Push_100Secrets benchmarks pushing 100 secrets.
func BenchmarkSyncService_Push_100Secrets(b *testing.B) {
	ts := setupSyncServiceTest(&testing.T{})
	defer ts.pool.Close()

	user := createTestUser(context.Background(), &testing.T{}, ts.userRepo)
	ctx := setupTestContext(user.ID, "bench-device")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		secrets := make([]*pb.Secret, 100)
		for j := 0; j < 100; j++ {
			secrets[j] = &pb.Secret{
				Id:            uuid.New().String(),
				Title:         fmt.Sprintf("Secret %d", j),
				Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
				EncryptedData: createEncryptedData(fmt.Sprintf("encrypted_data_%d", j)),
				Version:       0,
			}
		}

		req := &pb.PushRequest{Secrets: secrets}
		_, err := ts.syncService.Push(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncService_Push_Update benchmarks updating an existing secret.
func BenchmarkSyncService_Push_Update(b *testing.B) {
	ts := setupSyncServiceTest(&testing.T{})
	defer ts.pool.Close()

	user := createTestUser(context.Background(), &testing.T{}, ts.userRepo)
	ctx := setupTestContext(user.ID, "bench-device")

	// Create an initial secret
	secret := &repository.Secret{
		ID:            uuid.New(),
		UserID:        user.ID,
		Name:          "Initial Secret",
		Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
		EncryptedData: []byte("initial_data"),
		Nonce:         []byte("nonce123456789"),
		Metadata:      []byte(`{}`),
	}
	created, err := ts.secretRepo.Create(ctx, secret)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateReq := &pb.PushRequest{
			Secrets: []*pb.Secret{
				{
					Id:            created.ID.String(),
					Title:         fmt.Sprintf("Updated Secret %d", i),
					Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
					EncryptedData: createEncryptedData(fmt.Sprintf("updated_data_%d", i)),
					Version:       created.Version,
				},
			},
		}

		_, err := ts.syncService.Push(ctx, updateReq)
		if err != nil {
			b.Fatal(err)
		}

		// Refresh the version for next iteration
		created, err = ts.secretRepo.Get(ctx, created.ID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncService_Push_Delete benchmarks deleting secrets.
func BenchmarkSyncService_Push_Delete(b *testing.B) {
	ts := setupSyncServiceTest(&testing.T{})
	defer ts.pool.Close()

	user := createTestUser(context.Background(), &testing.T{}, ts.userRepo)
	ctx := setupTestContext(user.ID, "bench-device")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create a secret
		secret := &repository.Secret{
			ID:            uuid.New(),
			UserID:        user.ID,
			Name:          fmt.Sprintf("Secret %d", i),
			Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
			EncryptedData: []byte("data"),
			Nonce:         []byte("nonce123456789"),
			Metadata:      []byte(`{}`),
		}
		created, err := ts.secretRepo.Create(ctx, secret)
		if err != nil {
			b.Fatal(err)
		}

		// Delete it
		deleteReq := &pb.PushRequest{
			DeletedSecretIds: []string{created.ID.String()},
		}

		_, err = ts.syncService.Push(ctx, deleteReq)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncService_Pull_EmptyDatabase benchmarks pulling with no changes.
func BenchmarkSyncService_Pull_EmptyDatabase(b *testing.B) {
	ts := setupSyncServiceTest(&testing.T{})
	defer ts.pool.Close()

	user := createTestUser(context.Background(), &testing.T{}, ts.userRepo)
	ctx := setupTestContext(user.ID, "bench-device")

	req := &pb.PullRequest{
		LastSyncTime: timestamppb.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ts.syncService.Pull(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncService_Pull_100Secrets benchmarks pulling 100 secrets.
func BenchmarkSyncService_Pull_100Secrets(b *testing.B) {
	ts := setupSyncServiceTest(&testing.T{})
	defer ts.pool.Close()

	user := createTestUser(context.Background(), &testing.T{}, ts.userRepo)
	ctx := setupTestContext(user.ID, "bench-device")

	// Create 100 test secrets
	for i := 0; i < 100; i++ {
		secret := &repository.Secret{
			UserID:        user.ID,
			Name:          fmt.Sprintf("Secret %d", i),
			Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
			EncryptedData: []byte(fmt.Sprintf("encrypted_data_%d", i)),
			Nonce:         []byte("nonce123456789"),
			Metadata:      []byte(`{}`),
		}
		_, err := ts.secretRepo.Create(ctx, secret)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Pull from epoch
	req := &pb.PullRequest{
		LastSyncTime: nil, // Pull all
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ts.syncService.Pull(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncService_Pull_Incremental benchmarks incremental pull.
func BenchmarkSyncService_Pull_Incremental(b *testing.B) {
	ts := setupSyncServiceTest(&testing.T{})
	defer ts.pool.Close()

	user := createTestUser(context.Background(), &testing.T{}, ts.userRepo)
	ctx := setupTestContext(user.ID, "bench-device")

	// Create initial secrets
	for i := 0; i < 50; i++ {
		secret := &repository.Secret{
			UserID:        user.ID,
			Name:          fmt.Sprintf("Old Secret %d", i),
			Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
			EncryptedData: []byte(fmt.Sprintf("old_data_%d", i)),
			Nonce:         []byte("nonce123456789"),
			Metadata:      []byte(`{}`),
		}
		_, err := ts.secretRepo.Create(ctx, secret)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Get the last sync time
	lastSync := timestamppb.Now()

	// Create new secrets after sync point
	for i := 0; i < 10; i++ {
		secret := &repository.Secret{
			UserID:        user.ID,
			Name:          fmt.Sprintf("New Secret %d", i),
			Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
			EncryptedData: []byte(fmt.Sprintf("new_data_%d", i)),
			Nonce:         []byte("nonce123456789"),
			Metadata:      []byte(`{}`),
		}
		_, err := ts.secretRepo.Create(ctx, secret)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Pull incrementally
	req := &pb.PullRequest{
		LastSyncTime: lastSync,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ts.syncService.Pull(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSyncService_Push_MixedOperations benchmarks mixed create/update/delete.
func BenchmarkSyncService_Push_MixedOperations(b *testing.B) {
	ts := setupSyncServiceTest(&testing.T{})
	defer ts.pool.Close()

	user := createTestUser(context.Background(), &testing.T{}, ts.userRepo)
	ctx := setupTestContext(user.ID, "bench-device")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create initial secret
		secret := &repository.Secret{
			ID:            uuid.New(),
			UserID:        user.ID,
			Name:          "Initial",
			Type:          int32(pb.SecretType_SECRET_TYPE_CREDENTIAL),
			EncryptedData: []byte("data"),
			Nonce:         []byte("nonce123456789"),
			Metadata:      []byte(`{}`),
		}
		created, err := ts.secretRepo.Create(ctx, secret)
		if err != nil {
			b.Fatal(err)
		}

		// Push with mixed operations: create 3 new, update 1, delete 1
		req := &pb.PushRequest{
			Secrets: []*pb.Secret{
				{
					Id:            uuid.New().String(),
					Title:         "New 1",
					Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
					EncryptedData: createEncryptedData("new_data_1"),
					Version:       0,
				},
				{
					Id:            uuid.New().String(),
					Title:         "New 2",
					Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
					EncryptedData: createEncryptedData("new_data_2"),
					Version:       0,
				},
				{
					Id:            uuid.New().String(),
					Title:         "New 3",
					Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
					EncryptedData: createEncryptedData("new_data_3"),
					Version:       0,
				},
				{
					Id:            created.ID.String(),
					Title:         "Updated",
					Type:          pb.SecretType_SECRET_TYPE_CREDENTIAL,
					EncryptedData: createEncryptedData("updated_data"),
					Version:       created.Version,
				},
			},
			DeletedSecretIds: []string{created.ID.String()},
		}

		_, err = ts.syncService.Push(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

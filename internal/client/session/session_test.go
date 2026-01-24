package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	sess := New("/tmp/test-session.json")
	if sess == nil {
		t.Fatal("expected non-nil session")
	}

	if sess.filePath != "/tmp/test-session.json" {
		t.Errorf("expected filePath to be '/tmp/test-session.json', got '%s'", sess.filePath)
	}
}

func TestLoad_NewSession(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "session.json")

	sess, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if sess == nil {
		t.Fatal("expected non-nil session")
	}

	if sess.IsAuthenticated() {
		t.Error("expected new session to not be authenticated")
	}
}

func TestSaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "session.json")

	// Create and populate a session
	sess := New(tmpFile)
	sess.UserID = "user123"
	sess.AccessToken = "access-token-123"
	sess.RefreshToken = "refresh-token-456"
	sess.ExpiresAt = time.Now().Add(1 * time.Hour)
	sess.EncryptionKeyVerifier = "verifier-data"
	sess.SetEncryptionKey([]byte("test-encryption-key"))

	// Save the session
	if err := sess.Save(); err != nil {
		t.Fatalf("failed to save session: %v", err)
	}

	// Verify file was created with correct permissions
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("failed to stat session file: %v", err)
	}

	expectedMode := os.FileMode(0600)
	if info.Mode().Perm() != expectedMode {
		t.Errorf("expected file permissions to be %v, got %v", expectedMode, info.Mode().Perm())
	}

	// Load the session
	loadedSess, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("failed to load session: %v", err)
	}

	// Verify loaded data
	if loadedSess.UserID != "user123" {
		t.Errorf("expected UserID to be 'user123', got '%s'", loadedSess.UserID)
	}

	if loadedSess.AccessToken != "access-token-123" {
		t.Errorf("expected AccessToken to be 'access-token-123', got '%s'", loadedSess.AccessToken)
	}

	if loadedSess.RefreshToken != "refresh-token-456" {
		t.Errorf("expected RefreshToken to be 'refresh-token-456', got '%s'", loadedSess.RefreshToken)
	}

	if loadedSess.EncryptionKeyVerifier != "verifier-data" {
		t.Errorf("expected EncryptionKeyVerifier to be 'verifier-data', got '%s'", loadedSess.EncryptionKeyVerifier)
	}

	// Verify encryption key was NOT persisted
	if loadedSess.GetEncryptionKey() != nil {
		t.Error("expected encryption key to NOT be persisted to disk")
	}
}

func TestClear(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "session.json")

	// Create and save a session
	sess := New(tmpFile)
	sess.UserID = "user123"
	sess.AccessToken = "access-token"
	sess.RefreshToken = "refresh-token"
	sess.SetEncryptionKey([]byte("test-key"))

	if err := sess.Save(); err != nil {
		t.Fatalf("failed to save session: %v", err)
	}

	// Clear the session
	if err := sess.Clear(); err != nil {
		t.Fatalf("failed to clear session: %v", err)
	}

	// Verify all data is cleared
	if sess.UserID != "" {
		t.Error("expected UserID to be cleared")
	}

	if sess.AccessToken != "" {
		t.Error("expected AccessToken to be cleared")
	}

	if sess.RefreshToken != "" {
		t.Error("expected RefreshToken to be cleared")
	}

	if sess.GetEncryptionKey() != nil {
		t.Error("expected encryption key to be cleared")
	}

	// Verify file was removed
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Error("expected session file to be removed")
	}
}

func TestIsAuthenticated(t *testing.T) {
	sess := New("/tmp/test.json")

	// Not authenticated initially
	if sess.IsAuthenticated() {
		t.Error("expected new session to not be authenticated")
	}

	// Set tokens
	sess.AccessToken = "access"
	sess.RefreshToken = "refresh"

	// Now authenticated
	if !sess.IsAuthenticated() {
		t.Error("expected session with tokens to be authenticated")
	}

	// Clear one token
	sess.AccessToken = ""

	// Not authenticated anymore
	if sess.IsAuthenticated() {
		t.Error("expected session with missing access token to not be authenticated")
	}
}

func TestIsExpired(t *testing.T) {
	sess := New("/tmp/test.json")

	// Not expired initially (zero time is in the past but check handles it)
	sess.ExpiresAt = time.Now().Add(1 * time.Hour)
	if sess.IsExpired() {
		t.Error("expected session with future expiry to not be expired")
	}

	// Set to past time
	sess.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if !sess.IsExpired() {
		t.Error("expected session with past expiry to be expired")
	}
}

func TestUpdateTokens(t *testing.T) {
	sess := New("/tmp/test.json")

	expiresAt := time.Now().Add(1 * time.Hour)
	sess.UpdateTokens("new-access", "new-refresh", expiresAt)

	if sess.AccessToken != "new-access" {
		t.Errorf("expected AccessToken to be 'new-access', got '%s'", sess.AccessToken)
	}

	if sess.RefreshToken != "new-refresh" {
		t.Errorf("expected RefreshToken to be 'new-refresh', got '%s'", sess.RefreshToken)
	}

	if !sess.ExpiresAt.Equal(expiresAt) {
		t.Error("expected ExpiresAt to match")
	}
}

func TestEncryptionKey(t *testing.T) {
	sess := New("/tmp/test.json")

	// No key initially
	if sess.GetEncryptionKey() != nil {
		t.Error("expected no encryption key initially")
	}

	// Set a key
	originalKey := []byte("test-encryption-key-32-bytes!!")
	sess.SetEncryptionKey(originalKey)

	// Get the key
	retrievedKey := sess.GetEncryptionKey()
	if retrievedKey == nil {
		t.Fatal("expected to retrieve encryption key")
	}

	// Verify key matches
	if string(retrievedKey) != string(originalKey) {
		t.Error("expected retrieved key to match original")
	}

	// Verify it's a copy (not the same slice)
	retrievedKey[0] = 0xFF
	if sess.GetEncryptionKey()[0] == 0xFF {
		t.Error("expected GetEncryptionKey to return a copy, not the original slice")
	}
}

func TestUpdateLastSync(t *testing.T) {
	sess := New("/tmp/test.json")

	// No sync initially
	if !sess.LastSyncAt.IsZero() {
		t.Error("expected LastSyncAt to be zero initially")
	}

	// Update last sync
	before := time.Now()
	sess.UpdateLastSync()
	after := time.Now()

	if sess.LastSyncAt.Before(before) || sess.LastSyncAt.After(after) {
		t.Error("expected LastSyncAt to be between before and after times")
	}
}

func TestNeedsRefresh(t *testing.T) {
	sess := New("/tmp/test.json")

	tests := []struct {
		name            string
		expiresAt       time.Time
		expectedRefresh bool
	}{
		{
			name:            "expired token",
			expiresAt:       time.Now().Add(-1 * time.Hour),
			expectedRefresh: true,
		},
		{
			name:            "expiring in 2 minutes",
			expiresAt:       time.Now().Add(2 * time.Minute),
			expectedRefresh: true,
		},
		{
			name:            "expiring in 10 minutes",
			expiresAt:       time.Now().Add(10 * time.Minute),
			expectedRefresh: false,
		},
		{
			name:            "valid for 1 hour",
			expiresAt:       time.Now().Add(1 * time.Hour),
			expectedRefresh: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess.ExpiresAt = tt.expiresAt
			if got := sess.NeedsRefresh(); got != tt.expectedRefresh {
				t.Errorf("NeedsRefresh() = %v, want %v", got, tt.expectedRefresh)
			}
		})
	}
}

func TestRefreshAccessToken_NoRefreshToken(t *testing.T) {
	sess := New("/tmp/test.json")

	// Try to refresh without a refresh token
	err := sess.RefreshAccessToken("localhost:50051")
	if err == nil {
		t.Error("expected error when refreshing without refresh token")
	}

	if err.Error() != "no refresh token available" {
		t.Errorf("expected 'no refresh token available' error, got: %v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	sess := New("/tmp/test.json")

	// Test concurrent read/write operations don't panic
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			sess.UpdateTokens("access-"+string(rune(i)), "refresh-"+string(rune(i)), time.Now().Add(1*time.Hour))
		}
		done <- true
	}()

	// Reader goroutine 1
	go func() {
		for i := 0; i < 100; i++ {
			sess.IsAuthenticated()
			sess.IsExpired()
		}
		done <- true
	}()

	// Reader goroutine 2
	go func() {
		for i := 0; i < 100; i++ {
			sess.GetEncryptionKey()
		}
		done <- true
	}()

	// Writer goroutine 2
	go func() {
		for i := 0; i < 100; i++ {
			sess.SetEncryptionKey([]byte("key-" + string(rune(i))))
		}
		done <- true
	}()

	// Wait for all goroutines to complete
	for i := 0; i < 4; i++ {
		<-done
	}
}

func TestGetAccessToken(t *testing.T) {
	sess := New("/tmp/test.json")

	// No token initially
	if token := sess.GetAccessToken(); token != "" {
		t.Error("expected empty access token initially")
	}

	// Set a token
	sess.UpdateTokens("test-access-token", "test-refresh-token", time.Now().Add(1*time.Hour))

	// Get the token
	token := sess.GetAccessToken()
	if token != "test-access-token" {
		t.Errorf("expected 'test-access-token', got '%s'", token)
	}
}

func TestEnsureValidToken_NotAuthenticated(t *testing.T) {
	sess := New("/tmp/test.json")

	// Try to ensure valid token when not authenticated
	err := sess.EnsureValidToken("localhost:50051")
	if err == nil {
		t.Error("expected error when not authenticated")
	}

	if err.Error() != "not authenticated" {
		t.Errorf("expected 'not authenticated' error, got: %v", err)
	}
}

func TestEnsureValidToken_NoRefreshNeeded(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "session.json")
	sess := New(tmpFile)

	// Set up authenticated session with valid token
	sess.UserID = "user123"
	sess.UpdateTokens("access-token", "refresh-token", time.Now().Add(1*time.Hour))

	// Ensure valid token should succeed without making any server call
	err := sess.EnsureValidToken("localhost:50051")
	if err != nil {
		t.Errorf("expected no error when token is valid, got: %v", err)
	}
}

package auth

import (
	"testing"
	"time"
)

func TestTokenBlacklist_AddAndCheck(t *testing.T) {
	blacklist := NewTokenBlacklist(1 * time.Hour)
	defer blacklist.Stop()

	token := "test-token-123"
	expiresAt := time.Now().Add(1 * time.Hour)

	if blacklist.IsBlacklisted(token) {
		t.Error("Token should not be blacklisted initially")
	}

	blacklist.Add(token, expiresAt)

	if !blacklist.IsBlacklisted(token) {
		t.Error("Token should be blacklisted after adding")
	}
}

func TestTokenBlacklist_Remove(t *testing.T) {
	blacklist := NewTokenBlacklist(1 * time.Hour)
	defer blacklist.Stop()

	token := "test-token-456"
	expiresAt := time.Now().Add(1 * time.Hour)

	blacklist.Add(token, expiresAt)
	if !blacklist.IsBlacklisted(token) {
		t.Error("Token should be blacklisted")
	}

	blacklist.Remove(token)
	if blacklist.IsBlacklisted(token) {
		t.Error("Token should not be blacklisted after removal")
	}
}

func TestTokenBlacklist_ExpiredToken(t *testing.T) {
	blacklist := NewTokenBlacklist(1 * time.Hour)
	defer blacklist.Stop()

	token := "expired-token"
	expiresAt := time.Now().Add(-1 * time.Second) // Already expired

	blacklist.Add(token, expiresAt)

	// Even though it's in the blacklist, it should return false for expired tokens
	if blacklist.IsBlacklisted(token) {
		t.Error("Expired token should not be considered blacklisted")
	}
}

func TestTokenBlacklist_Size(t *testing.T) {
	blacklist := NewTokenBlacklist(1 * time.Hour)
	defer blacklist.Stop()

	if blacklist.Size() != 0 {
		t.Errorf("Expected size 0, got %d", blacklist.Size())
	}

	expiresAt := time.Now().Add(1 * time.Hour)

	blacklist.Add("token1", expiresAt)
	if blacklist.Size() != 1 {
		t.Errorf("Expected size 1, got %d", blacklist.Size())
	}

	blacklist.Add("token2", expiresAt)
	if blacklist.Size() != 2 {
		t.Errorf("Expected size 2, got %d", blacklist.Size())
	}

	blacklist.Remove("token1")
	if blacklist.Size() != 1 {
		t.Errorf("Expected size 1 after removal, got %d", blacklist.Size())
	}
}

func TestTokenBlacklist_Cleanup(t *testing.T) {
	blacklist := NewTokenBlacklist(100 * time.Millisecond)
	defer blacklist.Stop()

	// Add a token that expires in the past
	expiredToken := "expired-token"
	blacklist.Add(expiredToken, time.Now().Add(-1*time.Second))

	// Add a token that expires in the future
	validToken := "valid-token"
	blacklist.Add(validToken, time.Now().Add(10*time.Second))

	if blacklist.Size() != 2 {
		t.Errorf("Expected size 2, got %d", blacklist.Size())
	}

	// Wait for cleanup to run
	time.Sleep(150 * time.Millisecond)

	// After cleanup, only the valid token should remain
	size := blacklist.Size()
	if size != 1 {
		t.Errorf("Expected size 1 after cleanup, got %d", size)
	}

	if !blacklist.IsBlacklisted(validToken) {
		t.Error("Valid token should still be blacklisted")
	}
}

func TestTokenBlacklist_ConcurrentAccess(t *testing.T) {
	blacklist := NewTokenBlacklist(1 * time.Hour)
	defer blacklist.Stop()

	expiresAt := time.Now().Add(1 * time.Hour)

	// Run concurrent operations
	done := make(chan bool)
	for range 10 {
		go func() {
			token := time.Now().String()
			blacklist.Add(token, expiresAt)
			_ = blacklist.IsBlacklisted(token)
			_ = blacklist.Size()
			blacklist.Remove(token)
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for range 10 {
		<-done
	}
}

func TestTokenBlacklist_MultipleTokens(t *testing.T) {
	blacklist := NewTokenBlacklist(1 * time.Hour)
	defer blacklist.Stop()

	expiresAt := time.Now().Add(1 * time.Hour)
	tokens := []string{"token1", "token2", "token3", "token4", "token5"}

	for _, token := range tokens {
		blacklist.Add(token, expiresAt)
	}

	if blacklist.Size() != len(tokens) {
		t.Errorf("Expected size %d, got %d", len(tokens), blacklist.Size())
	}

	for _, token := range tokens {
		if !blacklist.IsBlacklisted(token) {
			t.Errorf("Token %s should be blacklisted", token)
		}
	}
}

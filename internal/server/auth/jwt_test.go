package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestJWTManager_GenerateAccessToken(t *testing.T) {
	manager := NewJWTManager("test-secret-key-that-is-long-enough")
	userID := uuid.New()
	deviceID := "device-123"

	token, expiresAt, err := manager.GenerateAccessToken(userID, deviceID)
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	if token == "" {
		t.Error("Generated token is empty")
	}

	if time.Until(expiresAt) > AccessTokenExpiry || time.Until(expiresAt) < AccessTokenExpiry-time.Second {
		t.Errorf("Token expiry time is incorrect: %v", expiresAt)
	}

	// Verify token structure (should be JWT format: header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("Token should have 3 parts, got %d", len(parts))
	}
}

func TestJWTManager_GenerateRefreshToken(t *testing.T) {
	manager := NewJWTManager("test-secret-key-that-is-long-enough")
	userID := uuid.New()
	deviceID := "device-123"

	token, expiresAt, err := manager.GenerateRefreshToken(userID, deviceID)
	if err != nil {
		t.Fatalf("Failed to generate refresh token: %v", err)
	}

	if token == "" {
		t.Error("Generated token is empty")
	}

	if time.Until(expiresAt) > RefreshTokenExpiry || time.Until(expiresAt) < RefreshTokenExpiry-time.Second {
		t.Errorf("Token expiry time is incorrect: %v", expiresAt)
	}
}

func TestJWTManager_GenerateTokenPair(t *testing.T) {
	manager := NewJWTManager("test-secret-key-that-is-long-enough")
	userID := uuid.New()
	deviceID := "device-123"

	accessToken, refreshToken, expiresAt, err := manager.GenerateTokenPair(userID, deviceID)
	if err != nil {
		t.Fatalf("Failed to generate token pair: %v", err)
	}

	if accessToken == "" {
		t.Error("Access token is empty")
	}

	if refreshToken == "" {
		t.Error("Refresh token is empty")
	}

	if accessToken == refreshToken {
		t.Error("Access token and refresh token should be different")
	}

	if time.Until(expiresAt) > AccessTokenExpiry {
		t.Errorf("Token expiry time is incorrect: %v", expiresAt)
	}
}

func TestJWTManager_ValidateToken(t *testing.T) {
	manager := NewJWTManager("test-secret-key-that-is-long-enough")
	userID := uuid.New()
	deviceID := "device-123"

	token, _, err := manager.GenerateAccessToken(userID, deviceID)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.UserID != userID.String() {
		t.Errorf("Expected user_id %s, got %s", userID.String(), claims.UserID)
	}

	if claims.DeviceID != deviceID {
		t.Errorf("Expected device_id %s, got %s", deviceID, claims.DeviceID)
	}

	if claims.Issuer != TokenIssuer {
		t.Errorf("Expected issuer %s, got %s", TokenIssuer, claims.Issuer)
	}
}

func TestJWTManager_ValidateToken_InvalidSignature(t *testing.T) {
	manager1 := NewJWTManager("secret-key-1")
	manager2 := NewJWTManager("secret-key-2")

	userID := uuid.New()
	deviceID := "device-123"

	token, _, err := manager1.GenerateAccessToken(userID, deviceID)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	_, err = manager2.ValidateToken(token)
	if err == nil {
		t.Error("Expected validation to fail with invalid signature")
	}

	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

func TestJWTManager_ValidateToken_MalformedToken(t *testing.T) {
	manager := NewJWTManager("test-secret-key")

	testCases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"invalid format", "invalid-token"},
		{"missing parts", "header.payload"},
		{"random string", "this.is.not.a.valid.jwt"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manager.ValidateToken(tc.token)
			if err == nil {
				t.Error("Expected validation to fail for malformed token")
			}
		})
	}
}

func TestJWTManager_ExtractUserID(t *testing.T) {
	manager := NewJWTManager("test-secret-key-that-is-long-enough")
	userID := uuid.New()
	deviceID := "device-123"

	token, _, err := manager.GenerateAccessToken(userID, deviceID)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	extractedUserID, err := manager.ExtractUserID(token)
	if err != nil {
		t.Fatalf("Failed to extract user ID: %v", err)
	}

	if extractedUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID.String(), extractedUserID.String())
	}
}

func TestHashRefreshToken(t *testing.T) {
	token1 := "refresh-token-1"
	token2 := "refresh-token-2"

	hash1 := HashRefreshToken(token1)
	hash2 := HashRefreshToken(token2)

	if hash1 == "" {
		t.Error("Hash should not be empty")
	}

	if hash1 == token1 {
		t.Error("Hash should be different from original token")
	}

	if hash1 == hash2 {
		t.Error("Different tokens should produce different hashes")
	}

	// Verify hash is deterministic
	hash1Again := HashRefreshToken(token1)
	if hash1 != hash1Again {
		t.Error("Hash should be deterministic")
	}

	// Verify hash is hex-encoded SHA-256 (64 characters)
	if len(hash1) != 64 {
		t.Errorf("SHA-256 hash should be 64 hex characters, got %d", len(hash1))
	}
}

func TestCustomClaims_Validation(t *testing.T) {
	manager := NewJWTManager("test-secret-key-that-is-long-enough")

	// Test with empty device ID
	userID := uuid.New()
	token, _, err := manager.GenerateAccessToken(userID, "")
	if err != nil {
		t.Fatalf("Failed to generate token with empty device ID: %v", err)
	}

	claims, err := manager.ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.DeviceID != "" {
		t.Errorf("Expected empty device_id, got %s", claims.DeviceID)
	}
}

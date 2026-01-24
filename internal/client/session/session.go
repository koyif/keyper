package session

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	pb "github.com/koy/keyper/pkg/api/proto"
	"google.golang.org/grpc"
)

// Session holds the current user session data
type Session struct {
	mu sync.RWMutex

	// User information
	UserID string `json:"user_id"`

	// JWT tokens
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`

	// Encryption key (never persisted to disk)
	encryptionKey []byte

	// Encryption key verifier for validating the key
	EncryptionKeyVerifier string `json:"encryption_key_verifier"`

	// Last sync timestamp
	LastSyncAt time.Time `json:"last_sync_at,omitempty"`

	// Session file path
	filePath string
}

// New creates a new empty session
func New(filePath string) *Session {
	return &Session{
		filePath: filePath,
	}
}

// Load loads the session from disk
func Load(filePath string) (*Session, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// No session file exists, return empty session
			return New(filePath), nil
		}
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}

	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("failed to parse session file: %w", err)
	}

	s.filePath = filePath
	return &s, nil
}

// Save saves the session to disk
// Note: encryption key is never saved to disk
func (s *Session) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Ensure directory exists
	dir := s.filePath
	// Find last separator
	for i := len(dir) - 1; i >= 0; i-- {
		if dir[i] == '/' || dir[i] == '\\' {
			dir = dir[:i]
			break
		}
	}
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create session directory: %w", err)
		}
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	// Write with restrictive permissions
	if err := os.WriteFile(s.filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

// Clear clears all session data and removes the session file
func (s *Session) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear in-memory data
	s.UserID = ""
	s.AccessToken = ""
	s.RefreshToken = ""
	s.ExpiresAt = time.Time{}
	s.encryptionKey = nil
	s.EncryptionKeyVerifier = ""
	s.LastSyncAt = time.Time{}

	// Remove session file
	if err := os.Remove(s.filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove session file: %w", err)
	}

	return nil
}

// SetEncryptionKey sets the encryption key (in memory only, never persisted)
func (s *Session) SetEncryptionKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.encryptionKey = make([]byte, len(key))
	copy(s.encryptionKey, key)
}

// GetEncryptionKey returns the encryption key
func (s *Session) GetEncryptionKey() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.encryptionKey == nil {
		return nil
	}
	// Return a copy to prevent modification
	key := make([]byte, len(s.encryptionKey))
	copy(key, s.encryptionKey)
	return key
}

// IsAuthenticated returns true if the session has valid tokens
func (s *Session) IsAuthenticated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AccessToken != "" && s.RefreshToken != ""
}

// IsExpired returns true if the access token has expired
func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Now().After(s.ExpiresAt)
}

// UpdateTokens updates the JWT tokens and expiry
func (s *Session) UpdateTokens(accessToken, refreshToken string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.AccessToken = accessToken
	s.RefreshToken = refreshToken
	s.ExpiresAt = expiresAt
}

// UpdateLastSync updates the last sync timestamp
func (s *Session) UpdateLastSync() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastSyncAt = time.Now()
}

// RefreshAccessToken refreshes the access token using the refresh token
// Returns true if refresh was successful, false otherwise
func (s *Session) RefreshAccessToken(serverAddr string, opts ...grpc.DialOption) error {
	s.mu.Lock()
	refreshToken := s.RefreshToken
	s.mu.Unlock()

	if refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	// Connect to server
	conn, err := grpc.NewClient(serverAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// Call RefreshToken RPC
	client := pb.NewAuthServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.RefreshToken(ctx, &pb.RefreshTokenRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		return fmt.Errorf("token refresh failed: %w", err)
	}

	// Update tokens
	s.mu.Lock()
	s.AccessToken = resp.AccessToken
	s.ExpiresAt = resp.ExpiresAt.AsTime()
	s.mu.Unlock()

	return nil
}

// NeedsRefresh returns true if the access token has expired or will expire soon
// Uses a 5-minute buffer to refresh before actual expiry
func (s *Session) NeedsRefresh() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Refresh if expired or expiring within 5 minutes
	return time.Now().Add(5 * time.Minute).After(s.ExpiresAt)
}

// EnsureValidToken ensures the access token is valid, refreshing if necessary
// This is a convenience method that checks if refresh is needed and performs it automatically
func (s *Session) EnsureValidToken(serverAddr string, opts ...grpc.DialOption) error {
	if !s.IsAuthenticated() {
		return fmt.Errorf("not authenticated")
	}

	if s.NeedsRefresh() {
		if err := s.RefreshAccessToken(serverAddr, opts...); err != nil {
			return fmt.Errorf("failed to refresh token: %w", err)
		}
		// Save the updated session after refresh
		if err := s.Save(); err != nil {
			return fmt.Errorf("failed to save refreshed session: %w", err)
		}
	}

	return nil
}

// GetAccessToken returns the current access token with thread safety
func (s *Session) GetAccessToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AccessToken
}

package session

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/koyif/keyper/internal/client/grpcutil"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

type Session struct {
	mu sync.RWMutex

	UserID string `json:"user_id"`

	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`

	// Encryption key (never persisted to disk)
	encryptionKey []byte

	EncryptionKeyVerifier string `json:"encryption_key_verifier"`

	LastSyncAt time.Time `json:"last_sync_at,omitempty"`

	filePath string
}

func New(filePath string) *Session {
	return &Session{
		filePath: filePath,
	}
}

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

// Note: encryption key is never saved to disk
func (s *Session) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dir := s.filePath
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

	if err := os.WriteFile(s.filePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	return nil
}

func (s *Session) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.UserID = ""
	s.AccessToken = ""
	s.RefreshToken = ""
	s.ExpiresAt = time.Time{}
	s.encryptionKey = nil
	s.EncryptionKeyVerifier = ""
	s.LastSyncAt = time.Time{}

	if err := os.Remove(s.filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove session file: %w", err)
	}

	return nil
}

// In memory only, never persisted
func (s *Session) SetEncryptionKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.encryptionKey = make([]byte, len(key))
	copy(s.encryptionKey, key)
}

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

func (s *Session) IsAuthenticated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.AccessToken != "" && s.RefreshToken != ""
}

func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return time.Now().After(s.ExpiresAt)
}

func (s *Session) UpdateTokens(accessToken, refreshToken string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.AccessToken = accessToken
	s.RefreshToken = refreshToken
	s.ExpiresAt = expiresAt
}

func (s *Session) UpdateLastSync() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastSyncAt = time.Now()
}

func (s *Session) RefreshAccessToken(serverAddr string) error {
	s.mu.Lock()
	refreshToken := s.RefreshToken
	s.mu.Unlock()

	if refreshToken == "" {
		return fmt.Errorf("no refresh token available")
	}

	conn, err := grpcutil.NewUnauthenticatedConnection(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	client := pb.NewAuthServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.RefreshToken(ctx, &pb.RefreshTokenRequest{
		RefreshToken: refreshToken,
	})
	if err != nil {
		return fmt.Errorf("token refresh failed: %w", err)
	}

	s.mu.Lock()
	s.AccessToken = resp.AccessToken
	s.ExpiresAt = resp.ExpiresAt.AsTime()
	s.mu.Unlock()

	return nil
}

// Uses a 5-minute buffer to refresh before actual expiry
func (s *Session) NeedsRefresh() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Refresh if expired or expiring within 5 minutes
	return time.Now().Add(5 * time.Minute).After(s.ExpiresAt)
}

func (s *Session) EnsureValidToken(serverAddr string) error {
	if !s.IsAuthenticated() {
		return fmt.Errorf("not authenticated")
	}

	if s.NeedsRefresh() {
		if err := s.RefreshAccessToken(serverAddr); err != nil {
			return fmt.Errorf("failed to refresh token: %w", err)
		}
		// Save the updated session after refresh
		if err := s.Save(); err != nil {
			return fmt.Errorf("failed to save refreshed session: %w", err)
		}
	}

	return nil
}

func (s *Session) GetAccessToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.AccessToken
}

// 30-second timeout prevents indefinite hangs on database calls.
// Usage:
//
//	ctx, cancel := session.DatabaseContext()
//	defer cancel()
//	err := repo.SomeMethod(ctx, ...)
func DatabaseContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

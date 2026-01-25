package auth

import (
	"sync"
	"time"
)

// TokenBlacklist provides an in-memory mechanism to revoke tokens before their expiration.
// This is useful for logout functionality and immediate token revocation.
type TokenBlacklist struct {
	mu         sync.RWMutex
	blacklist  map[string]time.Time // token -> expiration time
	cleanupInt time.Duration
	stopCh     chan struct{}
}

// NewTokenBlacklist creates a new in-memory token blacklist.
// cleanupInterval determines how often expired entries are removed from memory.
func NewTokenBlacklist(cleanupInterval time.Duration) *TokenBlacklist {
	tb := &TokenBlacklist{
		blacklist:  make(map[string]time.Time),
		cleanupInt: cleanupInterval,
		stopCh:     make(chan struct{}),
	}

	// Start background cleanup goroutine
	go tb.cleanupLoop()

	return tb
}

// Add adds a token to the blacklist with its expiration time.
func (tb *TokenBlacklist) Add(token string, expiresAt time.Time) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.blacklist[token] = expiresAt
}

// IsBlacklisted checks if a token is in the blacklist.
func (tb *TokenBlacklist) IsBlacklisted(token string) bool {
	tb.mu.RLock()
	defer tb.mu.RUnlock()

	expiresAt, exists := tb.blacklist[token]
	if !exists {
		return false
	}

	// If token has expired, it's no longer relevant
	if time.Now().After(expiresAt) {
		return false
	}

	return true
}

// Remove removes a token from the blacklist.
func (tb *TokenBlacklist) Remove(token string) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	delete(tb.blacklist, token)
}

// cleanupLoop periodically removes expired tokens from the blacklist.
func (tb *TokenBlacklist) cleanupLoop() {
	ticker := time.NewTicker(tb.cleanupInt)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tb.cleanup()
		case <-tb.stopCh:
			return
		}
	}
}

// cleanup removes expired tokens from the blacklist.
func (tb *TokenBlacklist) cleanup() {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	for token, expiresAt := range tb.blacklist {
		if now.After(expiresAt) {
			delete(tb.blacklist, token)
		}
	}
}

// Stop stops the cleanup goroutine.
func (tb *TokenBlacklist) Stop() {
	close(tb.stopCh)
}

// Size returns the current number of blacklisted tokens.
func (tb *TokenBlacklist) Size() int {
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	return len(tb.blacklist)
}

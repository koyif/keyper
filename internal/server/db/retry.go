package db

import (
	"context"
	"fmt"
	"time"
)

// RetryConfig configures retry behavior with exponential backoff.
type RetryConfig struct {
	MaxRetries  int           // Maximum number of retry attempts
	InitialWait time.Duration // Initial wait time between retries
	MaxWait     time.Duration // Maximum wait time between retries
	Multiplier  float64       // Backoff multiplier (e.g., 2.0 for exponential)
}

// DefaultRetryConfig returns sensible defaults for retry behavior.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:  5,
		InitialWait: 1 * time.Second,
		MaxWait:     30 * time.Second,
		Multiplier:  2.0,
	}
}

// Retry executes the given function with exponential backoff retry logic.
// It respects context cancellation and returns the last error if all retries fail.
func Retry(ctx context.Context, cfg RetryConfig, fn func() error) error {
	var lastErr error

	wait := cfg.InitialWait

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		// Check if context is cancelled before attempting
		if ctx.Err() != nil {
			return fmt.Errorf("context cancelled: %w", ctx.Err()) //nolint:wrapcheck // context error wrapped
		}

		// Try the operation
		lastErr = fn()
		if lastErr == nil {
			return nil // Success
		}

		// Don't wait after the last attempt
		if attempt == cfg.MaxRetries {
			break
		}

		// Wait with exponential backoff
		select {
		case <-time.After(wait):
			// Calculate next wait time
			wait = time.Duration(float64(wait) * cfg.Multiplier)
			if wait > cfg.MaxWait {
				wait = cfg.MaxWait
			}
		case <-ctx.Done():
			return fmt.Errorf("context cancelled during retry: %w", ctx.Err()) //nolint:wrapcheck // context error wrapped
		}
	}

	return fmt.Errorf("max retries (%d) exceeded: %w", cfg.MaxRetries, lastErr)
}

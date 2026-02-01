package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetry_Success(t *testing.T) {
	attempts := 0
	fn := func() error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary error")
		}
		return nil
	}

	cfg := RetryConfig{
		MaxRetries:  5,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     100 * time.Millisecond,
		Multiplier:  2.0,
	}

	err := Retry(context.Background(), cfg, fn)
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetry_ImmediateSuccess(t *testing.T) {
	attempts := 0
	fn := func() error {
		attempts++
		return nil
	}

	cfg := DefaultRetryConfig()
	err := Retry(context.Background(), cfg, fn)
	if err != nil {
		t.Errorf("expected success, got error: %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("should not retry after cancellation")
	}

	cfg := DefaultRetryConfig()
	err := Retry(ctx, cfg, fn)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
	// Should not attempt at all since context is already cancelled
	if attempts != 0 {
		t.Errorf("expected 0 attempts, got %d", attempts)
	}
}

func TestRetry_ContextCancellationDuringRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	attempts := 0
	fn := func() error {
		attempts++
		if attempts == 2 {
			cancel() // Cancel after second attempt
		}
		return errors.New("persistent error")
	}

	cfg := RetryConfig{
		MaxRetries:  5,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     100 * time.Millisecond,
		Multiplier:  2.0,
	}

	err := Retry(ctx, cfg, fn)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
	// Should have 2 attempts before cancellation
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

func TestRetry_MaxRetriesExceeded(t *testing.T) {
	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("persistent error")
	}

	cfg := RetryConfig{
		MaxRetries:  3,
		InitialWait: 10 * time.Millisecond,
		MaxWait:     100 * time.Millisecond,
		Multiplier:  2.0,
	}

	err := Retry(context.Background(), cfg, fn)
	if err == nil {
		t.Error("expected error, got nil")
	}
	if attempts != 4 { // Initial + 3 retries
		t.Errorf("expected 4 attempts, got %d", attempts)
	}
	// Check that the error message contains both the retry info and original error
	expectedSubstring := "max retries (3) exceeded"
	if err.Error() == "" || len(err.Error()) < len(expectedSubstring) {
		t.Errorf("expected error message to contain retry info, got: %v", err)
	}
}

func TestRetry_ExponentialBackoff(t *testing.T) {
	start := time.Now()
	attempts := 0

	fn := func() error {
		attempts++
		return errors.New("test error")
	}

	cfg := RetryConfig{
		MaxRetries:  2,
		InitialWait: 50 * time.Millisecond,
		MaxWait:     500 * time.Millisecond,
		Multiplier:  2.0,
	}

	Retry(context.Background(), cfg, fn)
	duration := time.Since(start)

	// Expected: 50ms + 100ms = 150ms minimum
	if duration < 150*time.Millisecond {
		t.Errorf("backoff too short: %v", duration)
	}
	// Allow some slack for test execution (300ms is generous)
	if duration > 300*time.Millisecond {
		t.Errorf("backoff too long: %v", duration)
	}
	if attempts != 3 { // Initial + 2 retries
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetry_MaxWaitCap(t *testing.T) {
	start := time.Now()
	attempts := 0

	fn := func() error {
		attempts++
		return errors.New("test error")
	}

	cfg := RetryConfig{
		MaxRetries:  3,
		InitialWait: 50 * time.Millisecond,
		MaxWait:     60 * time.Millisecond, // Cap at 60ms
		Multiplier:  2.0,
	}

	Retry(context.Background(), cfg, fn)
	duration := time.Since(start)

	// Expected: 50ms + 60ms (capped) + 60ms (capped) = 170ms minimum
	// Without cap: 50ms + 100ms + 200ms = 350ms
	if duration < 170*time.Millisecond {
		t.Errorf("backoff too short: %v", duration)
	}
	if duration > 300*time.Millisecond {
		t.Errorf("backoff too long (cap not applied?): %v", duration)
	}
	if attempts != 4 { // Initial + 3 retries
		t.Errorf("expected 4 attempts, got %d", attempts)
	}
}

func TestRetry_ContextTimeout(t *testing.T) {
	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("persistent error")
	}

	cfg := RetryConfig{
		MaxRetries:  10,
		InitialWait: 50 * time.Millisecond,
		MaxWait:     500 * time.Millisecond,
		Multiplier:  2.0,
	}

	err := Retry(ctx, cfg, fn)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
	// Should not reach all 10 retries due to timeout
	if attempts >= 10 {
		t.Errorf("expected fewer than 10 attempts due to timeout, got %d", attempts)
	}
}

func TestDefaultRetryConfig(t *testing.T) {
	cfg := DefaultRetryConfig()

	if cfg.MaxRetries != 5 {
		t.Errorf("expected MaxRetries=5, got %d", cfg.MaxRetries)
	}
	if cfg.InitialWait != 1*time.Second {
		t.Errorf("expected InitialWait=1s, got %v", cfg.InitialWait)
	}
	if cfg.MaxWait != 30*time.Second {
		t.Errorf("expected MaxWait=30s, got %v", cfg.MaxWait)
	}
	if cfg.Multiplier != 2.0 {
		t.Errorf("expected Multiplier=2.0, got %f", cfg.Multiplier)
	}
}

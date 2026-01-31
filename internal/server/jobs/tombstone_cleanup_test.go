package jobs

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockSecretRepository is a test double for SecretRepository.
type mockSecretRepository struct {
	hardDeleteTombstonesFunc func(ctx context.Context, olderThan time.Time, batchSize int) (int, error)
}

func (m *mockSecretRepository) HardDeleteTombstones(ctx context.Context, olderThan time.Time, batchSize int) (int, error) {
	if m.hardDeleteTombstonesFunc != nil {
		return m.hardDeleteTombstonesFunc(ctx, olderThan, batchSize)
	}
	return 0, nil
}

func TestNewTombstoneCleanup(t *testing.T) {
	repo := &mockSecretRepository{}
	cfg := Config{
		RetentionPeriod: 30 * 24 * time.Hour,
		Schedule:        24 * time.Hour,
		BatchSize:       1000,
		BatchDelay:      100 * time.Millisecond,
		CleanupTimeout:  10 * time.Minute,
	}

	tc := NewTombstoneCleanup(repo, cfg)

	if tc == nil {
		t.Fatal("NewTombstoneCleanup returned nil")
	}

	if tc.repo != repo {
		t.Error("Repository not set correctly")
	}

	if tc.retentionPeriod != cfg.RetentionPeriod {
		t.Errorf("RetentionPeriod = %v, want %v", tc.retentionPeriod, cfg.RetentionPeriod)
	}

	if tc.schedule != cfg.Schedule {
		t.Errorf("Schedule = %v, want %v", tc.schedule, cfg.Schedule)
	}

	if tc.batchSize != cfg.BatchSize {
		t.Errorf("BatchSize = %v, want %v", tc.batchSize, cfg.BatchSize)
	}

	if tc.stopCh == nil {
		t.Error("stopCh not initialized")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	expectedRetention := 30 * 24 * time.Hour
	expectedSchedule := 24 * time.Hour
	expectedBatchSize := 1000
	expectedBatchDelay := 100 * time.Millisecond
	expectedCleanupTimeout := 10 * time.Minute

	if cfg.RetentionPeriod != expectedRetention {
		t.Errorf("RetentionPeriod = %v, want %v", cfg.RetentionPeriod, expectedRetention)
	}

	if cfg.Schedule != expectedSchedule {
		t.Errorf("Schedule = %v, want %v", cfg.Schedule, expectedSchedule)
	}

	if cfg.BatchSize != expectedBatchSize {
		t.Errorf("BatchSize = %v, want %v", cfg.BatchSize, expectedBatchSize)
	}

	if cfg.BatchDelay != expectedBatchDelay {
		t.Errorf("BatchDelay = %v, want %v", cfg.BatchDelay, expectedBatchDelay)
	}

	if cfg.CleanupTimeout != expectedCleanupTimeout {
		t.Errorf("CleanupTimeout = %v, want %v", cfg.CleanupTimeout, expectedCleanupTimeout)
	}
}

func TestCleanup_Success(t *testing.T) {
	callCount := 0
	var capturedOlderThan time.Time
	var capturedBatchSize int

	repo := &mockSecretRepository{
		hardDeleteTombstonesFunc: func(ctx context.Context, olderThan time.Time, batchSize int) (int, error) {
			callCount++
			capturedOlderThan = olderThan
			capturedBatchSize = batchSize

			// Return 500 on first call (less than batch size, so cleanup stops)
			return 500, nil
		},
	}

	cfg := Config{
		RetentionPeriod: 30 * 24 * time.Hour,
		Schedule:        1 * time.Hour,
		BatchSize:       1000,
		BatchDelay:      100 * time.Millisecond,
		CleanupTimeout:  10 * time.Minute,
	}

	tc := NewTombstoneCleanup(repo, cfg)
	tc.cleanup()

	if callCount != 1 {
		t.Errorf("Expected 1 call to HardDeleteTombstones, got %d", callCount)
	}

	if capturedBatchSize != 1000 {
		t.Errorf("Expected batch size 1000, got %d", capturedBatchSize)
	}

	// Verify olderThan is approximately 30 days ago
	expectedCutoff := time.Now().Add(-30 * 24 * time.Hour)
	timeDiff := capturedOlderThan.Sub(expectedCutoff)
	if timeDiff > time.Second || timeDiff < -time.Second {
		t.Errorf("olderThan time not within expected range. Diff: %v", timeDiff)
	}
}

func TestCleanup_Error(t *testing.T) {
	expectedErr := errors.New("database error")
	callCount := 0

	repo := &mockSecretRepository{
		hardDeleteTombstonesFunc: func(ctx context.Context, olderThan time.Time, batchSize int) (int, error) {
			callCount++
			return 0, expectedErr
		},
	}

	cfg := Config{
		RetentionPeriod: 30 * 24 * time.Hour,
		Schedule:        1 * time.Hour,
		BatchSize:       1000,
		BatchDelay:      100 * time.Millisecond,
		CleanupTimeout:  10 * time.Minute,
	}

	tc := NewTombstoneCleanup(repo, cfg)
	tc.cleanup()

	if callCount != 1 {
		t.Errorf("Expected 1 call to HardDeleteTombstones on error, got %d", callCount)
	}
}

func TestCleanup_BatchProcessing(t *testing.T) {
	callCount := 0
	deletedCounts := []int{1000, 1000, 500} // Simulate 2.5 batches worth of data

	repo := &mockSecretRepository{
		hardDeleteTombstonesFunc: func(ctx context.Context, olderThan time.Time, batchSize int) (int, error) {
			if callCount >= len(deletedCounts) {
				return 0, nil
			}
			count := deletedCounts[callCount]
			callCount++
			return count, nil
		},
	}

	cfg := Config{
		RetentionPeriod: 30 * 24 * time.Hour,
		Schedule:        1 * time.Hour,
		BatchSize:       1000,
		BatchDelay:      10 * time.Millisecond, // Use shorter delay for test
		CleanupTimeout:  10 * time.Minute,
	}

	tc := NewTombstoneCleanup(repo, cfg)
	tc.cleanup()

	// Should have called 3 times (1000, 1000, 500)
	if callCount != 3 {
		t.Errorf("Expected 3 calls to HardDeleteTombstones, got %d", callCount)
	}
}

func TestStartStop(t *testing.T) {
	repo := &mockSecretRepository{
		hardDeleteTombstonesFunc: func(ctx context.Context, olderThan time.Time, batchSize int) (int, error) {
			return 0, nil
		},
	}

	cfg := Config{
		RetentionPeriod: 30 * 24 * time.Hour,
		Schedule:        100 * time.Millisecond, // Short schedule for testing
		BatchSize:       1000,
		BatchDelay:      10 * time.Millisecond,
		CleanupTimeout:  10 * time.Minute,
	}

	tc := NewTombstoneCleanup(repo, cfg)
	tc.Start()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Stop should not panic
	tc.Stop()

	// Give it time to shut down
	time.Sleep(50 * time.Millisecond)

	// Verify stopCh is closed
	select {
	case <-tc.stopCh:
		// Expected - channel is closed
	default:
		t.Error("stopCh should be closed after Stop()")
	}
}

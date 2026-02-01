package jobs

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// TombstoneCleanup manages periodic cleanup of soft-deleted secrets (tombstones).
// It removes secrets marked as deleted after a configurable retention period.
type TombstoneCleanup struct {
	repo            SecretRepository
	retentionPeriod time.Duration
	schedule        time.Duration
	batchSize       int
	batchDelay      time.Duration
	cleanupTimeout  time.Duration
	stopCh          chan struct{}
}

// SecretRepository defines the interface for secret cleanup operations.
type SecretRepository interface {
	HardDeleteTombstones(ctx context.Context, olderThan time.Time, batchSize int) (int, error)
}

// Config holds configuration for the tombstone cleanup job.
type Config struct {
	RetentionPeriod time.Duration // How long to keep tombstones before hard deletion
	Schedule        time.Duration // How often to run cleanup
	BatchSize       int           // Number of records to delete per batch
	BatchDelay      time.Duration // Delay between batches to reduce database load
	CleanupTimeout  time.Duration // Maximum time for entire cleanup operation
}

// DefaultConfig returns sensible default configuration.
// Runs daily with 30 days retention, 1000 records per batch.
func DefaultConfig() Config {
	return Config{
		RetentionPeriod: 30 * 24 * time.Hour, // 30 days
		Schedule:        24 * time.Hour,      // Daily
		BatchSize:       1000,                // 1000 records per batch
		BatchDelay:      100 * time.Millisecond,
		CleanupTimeout:  10 * time.Minute,
	}
}

// NewTombstoneCleanup creates a new tombstone cleanup job with the specified configuration.
func NewTombstoneCleanup(repo SecretRepository, cfg Config) *TombstoneCleanup {
	return &TombstoneCleanup{
		repo:            repo,
		retentionPeriod: cfg.RetentionPeriod,
		schedule:        cfg.Schedule,
		batchSize:       cfg.BatchSize,
		batchDelay:      cfg.BatchDelay,
		cleanupTimeout:  cfg.CleanupTimeout,
		stopCh:          make(chan struct{}),
	}
}

// Start begins the cleanup job background goroutine.
// It runs immediately on start, then continues on the configured schedule.
func (tc *TombstoneCleanup) Start() {
	zap.L().Info("Starting tombstone cleanup job",
		zap.Duration("retention", tc.retentionPeriod),
		zap.Duration("schedule", tc.schedule))

	go tc.cleanupLoop()
}

// Stop gracefully stops the cleanup job.
func (tc *TombstoneCleanup) Stop() {
	zap.L().Info("Stopping tombstone cleanup job")
	close(tc.stopCh)
}

// cleanupLoop runs the cleanup operation on a schedule.
func (tc *TombstoneCleanup) cleanupLoop() {
	// Run immediately on startup
	tc.cleanup()

	ticker := time.NewTicker(tc.schedule)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tc.cleanup()
		case <-tc.stopCh:
			zap.L().Info("Tombstone cleanup job stopped")
			return
		}
	}
}

// cleanup performs the actual tombstone deletion.
func (tc *TombstoneCleanup) cleanup() {
	zap.L().Info("Starting tombstone cleanup")

	ctx, cancel := context.WithTimeout(context.Background(), tc.cleanupTimeout)
	defer cancel()

	cutoffTime := time.Now().Add(-tc.retentionPeriod)
	totalDeleted := 0

	for {
		deleted, err := tc.repo.HardDeleteTombstones(ctx, cutoffTime, tc.batchSize)
		if err != nil {
			zap.L().Error("Error during tombstone cleanup", zap.Error(err))
			return
		}

		totalDeleted += deleted

		// If we deleted fewer records than batch size, we're done
		if deleted < tc.batchSize {
			break
		}

		// Add delay between batches to reduce database load
		select {
		case <-ctx.Done():
			zap.L().Warn("Tombstone cleanup cancelled due to timeout")
			return
		case <-time.After(tc.batchDelay):
			// Continue to next batch
		}
	}

	if totalDeleted > 0 {
		zap.L().Info("Tombstone cleanup complete",
			zap.Int("deleted_count", totalDeleted),
			zap.String("cutoff_time", cutoffTime.Format(time.RFC3339)))
	} else {
		zap.L().Info("Tombstone cleanup complete: no tombstones to delete")
	}
}

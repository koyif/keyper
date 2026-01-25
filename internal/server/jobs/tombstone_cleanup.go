package jobs

import (
	"context"
	"log"
	"time"
)

// TombstoneCleanup manages periodic cleanup of soft-deleted secrets (tombstones).
// It removes secrets marked as deleted after a configurable retention period.
type TombstoneCleanup struct {
	repo            SecretRepository
	retentionPeriod time.Duration
	schedule        time.Duration
	stopCh          chan struct{}
}

// SecretRepository defines the interface for secret cleanup operations.
type SecretRepository interface {
	HardDeleteTombstones(ctx context.Context, olderThan time.Time, batchSize int) (int, error)
}

// Config holds configuration for the tombstone cleanup job.
type Config struct {
	RetentionPeriod time.Duration
	Schedule        time.Duration
}

// DefaultConfig returns sensible default configuration.
// Runs daily at 2 AM (24 hours interval) with 30 days retention.
func DefaultConfig() Config {
	return Config{
		RetentionPeriod: 30 * 24 * time.Hour, // 30 days
		Schedule:        24 * time.Hour,      // Daily
	}
}

// NewTombstoneCleanup creates a new tombstone cleanup job with the specified configuration.
func NewTombstoneCleanup(repo SecretRepository, cfg Config) *TombstoneCleanup {
	return &TombstoneCleanup{
		repo:            repo,
		retentionPeriod: cfg.RetentionPeriod,
		schedule:        cfg.Schedule,
		stopCh:          make(chan struct{}),
	}
}

// Start begins the cleanup job background goroutine.
// It runs immediately on start, then continues on the configured schedule.
func (tc *TombstoneCleanup) Start() {
	log.Printf("Starting tombstone cleanup job (retention: %s, schedule: %s)",
		tc.retentionPeriod, tc.schedule)

	go tc.cleanupLoop()
}

// Stop gracefully stops the cleanup job.
func (tc *TombstoneCleanup) Stop() {
	log.Println("Stopping tombstone cleanup job...")
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
			log.Println("Tombstone cleanup job stopped")
			return
		}
	}
}

// cleanup performs the actual tombstone deletion.
func (tc *TombstoneCleanup) cleanup() {
	log.Println("Starting tombstone cleanup...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cutoffTime := time.Now().Add(-tc.retentionPeriod)
	batchSize := 1000 // Delete in batches to avoid long-running transactions

	totalDeleted := 0

	for {
		deleted, err := tc.repo.HardDeleteTombstones(ctx, cutoffTime, batchSize)
		if err != nil {
			log.Printf("Error during tombstone cleanup: %v", err)
			return
		}

		totalDeleted += deleted

		// If we deleted fewer records than batch size, we're done
		if deleted < batchSize {
			break
		}

		// Add a small delay between batches to reduce database load
		select {
		case <-ctx.Done():
			log.Println("Tombstone cleanup cancelled due to timeout")
			return
		case <-time.After(100 * time.Millisecond):
			// Continue to next batch
		}
	}

	if totalDeleted > 0 {
		log.Printf("Tombstone cleanup complete: deleted %d tombstones older than %s",
			totalDeleted, cutoffTime.Format(time.RFC3339))
	} else {
		log.Println("Tombstone cleanup complete: no tombstones to delete")
	}
}

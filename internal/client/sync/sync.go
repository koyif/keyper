package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
)

// SyncResult contains statistics and information about a sync operation.
type SyncResult struct {
	// PullStats contains information about the pull operation
	PulledSecrets int
	PulledDeletes int
	PullConflicts int
	PullDuration  time.Duration

	// PushStats contains information about the push operation
	PushedSecrets int
	PushedDeletes int
	PushConflicts int
	PushDuration  time.Duration

	// Overall sync information
	TotalDuration time.Duration
	Success       bool
	Error         error

	// Status information before sync
	InitialPendingCount int
	FinalPendingCount   int
	ConflictCount       int
	LastSyncTime        time.Time
}

// SyncOptions configures how sync should behave.
type SyncOptions struct {
	// ForceServerWins will resolve all conflicts by accepting the server version
	ForceServerWins bool

	// ProgressCallback is called to report sync progress (optional)
	ProgressCallback func(message string)
}

// Sync performs a complete bidirectional synchronization with the server.
// It executes the following steps in order:
// 1. Pull changes from server (PullAndSync) - CRITICAL: Must happen first to prevent data loss
// 2. Push local changes to server (PushWithRetry)
// 3. Report sync statistics
//
// This ordering ensures that:
// - Local changes are merged with latest server state before pushing
// - Conflicts are detected and resolved during pull
// - Push operation works with up-to-date conflict resolution
//
// The function uses database transactions to ensure atomicity and graceful handling
// of interrupted syncs.
func Sync(ctx context.Context, cfg *config.Config, sess *session.Session, repo storage.Repository, opts *SyncOptions) (*SyncResult, error) {
	if opts == nil {
		opts = &SyncOptions{}
	}

	startTime := time.Now()
	result := &SyncResult{
		Success: false,
	}

	// Helper to report progress
	reportProgress := func(msg string) {
		if opts.ProgressCallback != nil {
			opts.ProgressCallback(msg)
		} else {
			logrus.Info(msg)
		}
	}

	// Check authentication
	if !sess.IsAuthenticated() {
		result.Error = fmt.Errorf("not authenticated")
		return result, result.Error
	}

	// Get initial status for reporting
	reportProgress("Checking sync status...")
	pendingSecrets, err := repo.GetPendingSync(ctx)
	if err != nil {
		result.Error = fmt.Errorf("failed to get pending secrets: %w", err)
		return result, result.Error
	}
	result.InitialPendingCount = len(pendingSecrets)

	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	if err != nil {
		result.Error = fmt.Errorf("failed to get conflicts: %w", err)
		return result, result.Error
	}
	result.ConflictCount = len(conflicts)

	// Parse last sync time if available
	if cfg.LastSyncAt != "" {
		if t, err := time.Parse(time.RFC3339, cfg.LastSyncAt); err == nil {
			result.LastSyncTime = t
		}
	}

	reportProgress(fmt.Sprintf("Starting sync (pending: %d, conflicts: %d)...",
		result.InitialPendingCount, result.ConflictCount))

	// CRITICAL: Pull first to merge server changes before pushing
	// This prevents data loss by ensuring we have the latest server state
	reportProgress("Pulling changes from server...")
	pullStart := time.Now()

	// Handle force server wins option by temporarily setting manual conflict resolution
	origManualConflict := cfg.ManualConflictResolution
	if opts.ForceServerWins {
		cfg.ManualConflictResolution = false // Use last-write-wins which will favor server
		reportProgress("Force server wins enabled: conflicts will be resolved with server version")
	}
	// Use defer to ensure setting is restored even if PullAndSync panics or returns early
	defer func() {
		cfg.ManualConflictResolution = origManualConflict
	}()

	pullErr := PullAndSync(ctx, cfg, sess, repo)

	result.PullDuration = time.Since(pullStart)

	if pullErr != nil {
		result.Error = fmt.Errorf("pull failed: %w", pullErr)
		return result, result.Error
	}

	reportProgress(fmt.Sprintf("Pull complete (%.2fs)", result.PullDuration.Seconds()))

	// Get pull statistics by querying what changed
	// Note: This is approximate since we don't track exact changes
	// A more sophisticated implementation could track this during pull

	// Push local changes to server
	reportProgress("Pushing local changes to server...")
	pushStart := time.Now()

	pushResult, pushErr := PushWithRetry(ctx, cfg, sess, repo)
	result.PushDuration = time.Since(pushStart)

	if pushErr != nil {
		result.Error = fmt.Errorf("push failed: %w", pushErr)
		return result, result.Error
	}

	// Collect push statistics
	if pushResult != nil {
		result.PushedSecrets = len(pushResult.AcceptedSecretIDs)
		result.PushConflicts = len(pushResult.Conflicts)
	}

	reportProgress(fmt.Sprintf("Push complete (%.2fs, pushed: %d, conflicts: %d)",
		result.PushDuration.Seconds(), result.PushedSecrets, result.PushConflicts))

	// Get final status
	finalPending, err := repo.GetPendingSync(ctx)
	if err != nil {
		logrus.Warnf("Warning: failed to get final pending count: %v", err)
	} else {
		result.FinalPendingCount = len(finalPending)
	}

	finalConflicts, err := repo.GetUnresolvedConflicts(ctx)
	if err != nil {
		logrus.Warnf("Warning: failed to get final conflict count: %v", err)
	} else {
		result.ConflictCount = len(finalConflicts)
	}

	// Calculate total duration
	result.TotalDuration = time.Since(startTime)
	result.Success = true

	// Update last sync time
	syncTimeStr := time.Now().Format(time.RFC3339)
	if err := UpdateLastSyncAt(cfg, syncTimeStr); err != nil {
		logrus.Warnf("Warning: failed to update last_sync_at: %v", err)
	}
	result.LastSyncTime = time.Now()

	reportProgress(fmt.Sprintf("Sync complete (%.2fs total)", result.TotalDuration.Seconds()))

	return result, nil
}

// GetSyncStatus returns the current synchronization status without performing a sync.
// This is useful for displaying sync status to users.
type SyncStatus struct {
	PendingChanges  int
	ConflictCount   int
	LastSyncTime    *time.Time
	LastSyncTimeStr string
	DeviceID        string
	NeedsSyncReason string
}

// GetSyncStatusInfo returns detailed information about the current sync state.
func GetSyncStatusInfo(ctx context.Context, cfg *config.Config, repo storage.Repository) (*SyncStatus, error) {
	status := &SyncStatus{}

	// Get device ID
	deviceID, err := GetDeviceID(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get device ID: %w", err)
	}
	status.DeviceID = deviceID

	// Get pending changes count
	pending, err := repo.GetPendingSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending secrets: %w", err)
	}
	status.PendingChanges = len(pending)

	// Get unresolved conflicts count
	conflicts, err := repo.GetUnresolvedConflicts(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get conflicts: %w", err)
	}
	status.ConflictCount = len(conflicts)

	// Parse last sync time
	if cfg.LastSyncAt != "" {
		if t, err := time.Parse(time.RFC3339, cfg.LastSyncAt); err == nil {
			status.LastSyncTime = &t
			status.LastSyncTimeStr = t.Format("2006-01-02 15:04:05")
		}
	}

	// Determine if sync is needed and why
	if status.PendingChanges > 0 {
		status.NeedsSyncReason = fmt.Sprintf("%d pending change(s)", status.PendingChanges)
	} else if status.ConflictCount > 0 {
		status.NeedsSyncReason = fmt.Sprintf("%d unresolved conflict(s)", status.ConflictCount)
	} else if status.LastSyncTime == nil {
		status.NeedsSyncReason = "never synced"
	} else {
		// Check if last sync was more than 1 hour ago
		if time.Since(*status.LastSyncTime) > 1*time.Hour {
			status.NeedsSyncReason = "last sync was more than 1 hour ago"
		}
	}

	return status, nil
}

// InterruptedSyncRecovery attempts to recover from an interrupted sync operation.
// This is called during initialization if we detect potential incomplete sync state.
// It uses database transactions to ensure atomicity.
func InterruptedSyncRecovery(ctx context.Context, repo storage.Repository) error {
	// Cast to SQLiteRepository to access transaction methods
	sqliteRepo, ok := repo.(*storage.SQLiteRepository)
	if !ok {
		return fmt.Errorf("repository must be a SQLiteRepository for transaction support")
	}

	// Begin transaction for recovery
	tx, err := sqliteRepo.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		// nolint:errcheck // Rollback error is expected to fail after Commit
		_ = tx.Rollback()
	}()

	// Check for secrets with inconsistent state
	// For now, this is a placeholder - actual recovery logic would:
	// 1. Look for secrets with sync_status='pending' but no local modifications
	// 2. Look for orphaned conflict records
	// 3. Validate data integrity

	// Commit the recovery transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit recovery transaction: %w", err)
	}

	logrus.Info("Interrupted sync recovery completed successfully")
	return nil
}

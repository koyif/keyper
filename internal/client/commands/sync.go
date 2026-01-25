package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/client/sync"
	"github.com/spf13/cobra"
)

// NewSyncCommand creates the sync command
func NewSyncCommand(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	var (
		forceServerWins bool
		statusOnly      bool
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Synchronize secrets with the server",
		Long: `Synchronize local secrets with the server by:
  1. Pulling remote changes from the server (with conflict detection)
  2. Pushing local changes (pending status) to the server
  3. Reporting sync statistics and status

The sync operation pulls first, then pushes. This ordering prevents data loss
by ensuring local changes are merged with the latest server state before pushing.

Use --status to check sync status without performing a sync.
Use --force to resolve all conflicts by accepting the server version.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getCfg()
			sess := getSess()

			// Check authentication
			if !sess.IsAuthenticated() {
				return fmt.Errorf("not logged in. Please run 'keyper auth login' first")
			}

			// Open storage
			repo, err := getStorage()
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer repo.Close()

			ctx := context.Background()

			// Status-only mode
			if statusOnly {
				return printSyncStatus(ctx, cfg, repo)
			}

			// Perform full sync
			fmt.Println("Starting synchronization...")
			fmt.Println()

			opts := &sync.SyncOptions{
				ForceServerWins: forceServerWins,
				ProgressCallback: func(msg string) {
					fmt.Printf("  %s\n", msg)
				},
			}

			result, err := sync.Sync(ctx, cfg, sess, repo, opts)
			if err != nil {
				return fmt.Errorf("sync failed: %w", err)
			}

			// Print sync results
			fmt.Println()
			fmt.Println("Sync Results:")
			fmt.Println("─────────────────────────────────────")
			fmt.Printf("  Total Duration:    %.2fs\n", result.TotalDuration.Seconds())
			fmt.Printf("  Pull Duration:     %.2fs\n", result.PullDuration.Seconds())
			fmt.Printf("  Push Duration:     %.2fs\n", result.PushDuration.Seconds())
			fmt.Println()
			fmt.Printf("  Pushed Secrets:    %d\n", result.PushedSecrets)
			fmt.Printf("  Conflicts:         %d\n", result.ConflictCount)
			fmt.Println()
			fmt.Printf("  Initial Pending:   %d\n", result.InitialPendingCount)
			fmt.Printf("  Final Pending:     %d\n", result.FinalPendingCount)
			fmt.Println()

			if result.LastSyncTime.IsZero() {
				fmt.Printf("  Last Sync:         never\n")
			} else {
				fmt.Printf("  Last Sync:         %s\n", result.LastSyncTime.Format("2006-01-02 15:04:05"))
			}

			if result.Success {
				fmt.Println()
				fmt.Println("✓ Sync completed successfully")
			}

			return nil
		},
	}

	// Add flags
	cmd.Flags().BoolVar(&forceServerWins, "force", false, "Force sync by accepting server version for all conflicts")
	cmd.Flags().BoolVar(&statusOnly, "status", false, "Show sync status without performing sync")

	return cmd
}

// printSyncStatus displays the current sync status without performing a sync.
func printSyncStatus(ctx context.Context, cfg *config.Config, repo storage.Repository) error {
	status, err := sync.GetSyncStatusInfo(ctx, cfg, repo)
	if err != nil {
		return fmt.Errorf("failed to get sync status: %w", err)
	}

	fmt.Println("Sync Status:")
	fmt.Println("─────────────────────────────────────")
	fmt.Printf("  Device ID:         %s\n", status.DeviceID)
	fmt.Println()
	fmt.Printf("  Pending Changes:   %d\n", status.PendingChanges)
	fmt.Printf("  Conflicts:         %d\n", status.ConflictCount)
	fmt.Println()

	if status.LastSyncTime != nil {
		timeSince := time.Since(*status.LastSyncTime)
		fmt.Printf("  Last Sync:         %s\n", status.LastSyncTimeStr)
		fmt.Printf("  Time Since Sync:   %s\n", formatDuration(timeSince))
	} else {
		fmt.Printf("  Last Sync:         never\n")
	}

	fmt.Println()

	if status.NeedsSyncReason != "" {
		fmt.Printf("⚠ Sync needed: %s\n", status.NeedsSyncReason)
	} else {
		fmt.Println("✓ All changes synced")
	}

	return nil
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	} else if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	return fmt.Sprintf("%.1f days", d.Hours()/24)
}

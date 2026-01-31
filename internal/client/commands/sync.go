package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/session"
	"github.com/koyif/keyper/internal/client/storage"
	"github.com/koyif/keyper/internal/client/sync"
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
			if err := requireAuth(sess); err != nil {
				return err
			}

			return withStorage(getStorage, func(ctx context.Context, repo storage.Repository) error {
				// Status-only mode
				if statusOnly {
					return printSyncStatus(cmd, ctx, cfg, repo)
				}

				// Perform full sync
				fmt.Fprintln(cmd.OutOrStdout(), "Starting synchronization...")
				fmt.Fprintln(cmd.OutOrStdout())

				opts := &sync.SyncOptions{
					ForceServerWins: forceServerWins,
					ProgressCallback: func(msg string) {
						fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", msg)
					},
				}

				result, err := sync.Sync(ctx, cfg, sess, repo, opts)
				if err != nil {
					if errors.Is(err, context.DeadlineExceeded) {
						return fmt.Errorf("sync operation timed out after 30s")
					}

					return fmt.Errorf("sync failed: %w", err)
				}

				// Print sync results
				out := cmd.OutOrStdout()
				fmt.Fprintln(out)
				fmt.Fprintln(out, "Sync Results:")
				fmt.Fprintln(out, "─────────────────────────────────────")
				fmt.Fprintf(out, "  Total Duration:    %.2fs\n", result.TotalDuration.Seconds())
				fmt.Fprintf(out, "  Pull Duration:     %.2fs\n", result.PullDuration.Seconds())
				fmt.Fprintf(out, "  Push Duration:     %.2fs\n", result.PushDuration.Seconds())
				fmt.Fprintln(out)
				fmt.Fprintf(out, "  Pushed Secrets:    %d\n", result.PushedSecrets)
				fmt.Fprintf(out, "  Conflicts:         %d\n", result.ConflictCount)
				fmt.Fprintln(out)
				fmt.Fprintf(out, "  Initial Pending:   %d\n", result.InitialPendingCount)
				fmt.Fprintf(out, "  Final Pending:     %d\n", result.FinalPendingCount)
				fmt.Fprintln(out)

				if result.LastSyncTime.IsZero() {
					fmt.Fprintf(out, "  Last Sync:         never\n")
				} else {
					fmt.Fprintf(out, "  Last Sync:         %s\n", result.LastSyncTime.Format("2006-01-02 15:04:05"))
				}

				if result.Success {
					fmt.Fprintln(out)
					fmt.Fprintln(out, "✓ Sync completed successfully")
				}

				return nil
			})
		},
	}

	// Add flags
	cmd.Flags().BoolVar(&forceServerWins, "force", false, "Force sync by accepting server version for all conflicts")
	cmd.Flags().BoolVar(&statusOnly, "status", false, "Show sync status without performing sync")

	return cmd
}

// printSyncStatus displays the current sync status without performing a sync.
func printSyncStatus(cmd *cobra.Command, ctx context.Context, cfg *config.Config, repo storage.Repository) error {
	status, err := sync.GetSyncStatusInfo(ctx, cfg, repo)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("sync status check timed out after 30s")
		}

		return fmt.Errorf("failed to get sync status: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "Sync Status:")
	fmt.Fprintln(out, "─────────────────────────────────────")
	fmt.Fprintf(out, "  Device ID:         %s\n", status.DeviceID)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  Pending Changes:   %d\n", status.PendingChanges)
	fmt.Fprintf(out, "  Conflicts:         %d\n", status.ConflictCount)
	fmt.Fprintln(out)

	if status.LastSyncTime != nil {
		timeSince := time.Since(*status.LastSyncTime)
		fmt.Fprintf(out, "  Last Sync:         %s\n", status.LastSyncTimeStr)
		fmt.Fprintf(out, "  Time Since Sync:   %s\n", formatDuration(timeSince))
	} else {
		fmt.Fprintf(out, "  Last Sync:         never\n")
	}

	fmt.Fprintln(out)

	if status.NeedsSyncReason != "" {
		fmt.Fprintf(out, "⚠ Sync needed: %s\n", status.NeedsSyncReason)
	} else {
		fmt.Fprintln(out, "✓ All changes synced")
	}

	return nil
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	}

	if d < time.Hour {
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	}

	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}

	return fmt.Sprintf("%.1f days", d.Hours()/24)
}

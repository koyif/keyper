package commands

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/koy/keyper/internal/client/tui"
	"github.com/spf13/cobra"
)

// NewTUICommand creates the tui command
func NewTUICommand(getCfg func() *config.Config, getSess func() *session.Session, getStorage func() (storage.Repository, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Launch the Terminal User Interface",
		Long:  "Start the interactive Terminal User Interface for managing secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getCfg()
			sess := getSess()

			// Open storage
			repo, err := getStorage()
			if err != nil {
				return fmt.Errorf("failed to open storage: %w", err)
			}
			defer repo.Close()

			// Create TUI model
			ctx := context.Background()
			model := tui.NewModel(ctx, cfg, sess, repo)

			// Run TUI
			p := tea.NewProgram(
				model,
				tea.WithAltScreen(),
				tea.WithMouseCellMotion(),
			)

			if _, err := p.Run(); err != nil {
				return fmt.Errorf("TUI error: %w", err)
			}

			return nil
		},
	}
}

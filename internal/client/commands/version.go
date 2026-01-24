package commands

import (
	"fmt"

	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/output"
	"github.com/spf13/cobra"
)

// VersionInfo holds version information
type VersionInfo struct {
	Version   string `json:"version" yaml:"version"`
	Commit    string `json:"commit" yaml:"commit"`
	BuildDate string `json:"build_date" yaml:"build_date"`
}

// NewVersionCommand creates the version command
func NewVersionCommand(getCfg func() *config.Config, version, commit, buildDate string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Display version information",
		Long:  "Display the version, commit hash, and build date of the Keyper client",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := getCfg()

			versionInfo := VersionInfo{
				Version:   version,
				Commit:    commit,
				BuildDate: buildDate,
			}

			// Create formatter based on config
			formatter, err := output.NewFormatter(cfg.Format)
			if err != nil {
				// Fallback to text if format is invalid
				formatter = output.NewTextFormatter()
			}

			// Format version info
			if cfg.Format == "text" {
				// Custom text format for version
				fmt.Printf("Keyper CLI\n")
				fmt.Printf("Version:    %s\n", version)
				fmt.Printf("Commit:     %s\n", commit)
				fmt.Printf("Build Date: %s\n", buildDate)
				return nil
			}

			// Use formatter for JSON/YAML
			output, err := formatter.Format(versionInfo)
			if err != nil {
				return fmt.Errorf("failed to format version info: %w", err)
			}

			fmt.Print(output)
			return nil
		},
	}

	return cmd
}

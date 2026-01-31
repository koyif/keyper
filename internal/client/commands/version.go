package commands

import (
	"fmt"
	"runtime"

	"github.com/koyif/keyper/internal/client/config"
	"github.com/koyif/keyper/internal/client/output"
	"github.com/spf13/cobra"
)

// VersionInfo holds version information
type VersionInfo struct {
	Version   string `json:"version" yaml:"version"`
	Commit    string `json:"commit" yaml:"commit"`
	BuildDate string `json:"build_date" yaml:"build_date"`
	GoVersion string `json:"go_version" yaml:"go_version"`
	OS        string `json:"os" yaml:"os"`
	Arch      string `json:"arch" yaml:"arch"`
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
				GoVersion: runtime.Version(),
				OS:        runtime.GOOS,
				Arch:      runtime.GOARCH,
			}

			// Handle text format with custom layout
			if cfg.Format == "text" {
				fmt.Fprintf(cmd.OutOrStdout(), "Keyper CLI\n")
				fmt.Fprintf(cmd.OutOrStdout(), "Version:    %s\n", version)
				fmt.Fprintf(cmd.OutOrStdout(), "Commit:     %s\n", commit)
				fmt.Fprintf(cmd.OutOrStdout(), "Build Date: %s\n", buildDate)
				fmt.Fprintf(cmd.OutOrStdout(), "Go Version: %s\n", runtime.Version())
				fmt.Fprintf(cmd.OutOrStdout(), "OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
				return nil
			}

			// Handle JSON/YAML formats
			formatter, err := output.NewFormatter(cfg.Format)
			if err != nil {
				return fmt.Errorf("invalid output format: %w", err)
			}

			formattedOutput, err := formatter.Format(versionInfo)
			if err != nil {
				return fmt.Errorf("failed to format version info: %w", err)
			}

			fmt.Fprint(cmd.OutOrStdout(), formattedOutput)
			return nil
		},
	}

	return cmd
}

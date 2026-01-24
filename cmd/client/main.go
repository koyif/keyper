package main

import (
	"fmt"
	"os"

	"github.com/koy/keyper/internal/client/commands"
	"github.com/koy/keyper/internal/client/config"
	"github.com/koy/keyper/internal/client/session"
	"github.com/koy/keyper/internal/client/storage"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// Version information (injected via ldflags)
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"

	// Global configuration
	cfg *config.Config

	// Global session
	sess *session.Session

	// Global flags
	serverAddr string
	configPath string
	verbose    bool
	format     string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "keyper",
	Short: "Keyper - A secure password manager",
	Long: `Keyper is a secure, end-to-end encrypted password manager.
It stores your credentials, notes, and sensitive data securely
with client-side encryption.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Initialize configuration
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Load session
		sess, err = session.Load(cfg.SessionPath)
		if err != nil {
			return fmt.Errorf("failed to load session: %w", err)
		}

		// Override config with CLI flags if they were explicitly set
		if cmd.Flags().Changed("server") {
			cfg.Server = serverAddr
		}
		if cmd.Flags().Changed("verbose") {
			cfg.Verbose = verbose
		}
		if cmd.Flags().Changed("format") {
			cfg.Format = format
		}

		// Validate format
		if err := cfg.ValidateFormat(); err != nil {
			return err
		}

		// Configure logging
		if cfg.Verbose {
			logrus.SetLevel(logrus.DebugLevel)
		} else {
			logrus.SetLevel(logrus.InfoLevel)
		}

		// Set log formatter
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableTimestamp: true,
			DisableColors:    false,
		})

		// Ensure necessary directories exist
		if err := cfg.EnsureDirectories(); err != nil {
			return fmt.Errorf("failed to create directories: %w", err)
		}

		logrus.Debugf("Configuration loaded: server=%s, format=%s", cfg.Server, cfg.Format)

		return nil
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "", "Server address (default: localhost:50051)")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Config file path (default: $HOME/.keyper/config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVar(&format, "format", "text", "Output format (text, json, yaml)")

	// Mark flags that can be set via environment variables
	rootCmd.PersistentFlags().Lookup("server").Usage = "Server address [env: KEYPER_SERVER]"
	rootCmd.PersistentFlags().Lookup("format").Usage = "Output format [env: KEYPER_FORMAT]"

	// Add all subcommands
	addCommands()
}

// addCommands adds all subcommands to the root command
func addCommands() {
	// Use closures to provide lazy access to cfg and sess
	getCfg := func() *config.Config { return cfg }
	getSess := func() *session.Session { return sess }

	// Storage factory function
	getStorage := func() (storage.Repository, error) {
		return storage.NewSQLiteRepository(cfg.DBPath)
	}

	// Add auth commands
	rootCmd.AddCommand(commands.NewAuthCommands(getCfg, getSess))

	// Add credential commands
	rootCmd.AddCommand(commands.NewCredentialCommands(getCfg, getSess, getStorage))

	// Add text commands
	rootCmd.AddCommand(commands.NewTextCommands(getCfg, getSess, getStorage))

	// Add card commands
	rootCmd.AddCommand(commands.NewCardCommands(getCfg, getSess, getStorage))

	// Add binary commands
	rootCmd.AddCommand(commands.NewBinaryCommands(getCfg, getSess, getStorage))

	// Add version command
	rootCmd.AddCommand(commands.NewVersionCommand(getCfg, version, commit, buildDate))

	// Add sync command
	rootCmd.AddCommand(commands.NewSyncCommand(getCfg, getSess, getStorage))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

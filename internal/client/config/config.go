package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Config holds all configuration for the CLI client
type Config struct {
	// Server is the address of the Keyper server (e.g., "localhost:50051")
	Server string `mapstructure:"server"`

	// ConfigPath is the path to the configuration file
	ConfigPath string `mapstructure:"-"`

	// Verbose enables debug logging
	Verbose bool `mapstructure:"verbose"`

	// Format specifies the output format (text, json, yaml)
	Format string `mapstructure:"format"`

	// SessionPath is the path to the session file
	SessionPath string `mapstructure:"session_path"`

	// DBPath is the path to the local SQLite database
	DBPath string `mapstructure:"db_path"`

	// DeviceID is a unique identifier for this device (UUID v4)
	DeviceID string `mapstructure:"device_id"`

	// LastSyncAt is the timestamp of the last successful sync (RFC3339 format)
	LastSyncAt string `mapstructure:"last_sync_at"`

	// ManualConflictResolution when true, requires user to manually resolve conflicts
	// When false (default), uses last-write-wins strategy
	ManualConflictResolution bool `mapstructure:"manual_conflict_resolution"`
}

// DefaultConfig returns a Config with default values
func DefaultConfig() *Config {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	keyperDir := filepath.Join(homeDir, ".keyper")

	return &Config{
		Server:      "localhost:50051",
		Verbose:     false,
		Format:      "text",
		SessionPath: filepath.Join(keyperDir, "session.json"),
		DBPath:      filepath.Join(keyperDir, "keyper.db"),
	}
}

// Load loads configuration from file, environment variables, and CLI flags
// Priority (highest to lowest): CLI flags > Environment variables > Config file > Defaults
func Load(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	v := viper.New()

	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			v.SetConfigFile(configPath)
		}
		cfg.ConfigPath = configPath
	} else {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			keyperDir := filepath.Join(homeDir, ".keyper")
			v.AddConfigPath(keyperDir)
			v.SetConfigName("config")
			v.SetConfigType("yaml")
			cfg.ConfigPath = filepath.Join(keyperDir, "config.yaml")
		}
	}

	v.SetEnvPrefix("KEYPER")
	v.AutomaticEnv()

	v.BindEnv("server")
	v.BindEnv("verbose")
	v.BindEnv("format")
	v.BindEnv("session_path")
	v.BindEnv("db_path")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		logrus.Debug("No config file found, using defaults")
	} else {
		logrus.Debugf("Using config file: %s", v.ConfigFileUsed())
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg, nil
}

// EnsureDirectories ensures that all necessary directories exist
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		filepath.Dir(c.SessionPath),
		filepath.Dir(c.DBPath),
		filepath.Dir(c.ConfigPath),
	}

	for _, dir := range dirs {
		if dir == "" || dir == "." {
			continue
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// ValidateFormat validates the output format
func (c *Config) ValidateFormat() error {
	switch c.Format {
	case "text", "json", "yaml":
		return nil
	default:
		return fmt.Errorf("invalid format %q, must be one of: text, json, yaml", c.Format)
	}
}

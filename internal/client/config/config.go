package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Config struct {
	Server string `mapstructure:"server"`

	ConfigPath string `mapstructure:"-"`

	Verbose bool `mapstructure:"verbose"`

	Format string `mapstructure:"format"`

	SessionPath string `mapstructure:"session_path"`

	DBPath string `mapstructure:"db_path"`

	DeviceID string `mapstructure:"device_id"`

	LastSyncAt string `mapstructure:"last_sync_at"`

	// When true, requires user to manually resolve conflicts
	// When false (default), uses last-write-wins strategy
	ManualConflictResolution bool `mapstructure:"manual_conflict_resolution"`
}

func DefaultConfig() *Config {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		logrus.Warnf("Could not get home directory, using current dir: %v", err)

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
		if err != nil {
			logrus.Warnf("Could not get home directory, using current dir: %v", err)

			homeDir = "."
		}

		keyperDir := filepath.Join(homeDir, ".keyper")
		v.AddConfigPath(keyperDir)
		v.SetConfigName("config")
		v.SetConfigType("yaml")

		cfg.ConfigPath = filepath.Join(keyperDir, "config.yaml")
	}

	v.SetEnvPrefix("KEYPER")
	v.AutomaticEnv()

	v.BindEnv("server")
	v.BindEnv("verbose")
	v.BindEnv("format")
	v.BindEnv("session_path")
	v.BindEnv("db_path")

	if err := v.ReadInConfig(); err != nil {
		var cfgNotFoundErr viper.ConfigFileNotFoundError
		if !errors.As(err, &cfgNotFoundErr) {
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

func (c *Config) ValidateFormat() error {
	switch c.Format {
	case "text", "json", "yaml":
		return nil
	default:
		return fmt.Errorf("invalid format %q, must be one of: text, json, yaml", c.Format)
	}
}

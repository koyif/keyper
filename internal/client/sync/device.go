package sync

import (
	"fmt"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/spf13/viper"

	"github.com/koyif/keyper/internal/client/config"
)

// deviceIDMutex protects device ID loading/creation to prevent race conditions.
var deviceIDMutex sync.Mutex

// LoadOrCreateDeviceID loads the device ID from config or generates a new one if it doesn't exist.
// The device ID is a UUID v4 that uniquely identifies this device for sync operations.
// It is persisted in the config file and reused across application restarts.
// This function is thread-safe for concurrent access.
func LoadOrCreateDeviceID(cfg *config.Config) (string, error) {
	// Lock to prevent concurrent device ID generation
	deviceIDMutex.Lock()
	defer deviceIDMutex.Unlock()

	// If device ID already exists in config, return it
	if cfg.DeviceID != "" {
		return cfg.DeviceID, nil
	}

	// Check if device ID exists in the config file
	v := viper.New()
	v.SetConfigType("yaml")
	if _, err := os.Stat(cfg.ConfigPath); err == nil {
		v.SetConfigFile(cfg.ConfigPath)
		if err := v.ReadInConfig(); err == nil {
			if existingID := v.GetString("device_id"); existingID != "" {
				cfg.DeviceID = existingID
				return existingID, nil
			}
		}
	}

	// Generate a new UUID v4
	deviceID := uuid.New().String()

	// Save it to the config file
	if err := saveDeviceID(cfg, deviceID); err != nil {
		return "", fmt.Errorf("failed to save device ID: %w", err)
	}

	// Update the in-memory config
	cfg.DeviceID = deviceID

	return deviceID, nil
}

// saveDeviceID persists the device ID to the config file.
func saveDeviceID(cfg *config.Config, deviceID string) error {
	// Ensure config directory exists
	if err := cfg.EnsureDirectories(); err != nil {
		return err
	}

	// Load or create viper instance for the config file
	v := viper.New()
	v.SetConfigType("yaml")

	// Check if config file exists
	if _, err := os.Stat(cfg.ConfigPath); err == nil {
		// Read existing config
		v.SetConfigFile(cfg.ConfigPath)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Set the device ID
	v.Set("device_id", deviceID)

	// Write the config file
	if err := v.WriteConfigAs(cfg.ConfigPath); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Ensure config file has secure permissions (0600 - read/write for owner only)
	if err := os.Chmod(cfg.ConfigPath, 0o600); err != nil {
		return fmt.Errorf("failed to set config file permissions: %w", err)
	}

	return nil
}

// UpdateLastSyncAt updates the last sync timestamp in the config file.
func UpdateLastSyncAt(cfg *config.Config, timestamp string) error {
	// Ensure config directory exists
	if err := cfg.EnsureDirectories(); err != nil {
		return err
	}

	// Load or create viper instance for the config file
	v := viper.New()
	v.SetConfigFile(cfg.ConfigPath)
	v.SetConfigType("yaml")

	// Try to read existing config
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Set the last sync timestamp
	v.Set("last_sync_at", timestamp)

	// Write the config file
	if err := v.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	// Update the in-memory config
	cfg.LastSyncAt = timestamp

	// Ensure config file has secure permissions (0600 - read/write for owner only)
	if err := os.Chmod(cfg.ConfigPath, 0o600); err != nil {
		return fmt.Errorf("failed to set config file permissions: %w", err)
	}

	return nil
}

// GetDeviceID returns the current device ID, generating one if necessary.
func GetDeviceID(cfg *config.Config) (string, error) {
	return LoadOrCreateDeviceID(cfg)
}

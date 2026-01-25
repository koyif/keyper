package sync

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/koy/keyper/internal/client/config"
)

func TestLoadOrCreateDeviceID_GeneratesValidUUID(t *testing.T) {
	// Create a temporary config
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigPath: filepath.Join(tmpDir, "config.yaml"),
	}

	// Generate device ID
	deviceID, err := LoadOrCreateDeviceID(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreateDeviceID failed: %v", err)
	}

	// Verify it's a valid UUID
	_, err = uuid.Parse(deviceID)
	if err != nil {
		t.Errorf("Generated device ID is not a valid UUID: %v", err)
	}

	// Verify it was saved to config
	if cfg.DeviceID != deviceID {
		t.Errorf("Device ID not saved to config: got %q, want %q", cfg.DeviceID, deviceID)
	}
}

func TestLoadOrCreateDeviceID_CreatesNewIDOnFirstRun(t *testing.T) {
	// Create a temporary config
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigPath: filepath.Join(tmpDir, "config.yaml"),
		DeviceID:   "", // No existing device ID
	}

	// First run should generate a new ID
	deviceID1, err := LoadOrCreateDeviceID(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreateDeviceID failed: %v", err)
	}

	if deviceID1 == "" {
		t.Error("Generated device ID is empty")
	}

	// Verify config file was created
	if _, err := os.Stat(cfg.ConfigPath); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Verify file has secure permissions (0600)
	info, err := os.Stat(cfg.ConfigPath)
	if err != nil {
		t.Fatalf("Failed to stat config file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("Config file has incorrect permissions: got %o, want 0600", info.Mode().Perm())
	}
}

func TestLoadOrCreateDeviceID_ReusesExistingID(t *testing.T) {
	// Create a temporary config with existing device ID
	tmpDir := t.TempDir()
	existingID := uuid.New().String()
	cfg := &config.Config{
		ConfigPath: filepath.Join(tmpDir, "config.yaml"),
		DeviceID:   existingID,
	}

	// Should return existing ID without writing to file
	deviceID, err := LoadOrCreateDeviceID(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreateDeviceID failed: %v", err)
	}

	if deviceID != existingID {
		t.Errorf("Device ID mismatch: got %q, want %q", deviceID, existingID)
	}
}

func TestLoadOrCreateDeviceID_PersistsAcrossLoads(t *testing.T) {
	// Create a temporary config
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	// First load: generate device ID
	cfg1 := &config.Config{
		ConfigPath: cfgPath,
	}
	deviceID1, err := LoadOrCreateDeviceID(cfg1)
	if err != nil {
		t.Fatalf("First LoadOrCreateDeviceID failed: %v", err)
	}

	// Second load: should read same device ID from file
	cfg2, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	deviceID2, err := LoadOrCreateDeviceID(cfg2)
	if err != nil {
		t.Fatalf("Second LoadOrCreateDeviceID failed: %v", err)
	}

	if deviceID1 != deviceID2 {
		t.Errorf("Device ID not persisted: first=%q, second=%q", deviceID1, deviceID2)
	}
}

func TestLoadOrCreateDeviceID_ConcurrentAccess(t *testing.T) {
	// Create a temporary config
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigPath: filepath.Join(tmpDir, "config.yaml"),
	}

	// Run multiple goroutines concurrently
	const numGoroutines = 10
	var wg sync.WaitGroup
	deviceIDs := make([]string, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := range numGoroutines {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			id, err := LoadOrCreateDeviceID(cfg)
			deviceIDs[index] = id
			errors[index] = err
		}(i)
	}

	wg.Wait()

	// Check for errors
	for i, err := range errors {
		if err != nil {
			t.Errorf("Goroutine %d failed: %v", i, err)
		}
	}

	// All device IDs should be the same (either from first write or existing)
	firstID := deviceIDs[0]
	for i, id := range deviceIDs {
		if id != firstID {
			t.Errorf("Goroutine %d got different device ID: got %q, want %q", i, id, firstID)
		}
	}
}

func TestUpdateLastSyncAt(t *testing.T) {
	// Create a temporary config with device ID
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigPath: filepath.Join(tmpDir, "config.yaml"),
	}

	// Generate device ID first
	_, err := LoadOrCreateDeviceID(cfg)
	if err != nil {
		t.Fatalf("LoadOrCreateDeviceID failed: %v", err)
	}

	// Update last sync timestamp
	timestamp := time.Now().UTC().Format(time.RFC3339)
	err = UpdateLastSyncAt(cfg, timestamp)
	if err != nil {
		t.Fatalf("UpdateLastSyncAt failed: %v", err)
	}

	// Verify it was saved to config
	if cfg.LastSyncAt != timestamp {
		t.Errorf("LastSyncAt not saved to config: got %q, want %q", cfg.LastSyncAt, timestamp)
	}

	// Load config again and verify persistence
	cfg2, err := config.Load(cfg.ConfigPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg2.LastSyncAt != timestamp {
		t.Errorf("LastSyncAt not persisted: got %q, want %q", cfg2.LastSyncAt, timestamp)
	}
}

func TestUpdateLastSyncAt_WithoutConfigFile(t *testing.T) {
	// Create a temporary config without creating the file first
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigPath: filepath.Join(tmpDir, "nonexistent", "config.yaml"),
	}

	// Should fail because config file doesn't exist
	timestamp := time.Now().UTC().Format(time.RFC3339)
	err := UpdateLastSyncAt(cfg, timestamp)
	if err == nil {
		t.Error("Expected error when updating LastSyncAt without existing config file")
	}
	if !strings.Contains(err.Error(), "failed to read config file") {
		t.Errorf("Expected 'failed to read config file' error, got: %v", err)
	}
}

func TestGetDeviceID(t *testing.T) {
	// Create a temporary config
	tmpDir := t.TempDir()
	cfg := &config.Config{
		ConfigPath: filepath.Join(tmpDir, "config.yaml"),
	}

	// GetDeviceID should work the same as LoadOrCreateDeviceID
	deviceID, err := GetDeviceID(cfg)
	if err != nil {
		t.Fatalf("GetDeviceID failed: %v", err)
	}

	// Verify it's a valid UUID
	_, err = uuid.Parse(deviceID)
	if err != nil {
		t.Errorf("Device ID is not a valid UUID: %v", err)
	}

	// Call again, should return the same ID
	deviceID2, err := GetDeviceID(cfg)
	if err != nil {
		t.Fatalf("Second GetDeviceID failed: %v", err)
	}

	if deviceID != deviceID2 {
		t.Errorf("GetDeviceID returned different IDs: first=%q, second=%q", deviceID, deviceID2)
	}
}

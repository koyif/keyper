package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server != "localhost:50051" {
		t.Errorf("expected default server to be 'localhost:50051', got '%s'", cfg.Server)
	}

	if cfg.Verbose != false {
		t.Error("expected default verbose to be false")
	}

	if cfg.Format != "text" {
		t.Errorf("expected default format to be 'text', got '%s'", cfg.Format)
	}

	if cfg.SessionPath == "" {
		t.Error("expected SessionPath to be set")
	}

	if cfg.DBPath == "" {
		t.Error("expected DBPath to be set")
	}
}

func TestLoad_NoConfigFile(t *testing.T) {
	// Load with a non-existent config file path
	cfg, err := Load("/tmp/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("expected no error when config file doesn't exist, got: %v", err)
	}

	// Should use defaults
	if cfg.Server != "localhost:50051" {
		t.Errorf("expected default server, got '%s'", cfg.Server)
	}
}

func TestLoad_WithConfigFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	configContent := `
server: "test-server:9999"
verbose: true
format: "json"
`

	if err := os.WriteFile(configFile, []byte(configContent), 0600); err != nil {
		t.Fatalf("failed to create test config file: %v", err)
	}

	// Load the config
	cfg, err := Load(configFile)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify values from config file
	if cfg.Server != "test-server:9999" {
		t.Errorf("expected server to be 'test-server:9999', got '%s'", cfg.Server)
	}

	if cfg.Verbose != true {
		t.Error("expected verbose to be true")
	}

	if cfg.Format != "json" {
		t.Errorf("expected format to be 'json', got '%s'", cfg.Format)
	}
}

func TestLoad_WithEnvironmentVariables(t *testing.T) {
	// Set environment variables
	os.Setenv("KEYPER_SERVER", "env-server:8888")
	os.Setenv("KEYPER_FORMAT", "yaml")
	defer func() {
		os.Unsetenv("KEYPER_SERVER")
		os.Unsetenv("KEYPER_FORMAT")
	}()

	// Load with non-existent config file (so env vars take precedence)
	cfg, err := Load("/tmp/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify values from environment variables
	if cfg.Server != "env-server:8888" {
		t.Errorf("expected server to be 'env-server:8888', got '%s'", cfg.Server)
	}

	if cfg.Format != "yaml" {
		t.Errorf("expected format to be 'yaml', got '%s'", cfg.Format)
	}
}

func TestValidateFormat(t *testing.T) {
	tests := []struct {
		name        string
		format      string
		expectError bool
	}{
		{"valid text", "text", false},
		{"valid json", "json", false},
		{"valid yaml", "yaml", false},
		{"invalid format", "xml", true},
		{"invalid format", "invalid", true},
		{"empty format", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Format: tt.format}
			err := cfg.ValidateFormat()

			if tt.expectError && err == nil {
				t.Error("expected error but got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestEnsureDirectories(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &Config{
		SessionPath: filepath.Join(tmpDir, "subdir", "session.json"),
		DBPath:      filepath.Join(tmpDir, "subdir", "db.sqlite"),
		ConfigPath:  filepath.Join(tmpDir, "config.yaml"),
	}

	if err := cfg.EnsureDirectories(); err != nil {
		t.Fatalf("failed to ensure directories: %v", err)
	}

	// Check that directories were created
	subdirPath := filepath.Join(tmpDir, "subdir")
	if _, err := os.Stat(subdirPath); os.IsNotExist(err) {
		t.Errorf("expected directory %s to be created", subdirPath)
	}

	// Verify directory permissions
	info, err := os.Stat(subdirPath)
	if err != nil {
		t.Fatalf("failed to stat directory: %v", err)
	}

	expectedMode := os.FileMode(0700)
	if info.Mode().Perm() != expectedMode {
		t.Errorf("expected directory permissions to be %v, got %v", expectedMode, info.Mode().Perm())
	}
}

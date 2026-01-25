package logger

import (
	"context"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestInitialize(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		wantErr bool
	}{
		{
			name:    "production environment",
			env:     "production",
			wantErr: false,
		},
		{
			name:    "development environment",
			env:     "development",
			wantErr: false,
		},
		{
			name:    "unknown environment defaults to development",
			env:     "unknown",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Initialize(tt.env)
			if (err != nil) != tt.wantErr {
				t.Errorf("Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify logger is initialized
			logger := Get()
			if logger == nil {
				t.Error("Get() returned nil logger after Initialize()")
			}
		})
	}
}

func TestWithContext(t *testing.T) {
	// Initialize logger for testing
	if err := Initialize("development"); err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	tests := []struct {
		name            string
		ctx             context.Context
		expectRequestID bool
		expectUserID    bool
	}{
		{
			name:            "context with request ID",
			ctx:             context.WithValue(context.Background(), RequestIDKey, "req-123"),
			expectRequestID: true,
			expectUserID:    false,
		},
		{
			name:            "context with user ID",
			ctx:             context.WithValue(context.Background(), UserIDKey, "user-456"),
			expectRequestID: false,
			expectUserID:    true,
		},
		{
			name: "context with both IDs",
			ctx: context.WithValue(
				context.WithValue(context.Background(), RequestIDKey, "req-123"),
				UserIDKey,
				"user-456",
			),
			expectRequestID: true,
			expectUserID:    true,
		},
		{
			name:            "empty context",
			ctx:             context.Background(),
			expectRequestID: false,
			expectUserID:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := WithContext(tt.ctx)
			if logger == nil {
				t.Error("WithContext() returned nil logger")
			}
		})
	}
}

func TestWithRequestID(t *testing.T) {
	// Create a test logger with observer
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	requestID := "test-request-123"
	enrichedLogger := WithRequestID(logger, requestID)

	enrichedLogger.Info("test message")

	// Verify the log entry has the request_id field
	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(entries))
	}

	found := false
	for _, field := range entries[0].Context {
		if field.Key == "request_id" && field.String == requestID {
			found = true
			break
		}
	}

	if !found {
		t.Error("request_id field not found in log entry")
	}
}

func TestWithUserID(t *testing.T) {
	// Create a test logger with observer
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	userID := "test-user-456"
	enrichedLogger := WithUserID(logger, userID)

	enrichedLogger.Info("test message")

	// Verify the log entry has the user_id field
	entries := logs.All()
	if len(entries) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(entries))
	}

	found := false
	for _, field := range entries[0].Context {
		if field.Key == "user_id" && field.String == userID {
			found = true
			break
		}
	}

	if !found {
		t.Error("user_id field not found in log entry")
	}
}

func TestIsSensitiveField(t *testing.T) {
	tests := []struct {
		name      string
		fieldName string
		want      bool
	}{
		{
			name:      "password field is sensitive",
			fieldName: "password",
			want:      true,
		},
		{
			name:      "master_password field is sensitive",
			fieldName: "master_password",
			want:      true,
		},
		{
			name:      "encryption_key field is sensitive",
			fieldName: "encryption_key",
			want:      true,
		},
		{
			name:      "access_token field is sensitive",
			fieldName: "access_token",
			want:      true,
		},
		{
			name:      "username field is not sensitive",
			fieldName: "username",
			want:      false,
		},
		{
			name:      "request_id field is not sensitive",
			fieldName: "request_id",
			want:      false,
		},
		{
			name:      "email field is not sensitive",
			fieldName: "email",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSensitiveField(tt.fieldName)
			if got != tt.want {
				t.Errorf("IsSensitiveField(%q) = %v, want %v", tt.fieldName, got, tt.want)
			}
		})
	}
}

func TestSync(t *testing.T) {
	// Test syncing without initialization - should not panic
	err := Sync()
	// Sync may fail in test environments (e.g., /dev/stderr bad file descriptor)
	// so we just verify it doesn't panic
	_ = err

	// Test syncing with initialization
	if err := Initialize("development"); err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	err = Sync()
	// Sync may fail in test environments, so we just verify it doesn't panic
	_ = err
}

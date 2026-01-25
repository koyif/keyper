package logger

import (
	"context"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ContextKey is a type for context keys to avoid collisions.
type ContextKey string

const (
	// RequestIDKey is the context key for request ID.
	RequestIDKey ContextKey = "request_id"

	// UserIDKey is the context key for user ID (from auth).
	UserIDKey ContextKey = "user_id"
)

var (
	// globalLogger is the application's global logger instance.
	globalLogger *zap.Logger
)

// Initialize sets up the global logger based on the environment.
// env should be "production" or "development".
func Initialize(env string) error {
	var logger *zap.Logger
	var err error

	if env == "production" {
		// Production config: JSON encoding, InfoLevel and above
		config := zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		config.EncoderConfig.MessageKey = "message"
		config.EncoderConfig.LevelKey = "level"
		config.EncoderConfig.CallerKey = "caller"
		config.EncoderConfig.StacktraceKey = "stacktrace"

		logger, err = config.Build(
			zap.AddCaller(),
			zap.AddStacktrace(zapcore.ErrorLevel),
		)
	} else {
		// Development config: Console encoding, DebugLevel
		config := zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

		logger, err = config.Build(
			zap.AddCaller(),
			zap.AddStacktrace(zapcore.ErrorLevel),
		)
	}

	if err != nil {
		return err
	}

	globalLogger = logger
	return nil
}

// Get returns the global logger instance.
// If not initialized, returns a no-op logger.
func Get() *zap.Logger {
	if globalLogger == nil {
		// Fallback to a no-op logger
		return zap.NewNop()
	}
	return globalLogger
}

// Sync flushes any buffered log entries.
// Should be called before application shutdown.
func Sync() error {
	if globalLogger != nil {
		return globalLogger.Sync()
	}
	return nil
}

// WithContext creates a child logger with contextual fields from the context.
// It extracts request_id and user_id if present in the context.
func WithContext(ctx context.Context) *zap.Logger {
	logger := Get()

	// Add request ID if present
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
		logger = logger.With(zap.String("request_id", requestID))
	}

	// Add user ID if present
	if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
		logger = logger.With(zap.String("user_id", userID))
	}

	return logger
}

// WithRequestID adds a request ID to the logger.
func WithRequestID(logger *zap.Logger, requestID string) *zap.Logger {
	return logger.With(zap.String("request_id", requestID))
}

// WithUserID adds a user ID to the logger.
func WithUserID(logger *zap.Logger, userID string) *zap.Logger {
	return logger.With(zap.String("user_id", userID))
}

// WithMethod adds a gRPC method name to the logger.
func WithMethod(logger *zap.Logger, method string) *zap.Logger {
	return logger.With(zap.String("grpc_method", method))
}

// SanitizeError removes sensitive information from errors before logging.
// This is a placeholder for actual sanitization logic.
func SanitizeError(err error) error {
	// In production, implement logic to remove sensitive data
	// For now, return as-is since we control error messages
	return err
}

// IsSensitiveField checks if a field name contains sensitive data.
func IsSensitiveField(fieldName string) bool {
	sensitiveFields := map[string]bool{
		"password":        true,
		"master_password": true,
		"old_password":    true,
		"new_password":    true,
		"encryption_key":  true,
		"secret_key":      true,
		"jwt_secret":      true,
		"access_token":    true,
		"refresh_token":   true,
		"encrypted_data":  true,
		"decrypted_data":  true,
		"plaintext":       true,
	}

	return sensitiveFields[fieldName]
}

// GetEnv returns the current environment based on LOG_LEVEL or defaults to development.
func GetEnv() string {
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "development"
	}
	return env
}

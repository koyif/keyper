package config

import "time"

type Limits struct {
	DefaultPageSize int
	MaxPageSize     int

	MaxSyncSecrets int

	TombstoneBatchSize int

	// Size of cryptographic nonce in bytes (for AES-GCM)
	NonceSize int

	DatabaseQueryTimeout time.Duration
	HealthCheckTimeout   time.Duration
	ShutdownTimeout      time.Duration
	CleanupTimeout       time.Duration

	TombstoneRetentionPeriod time.Duration
	TombstoneCleanupSchedule time.Duration
	TombstoneBatchDelay      time.Duration
	TokenCleanupInterval     time.Duration
	MetricsLogInterval       time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		DefaultPageSize: 100,
		MaxPageSize:     1000,

		MaxSyncSecrets: 1000,

		TombstoneBatchSize: 1000,

		// AES-GCM standard nonce size
		NonceSize: 12,

		DatabaseQueryTimeout: 30 * time.Second,
		HealthCheckTimeout:   2 * time.Second,
		ShutdownTimeout:      30 * time.Second,
		CleanupTimeout:       10 * time.Minute,

		TombstoneRetentionPeriod: 30 * 24 * time.Hour,
		TombstoneCleanupSchedule: 24 * time.Hour,
		TombstoneBatchDelay:      100 * time.Millisecond,
		TokenCleanupInterval:     1 * time.Hour,
		MetricsLogInterval:       5 * time.Minute,
	}
}

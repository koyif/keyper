package db

import (
	"context"
	"errors"
	"testing"
)

func BenchmarkRetry_Success(b *testing.B) {
	cfg := DefaultRetryConfig()
	fn := func() error { return nil }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Retry(context.Background(), cfg, fn)
	}
}

func BenchmarkRetry_OneRetry(b *testing.B) {
	cfg := DefaultRetryConfig()
	cfg.InitialWait = 1 // Very short for benchmarking

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		attempts := 0
		fn := func() error {
			attempts++
			if attempts < 2 {
				return errors.New("temporary error")
			}
			return nil
		}
		_ = Retry(context.Background(), cfg, fn)
	}
}

func BenchmarkRetry_ContextCanceled(b *testing.B) {
	cfg := DefaultRetryConfig()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	fn := func() error {
		return errors.New("should not be called")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Retry(ctx, cfg, fn)
	}
}

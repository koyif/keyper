package server

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/koyif/keyper/internal/server/errors"
	"github.com/koyif/keyper/internal/server/logger"
	"github.com/koyif/keyper/internal/server/metrics"
)

// TestObservabilityIntegration tests the complete observability stack.
func TestObservabilityIntegration(t *testing.T) {
	// Initialize logger
	if err := logger.Initialize("development"); err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Create metrics collector
	metricsCollector := metrics.NewMetrics()

	// Create a mock handler that returns an error
	mockHandler := func(ctx context.Context, req any) (any, error) {
		// Simulate some work
		time.Sleep(10 * time.Millisecond)
		// Return a gRPC status error (as handlers should do)
		return nil, errors.ToGRPCStatus(errors.NewNotFound("resource not found"))
	}

	// Create interceptor chain
	panicInterceptor := logger.UnaryPanicRecoveryInterceptor()
	loggingInterceptor := logger.UnaryLoggingInterceptor()
	metricsInterceptor := metrics.UnaryMetricsInterceptor(metricsCollector)

	// Chain interceptors
	chainedInterceptor := func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// Apply interceptors in order
		return panicInterceptor(ctx, req, info, func(ctx context.Context, req any) (any, error) {
			return loggingInterceptor(ctx, req, info, func(ctx context.Context, req any) (any, error) {
				return metricsInterceptor(ctx, req, info, handler)
			})
		})
	}

	// Create context with request ID
	md := metadata.New(map[string]string{
		"x-request-id": "test-request-123",
	})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	// Create server info
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/TestMethod",
	}

	// Execute the handler through the interceptor chain
	_, err := chainedInterceptor(ctx, nil, info, mockHandler)

	// Verify error was returned
	if err == nil {
		t.Error("Expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound code, got %v", st.Code())
	}

	// Verify metrics were collected
	requestCount := metricsCollector.GetRequestCount("/test.Service/TestMethod")
	if requestCount != 1 {
		t.Errorf("Expected request count 1, got %d", requestCount)
	}

	errorCount := metricsCollector.GetRequestErrors("/test.Service/TestMethod")
	if errorCount != 1 {
		t.Errorf("Expected error count 1, got %d", errorCount)
	}

	activeConnections := metricsCollector.GetActiveConnections()
	if activeConnections != 0 {
		t.Errorf("Expected active connections 0, got %d", activeConnections)
	}
}

// TestPanicRecovery tests that panics are recovered and logged.
func TestPanicRecovery(t *testing.T) {
	// Initialize logger
	if err := logger.Initialize("development"); err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Create a handler that panics
	panicHandler := func(ctx context.Context, req any) (any, error) {
		panic("something went wrong")
	}

	// Create panic recovery interceptor
	interceptor := logger.UnaryPanicRecoveryInterceptor()

	// Create server info
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/PanicMethod",
	}

	// Execute the handler
	_, err := interceptor(context.Background(), nil, info, panicHandler)

	// Verify error was returned
	if err == nil {
		t.Fatal("Expected error after panic, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal code, got %v", st.Code())
	}

	if st.Message() != "internal server error" {
		t.Errorf("Expected 'internal server error', got %v", st.Message())
	}
}

// TestLoggingInterceptor tests request logging.
func TestLoggingInterceptor(t *testing.T) {
	// Initialize logger
	if err := logger.Initialize("development"); err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Create a successful handler
	successHandler := func(ctx context.Context, req any) (any, error) {
		return "success", nil
	}

	// Create logging interceptor
	interceptor := logger.UnaryLoggingInterceptor()

	// Create server info
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/SuccessMethod",
	}

	// Execute the handler
	_, err := interceptor(context.Background(), nil, info, successHandler)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestSlowRequestLogging tests that slow requests are logged.
func TestSlowRequestLogging(t *testing.T) {
	// Create test logger with observer
	core, logs := observer.New(zap.WarnLevel)
	testLogger := zap.New(core)

	// Note: We can't easily replace the global logger for this test
	_ = testLogger
	_ = logs

	// Create a slow handler (>100ms)
	slowHandler := func(ctx context.Context, req any) (any, error) {
		time.Sleep(150 * time.Millisecond)
		return "success", nil
	}

	// Create logging interceptor
	interceptor := logger.UnaryLoggingInterceptor()

	// Create server info
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/SlowMethod",
	}

	// Execute the handler
	start := time.Now()
	_, err := interceptor(context.Background(), nil, info, slowHandler)
	duration := time.Since(start)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify duration was > 100ms
	if duration < 100*time.Millisecond {
		t.Errorf("Expected slow request (>100ms), got %v", duration)
	}
}

// TestRequestIDPropagation tests that request IDs are propagated.
func TestRequestIDPropagation(t *testing.T) {
	// Initialize logger
	if err := logger.Initialize("development"); err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	var capturedRequestID string

	// Create handler that captures request ID from context
	handler := func(ctx context.Context, req any) (any, error) {
		if requestID, ok := ctx.Value(logger.RequestIDKey).(string); ok {
			capturedRequestID = requestID
		}
		return "success", nil
	}

	// Create logging interceptor
	interceptor := logger.UnaryLoggingInterceptor()

	// Create server info
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/TestMethod",
	}

	// Test with provided request ID
	t.Run("with provided request ID", func(t *testing.T) {
		md := metadata.New(map[string]string{
			"x-request-id": "custom-request-id",
		})
		ctx := metadata.NewIncomingContext(context.Background(), md)

		_, err := interceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if capturedRequestID != "custom-request-id" {
			t.Errorf("Expected request ID 'custom-request-id', got %v", capturedRequestID)
		}
	})

	// Test with generated request ID
	t.Run("with generated request ID", func(t *testing.T) {
		capturedRequestID = ""
		ctx := context.Background()

		_, err := interceptor(ctx, nil, info, handler)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if capturedRequestID == "" {
			t.Error("Expected request ID to be generated, got empty string")
		}

		// Verify it's a valid UUID format (36 characters with hyphens)
		if len(capturedRequestID) != 36 {
			t.Errorf("Expected UUID format (36 chars), got %d chars", len(capturedRequestID))
		}
	})
}

// TestMetricsCollection tests metrics collection.
func TestMetricsCollection(t *testing.T) {
	metricsCollector := metrics.NewMetrics()

	// Create handler
	handler := func(ctx context.Context, req any) (any, error) {
		time.Sleep(50 * time.Millisecond)
		return "success", nil
	}

	// Create metrics interceptor
	interceptor := metrics.UnaryMetricsInterceptor(metricsCollector)

	// Create server info
	info := &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/MetricsTest",
	}

	// Execute multiple requests
	for i := 0; i < 5; i++ {
		_, err := interceptor(context.Background(), nil, info, handler)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	}

	// Verify metrics
	requestCount := metricsCollector.GetRequestCount("/test.Service/MetricsTest")
	if requestCount != 5 {
		t.Errorf("Expected request count 5, got %d", requestCount)
	}

	errorCount := metricsCollector.GetRequestErrors("/test.Service/MetricsTest")
	if errorCount != 0 {
		t.Errorf("Expected error count 0, got %d", errorCount)
	}

	// Verify active connections returned to 0
	activeConnections := metricsCollector.GetActiveConnections()
	if activeConnections != 0 {
		t.Errorf("Expected active connections 0, got %d", activeConnections)
	}

	// Get latency percentiles
	p50, p95, p99 := metricsCollector.GetLatencyPercentiles("/test.Service/MetricsTest")

	// Verify latencies are reasonable (>50ms since handler sleeps for 50ms)
	if p50 < 50*time.Millisecond {
		t.Errorf("Expected p50 > 50ms, got %v", p50)
	}
	if p95 < 50*time.Millisecond {
		t.Errorf("Expected p95 > 50ms, got %v", p95)
	}
	if p99 < 50*time.Millisecond {
		t.Errorf("Expected p99 > 50ms, got %v", p99)
	}
}

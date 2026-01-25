package metrics

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/koyif/keyper/internal/server/logger"
)

// UnaryMetricsInterceptor creates a gRPC interceptor that collects metrics.
func UnaryMetricsInterceptor(metrics *Metrics) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		start := time.Now()
		method := info.FullMethod

		// Increment active connections
		metrics.IncActiveConnections()
		defer metrics.DecActiveConnections()

		// Increment request count
		metrics.IncRequestCount(method)

		// Call handler
		resp, err := handler(ctx, req)

		// Record duration
		duration := time.Since(start)
		metrics.RecordRequestDuration(method, duration)

		// Increment error count if request failed
		if err != nil {
			metrics.IncRequestErrors(method)
		}

		// Log slow requests
		if duration > 100*time.Millisecond {
			log := logger.WithContext(ctx).With(
				zap.String("grpc_method", method),
				zap.Duration("duration", duration),
			)

			if err != nil {
				st, _ := status.FromError(err)
				log.Warn("slow request with error",
					zap.String("grpc_code", st.Code().String()),
				)
			} else {
				log.Warn("slow request")
			}
		}

		return resp, err
	}
}

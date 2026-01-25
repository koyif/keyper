package logger

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// UnaryLoggingInterceptor logs incoming gRPC requests and responses.
// It also adds request ID to context and logs slow queries.
func UnaryLoggingInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		start := time.Now()

		// Generate or extract request ID
		requestID := extractOrGenerateRequestID(ctx)

		// Add request ID to context
		ctx = context.WithValue(ctx, RequestIDKey, requestID)

		// Get logger with request ID
		logger := WithContext(ctx).With(
			zap.String("grpc_method", info.FullMethod),
		)

		// Log incoming request
		logger.Info("incoming gRPC request")

		// Call the handler
		resp, err := handler(ctx, req)

		// Calculate duration
		duration := time.Since(start)

		// Prepare log fields
		fields := []zap.Field{
			zap.Duration("duration", duration),
			zap.String("grpc_method", info.FullMethod),
		}

		// Log slow queries (>100ms)
		if duration > 100*time.Millisecond {
			logger.Warn("slow gRPC request", fields...)
		}

		// Log response status
		if err != nil {
			st, _ := status.FromError(err)
			fields = append(fields,
				zap.String("grpc_code", st.Code().String()),
				zap.Error(err),
			)
			logger.Error("gRPC request failed", fields...)
		} else {
			logger.Info("gRPC request completed", fields...)
		}

		return resp, err
	}
}

// UnaryPanicRecoveryInterceptor recovers from panics in gRPC handlers.
func UnaryPanicRecoveryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger := WithContext(ctx).With(
					zap.String("grpc_method", info.FullMethod),
				)

				logger.Error("panic recovered in gRPC handler",
					zap.Any("panic", r),
					zap.Stack("stacktrace"),
				)

				err = status.Errorf(codes.Internal, "internal server error")
			}
		}()

		return handler(ctx, req)
	}
}

// extractOrGenerateRequestID extracts request ID from metadata or generates a new one.
func extractOrGenerateRequestID(ctx context.Context) string {
	// Try to extract from metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		if requestIDs := md.Get("x-request-id"); len(requestIDs) > 0 {
			return requestIDs[0]
		}
	}

	// Generate new UUID
	return uuid.New().String()
}

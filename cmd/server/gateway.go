package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"mime"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/koyif/keyper/internal/server/health"
	pb "github.com/koyif/keyper/pkg/api/proto"
)

//go:embed swagger-ui/*
var swaggerUIFiles embed.FS

// GatewayConfig holds configuration for the HTTP gateway server.
type GatewayConfig struct {
	HTTPPort      int
	GRPCEndpoint  string
	EnableCORS    bool
	HealthService *health.Service
}

// StartGatewayServer starts the gRPC-Gateway HTTP server.
// It serves REST endpoints, Swagger UI, and OpenAPI specification.
func StartGatewayServer(ctx context.Context, cfg GatewayConfig) error {
	// Create a client connection to the gRPC server.
	conn, err := grpc.NewClient(
		cfg.GRPCEndpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to dial gRPC server: %w", err)
	}

	// Create gRPC-Gateway mux with custom options.
	gwmux := runtime.NewServeMux(
		runtime.WithMarshalerOption(runtime.MIMEWildcard, &runtime.JSONPb{}),
	)

	// Register all gRPC services with the gateway.
	if err := pb.RegisterAuthServiceHandler(ctx, gwmux, conn); err != nil {
		return fmt.Errorf("failed to register auth service: %w", err)
	}
	if err := pb.RegisterSecretsServiceHandler(ctx, gwmux, conn); err != nil {
		return fmt.Errorf("failed to register secrets service: %w", err)
	}
	if err := pb.RegisterSyncServiceHandler(ctx, gwmux, conn); err != nil {
		return fmt.Errorf("failed to register sync service: %w", err)
	}

	log.Println("gRPC-Gateway services registered")

	// Create HTTP mux and register handlers.
	mux := http.NewServeMux()

	// Serve OpenAPI spec at /swagger.json
	mux.HandleFunc("/swagger.json", serveSwaggerSpec())

	// Serve Swagger UI at /swagger/
	swaggerUIHandler, err := createSwaggerUIHandler()
	if err != nil {
		return fmt.Errorf("failed to create Swagger UI handler: %w", err)
	}
	mux.Handle("/swagger/", http.StripPrefix("/swagger/", swaggerUIHandler))

	// Health check endpoints
	mux.HandleFunc("/health", healthHandler(cfg.HealthService))
	mux.HandleFunc("/health/live", livenessHandler())
	mux.HandleFunc("/health/ready", readinessHandler(cfg.HealthService))

	// Forward all other requests to gRPC-Gateway.
	mux.Handle("/", gwmux)

	// Wrap with CORS middleware if enabled.
	var handler http.Handler = mux
	if cfg.EnableCORS {
		handler = corsMiddleware(mux)
	}

	// Start HTTP server.
	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	log.Printf("Starting HTTP gateway server on %s", addr)
	log.Printf("Swagger UI available at http://localhost:%d/swagger/", cfg.HTTPPort)
	log.Printf("OpenAPI spec available at http://localhost:%d/swagger.json", cfg.HTTPPort)

	server := &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	return server.ListenAndServe()
}

// serveSwaggerSpec returns a handler that serves the merged OpenAPI specification.
func serveSwaggerSpec() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		// Read the generated OpenAPI spec.
		spec, err := fs.ReadFile(swaggerUIFiles, "swagger-ui/keyper.swagger.json")
		if err != nil {
			http.Error(w, "OpenAPI spec not found", http.StatusNotFound)
			log.Printf("Error reading OpenAPI spec: %v", err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(spec); err != nil {
			log.Printf("Error writing OpenAPI spec response: %v", err)
		}
	}
}

// createSwaggerUIHandler creates a file server for Swagger UI static files.
func createSwaggerUIHandler() (http.Handler, error) {
	// Get the swagger-ui subdirectory from embedded files.
	swaggerUI, err := fs.Sub(swaggerUIFiles, "swagger-ui")
	if err != nil {
		return nil, fmt.Errorf("failed to get swagger-ui subdirectory: %w", err)
	}

	// Configure MIME types for common web files.
	// These are typically already registered, but we set them explicitly
	// to ensure consistent behavior. Errors are ignored since these
	// registrations are not critical for operation.
	_ = mime.AddExtensionType(".js", "application/javascript")
	_ = mime.AddExtensionType(".css", "text/css")
	_ = mime.AddExtensionType(".html", "text/html")
	_ = mime.AddExtensionType(".json", "application/json")

	return http.FileServer(http.FS(swaggerUI)), nil
}

// corsMiddleware adds CORS headers for development.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token")
		w.Header().Set("Access-Control-Expose-Headers", "Authorization")

		// Handle preflight requests.
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// healthHandler returns a handler for comprehensive health checks.
func healthHandler(healthService *health.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if healthService == nil {
			http.Error(w, "Health service not configured", http.StatusInternalServerError)
			return
		}

		report := healthService.CheckHealth(r.Context())

		w.Header().Set("Content-Type", "application/json")

		// Set appropriate HTTP status code based on health status
		statusCode := http.StatusOK
		if report.Status == health.StatusUnhealthy {
			statusCode = http.StatusServiceUnavailable
		} else if report.Status == health.StatusDegraded {
			statusCode = http.StatusOK // Still accepting requests
		}

		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(report); err != nil {
			log.Printf("Error encoding health report: %v", err)
		}
	}
}

// livenessHandler returns a simple liveness probe handler.
func livenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"alive"}`)); err != nil {
			log.Printf("Error writing liveness response: %v", err)
		}
	}
}

// readinessHandler returns a readiness probe handler.
func readinessHandler(healthService *health.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if healthService == nil {
			http.Error(w, "Health service not configured", http.StatusInternalServerError)
			return
		}

		report := healthService.CheckHealth(r.Context())

		w.Header().Set("Content-Type", "application/json")

		// Service is ready only if all checks are healthy
		if report.Status == health.StatusHealthy {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		response := map[string]any{
			"status": report.Status,
			"ready":  report.Status == health.StatusHealthy,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding readiness response: %v", err)
		}
	}
}

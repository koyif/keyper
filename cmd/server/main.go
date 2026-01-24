package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/koy/keyper/internal/database"
	"google.golang.org/grpc"
)

func main() {
	log.Println("Starting Keyper server...")

	// Load configuration from environment variables
	cfg := loadConfig()

	// Initialize database connection with auto-migrations
	db, err := database.New(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	log.Println("Database initialized successfully")

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// TODO: Register gRPC services here
	// pb.RegisterAuthServiceServer(grpcServer, authService)
	// pb.RegisterSecretsServiceServer(grpcServer, secretsService)
	// pb.RegisterSyncServiceServer(grpcServer, syncService)

	// Start listening
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}

	log.Printf("Server listening on %s", addr)

	// Start server in a goroutine
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		log.Println("Server stopped gracefully")
	case <-ctx.Done():
		log.Println("Shutdown timeout, forcing stop")
		grpcServer.Stop()
	}
}

// Config holds application configuration
type Config struct {
	Server   ServerConfig
	Database database.Config
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Host string
	Port int
}

// loadConfig loads configuration from environment variables
func loadConfig() Config {
	return Config{
		Server: ServerConfig{
			Host: getEnv("SERVER_HOST", "localhost"),
			Port: getEnvInt("SERVER_PORT", 50051),
		},
		Database: database.Config{
			Host:     getEnv("POSTGRES_HOST", "localhost"),
			Port:     getEnvInt("POSTGRES_PORT", 5432),
			User:     getEnv("POSTGRES_USER", "keyper"),
			Password: getEnv("POSTGRES_PASSWORD", "keyper_dev_password"),
			Database: getEnv("POSTGRES_DB", "keyper"),
			SSLMode:  getEnv("POSTGRES_SSL_MODE", "disable"),
		},
	}
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt retrieves an integer environment variable or returns a default value
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

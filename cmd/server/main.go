package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/koyif/keyper/internal/database"
	"google.golang.org/grpc"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"

	showVersion = flag.Bool("version", false, "Show version information and exit")
)

func main() {
	flag.Parse()

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	log.Println("Starting Keyper server...")
	log.Printf("Version: %s, Commit: %s, Build Date: %s", version, commit, buildDate)

	cfg := loadConfig()

	db, err := database.New(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	log.Println("Database initialized successfully")

	grpcServer := grpc.NewServer()

	// TODO: Register gRPC services here
	// pb.RegisterAuthServiceServer(grpcServer, authService)
	// pb.RegisterSecretsServiceServer(grpcServer, secretsService)
	// pb.RegisterSyncServiceServer(grpcServer, syncService)

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}

	log.Printf("Server listening on %s", addr)

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

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

// printVersion prints version information
func printVersion() {
	fmt.Printf("Keyper Server\n")
	fmt.Printf("Version:    %s\n", version)
	fmt.Printf("Commit:     %s\n", commit)
	fmt.Printf("Build Date: %s\n", buildDate)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

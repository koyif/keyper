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

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/koyif/keyper/internal/server/auth"
	"github.com/koyif/keyper/internal/server/db"
	"github.com/koyif/keyper/internal/server/handlers"
	"github.com/koyif/keyper/internal/server/health"
	"github.com/koyif/keyper/internal/server/jobs"
	"github.com/koyif/keyper/internal/server/logger"
	"github.com/koyif/keyper/internal/server/metrics"
	"github.com/koyif/keyper/internal/server/repository/postgres"
	pb "github.com/koyif/keyper/pkg/api/proto"
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

	// Initialize structured logger.
	env := logger.GetEnv()
	if err := logger.Initialize(env); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer func() {
		if err := logger.Sync(); err != nil {
			log.Printf("Error syncing logger: %v", err)
		}
	}()

	zapLogger := logger.Get()
	zapLogger.Info("Keyper server starting",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("build_date", buildDate),
		zap.String("environment", env),
	)

	// Initialize database connection pool.
	ctx := context.Background()
	pool, err := db.NewPool(ctx, &cfg.Database)
	if err != nil {
		zapLogger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer pool.Close()

	zapLogger.Info("Database initialized successfully")

	// Initialize repositories.
	userRepo := postgres.NewUserRepository(pool.Pool)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(pool.Pool)
	secretRepo := postgres.NewSecretRepository(pool.Pool)

	// Initialize transactor for multi-step operations.
	transactor := postgres.NewTransactor(pool.Pool)

	// Initialize JWT manager.
	jwtManager := auth.NewJWTManager(cfg.Auth.JWTSecret)
	zapLogger.Info("JWT manager initialized")

	// Initialize token blacklist with 1 hour cleanup interval.
	tokenBlacklist := auth.NewTokenBlacklist(1 * time.Hour)
	defer tokenBlacklist.Stop()
	zapLogger.Info("Token blacklist initialized")

	// Initialize tombstone cleanup job with default configuration (daily, 30-day retention).
	tombstoneCleanup := jobs.NewTombstoneCleanup(secretRepo, jobs.DefaultConfig())
	tombstoneCleanup.Start()
	defer tombstoneCleanup.Stop()
	zapLogger.Info("Tombstone cleanup job initialized")

	// Initialize metrics collector.
	metricsCollector := metrics.NewMetrics()

	// Start periodic metrics logging (every 5 minutes).
	metricsCtx, metricsCancel := context.WithCancel(context.Background())
	defer metricsCancel()
	go metricsCollector.StartPeriodicLogging(metricsCtx, zapLogger, 5*time.Minute)
	zapLogger.Info("Metrics collector initialized")

	// Initialize health check service.
	healthService := health.NewService(version)
	healthService.RegisterChecker("postgres", health.NewPostgresChecker(pool.Pool))
	healthService.RegisterChecker("liveness", health.NewLivenessChecker())
	zapLogger.Info("Health check service initialized")

	// Create gRPC server with chained interceptors.
	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			logger.UnaryPanicRecoveryInterceptor(),
			logger.UnaryLoggingInterceptor(),
			metrics.UnaryMetricsInterceptor(metricsCollector),
			auth.UnaryAuthInterceptorWithBlacklist(jwtManager, tokenBlacklist),
		),
	)

	// Initialize service handlers.
	authService := handlers.NewAuthService(userRepo, refreshTokenRepo, jwtManager, tokenBlacklist)
	secretsService := handlers.NewSecretsService(secretRepo)
	syncService := handlers.NewSyncService(secretRepo, transactor)

	// Register gRPC services.
	pb.RegisterAuthServiceServer(grpcServer, authService)
	pb.RegisterSecretsServiceServer(grpcServer, secretsService)
	pb.RegisterSyncServiceServer(grpcServer, syncService)

	zapLogger.Info("gRPC services registered")

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		zapLogger.Fatal("Failed to create listener",
			zap.String("address", addr),
			zap.Error(err),
		)
	}

	zapLogger.Info("gRPC server listening", zap.String("address", addr))

	// Start gRPC server in a goroutine.
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			zapLogger.Fatal("Failed to serve gRPC", zap.Error(err))
		}
	}()

	// Start HTTP gateway server in a goroutine.
	gatewayCtx, gatewayCancel := context.WithCancel(context.Background())
	defer gatewayCancel()

	go func() {
		gatewayCfg := GatewayConfig{
			HTTPPort:      cfg.Server.HTTPPort,
			GRPCEndpoint:  addr,
			EnableCORS:    cfg.Server.EnableCORS,
			HealthService: healthService,
		}
		if err := StartGatewayServer(gatewayCtx, gatewayCfg); err != nil {
			zapLogger.Fatal("Failed to serve HTTP gateway", zap.Error(err))
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	zapLogger.Info("Shutting down server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		zapLogger.Info("Server stopped gracefully")
	case <-shutdownCtx.Done():
		zapLogger.Warn("Shutdown timeout, forcing stop")
		grpcServer.Stop()
	}
}

// Config holds application configuration.
type Config struct {
	Server   ServerConfig
	Database db.Config
	Auth     AuthConfig
}

// ServerConfig holds server configuration.
type ServerConfig struct {
	Host       string
	Port       int
	HTTPPort   int
	EnableCORS bool
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	JWTSecret string
}

// loadConfig loads configuration from environment variables.
func loadConfig() Config {
	jwtSecret := getEnv("JWT_SECRET", "")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	return Config{
		Server: ServerConfig{
			Host:       getEnv("SERVER_HOST", "localhost"),
			Port:       getEnvInt("SERVER_PORT", 50051),
			HTTPPort:   getEnvInt("HTTP_PORT", 8080),
			EnableCORS: getEnvBool("ENABLE_CORS", true),
		},
		Database: db.Config{
			Host:              getEnv("POSTGRES_HOST", "localhost"),
			Port:              getEnvInt("POSTGRES_PORT", 5432),
			User:              getEnv("POSTGRES_USER", "keyper"),
			Password:          getEnv("POSTGRES_PASSWORD", "keyper_dev_password"),
			Database:          getEnv("POSTGRES_DB", "keyper"),
			SSLMode:           getEnv("POSTGRES_SSL_MODE", "disable"),
			MaxConns:          25,
			MinConns:          5,
			MaxConnLifetime:   time.Hour,
			MaxConnIdleTime:   30 * time.Minute,
			HealthCheckPeriod: time.Minute,
		},
		Auth: AuthConfig{
			JWTSecret: jwtSecret,
		},
	}
}

// getEnv retrieves an environment variable or returns a default value.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt retrieves an integer environment variable or returns a default value.
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvBool retrieves a boolean environment variable or returns a default value.
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// printVersion prints version information.
func printVersion() {
	fmt.Printf("Keyper Server\n")
	fmt.Printf("Version:    %s\n", version)
	fmt.Printf("Commit:     %s\n", commit)
	fmt.Printf("Build Date: %s\n", buildDate)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

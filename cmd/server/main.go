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
	"github.com/koyif/keyper/internal/server/config"
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

	// Use standard log for initial startup before logger is initialized
	//nolint:forbidigo // Early startup logging before structured logger is initialized
	log.Println("Starting Keyper server...")
	//nolint:forbidigo // Early startup logging before structured logger is initialized
	log.Printf("Version: %s, Commit: %s, Build Date: %s", version, commit, buildDate)

	cfg := loadConfig()

	env := logger.GetEnv()
	if err := logger.Initialize(env); err != nil {
		//nolint:forbidigo // Early fatal error before logger is available
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	defer func() {
		if err := logger.Sync(); err != nil {
			//nolint:forbidigo // Logger sync error in defer, structured logger may not be available
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

	ctx := context.Background()
	pool, err := db.NewPool(ctx, &cfg.Database)
	if err != nil {
		zapLogger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer pool.Close()

	zapLogger.Info("Database initialized successfully")

	userRepo := postgres.NewUserRepository(pool.Pool)
	refreshTokenRepo := postgres.NewRefreshTokenRepository(pool.Pool)
	secretRepo := postgres.NewSecretRepository(pool.Pool)

	transactor := postgres.NewTransactor(pool.Pool)

	jwtManager := auth.NewJWTManager(cfg.Auth.JWTSecret)
	zapLogger.Info("JWT manager initialized")

	tokenBlacklist := auth.NewTokenBlacklist(cfg.Limits.TokenCleanupInterval)
	defer tokenBlacklist.Stop()
	zapLogger.Info("Token blacklist initialized")

	tombstoneConfig := jobs.Config{
		RetentionPeriod: cfg.Limits.TombstoneRetentionPeriod,
		Schedule:        cfg.Limits.TombstoneCleanupSchedule,
		BatchSize:       cfg.Limits.TombstoneBatchSize,
		BatchDelay:      cfg.Limits.TombstoneBatchDelay,
		CleanupTimeout:  cfg.Limits.CleanupTimeout,
	}
	tombstoneCleanup := jobs.NewTombstoneCleanup(secretRepo, tombstoneConfig)
	tombstoneCleanup.Start()
	defer tombstoneCleanup.Stop()
	zapLogger.Info("Tombstone cleanup job initialized")

	metricsCollector := metrics.NewMetrics()

	metricsCtx, metricsCancel := context.WithCancel(context.Background())
	defer metricsCancel()
	go metricsCollector.StartPeriodicLogging(metricsCtx, zapLogger, cfg.Limits.MetricsLogInterval)
	zapLogger.Info("Metrics collector initialized")

	healthService := health.NewService(version)
	healthService.RegisterChecker("postgres", health.NewPostgresChecker(pool.Pool))
	healthService.RegisterChecker("liveness", health.NewLivenessChecker())
	zapLogger.Info("Health check service initialized")

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			logger.UnaryPanicRecoveryInterceptor(),
			logger.UnaryLoggingInterceptor(),
			metrics.UnaryMetricsInterceptor(metricsCollector),
			auth.UnaryAuthInterceptorWithBlacklist(jwtManager, tokenBlacklist),
		),
	)

	authService := handlers.NewAuthService(userRepo, refreshTokenRepo, jwtManager, tokenBlacklist)
	secretsService := handlers.NewSecretsService(secretRepo, cfg.Limits)
	syncService := handlers.NewSyncService(secretRepo, transactor, cfg.Limits)

	pb.RegisterAuthServiceServer(grpcServer, authService)
	pb.RegisterSecretsServiceServer(grpcServer, secretsService)
	pb.RegisterSyncServiceServer(grpcServer, syncService)

	zapLogger.Info("gRPC services registered")

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		zapLogger.Fatal("Failed to create listener",
			zap.String("address", addr),
			zap.Error(err),
		)
	}

	zapLogger.Info("gRPC server listening", zap.String("address", addr))

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			zapLogger.Fatal("Failed to serve gRPC", zap.Error(err))
		}
	}()

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

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Limits.ShutdownTimeout)
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

type Config struct {
	Server   ServerConfig
	Database db.Config
	Auth     AuthConfig
	Limits   config.Limits
}

type ServerConfig struct {
	Host       string
	Port       int
	HTTPPort   int
	EnableCORS bool
}

type AuthConfig struct {
	JWTSecret string
}

func loadConfig() Config {
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}

	serverPort := 50051
	if port := os.Getenv("SERVER_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			serverPort = p
		}
	}

	httpPort := 8080
	if port := os.Getenv("HTTP_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			httpPort = p
		}
	}

	postgresPort := 5432
	if port := os.Getenv("POSTGRES_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			postgresPort = p
		}
	}

	enableCORS := true
	if cors := os.Getenv("ENABLE_CORS"); cors != "" {
		if b, err := strconv.ParseBool(cors); err == nil {
			enableCORS = b
		}
	}

	getEnvDefault := func(key, defaultValue string) string {
		if value := os.Getenv(key); value != "" {
			return value
		}
		return defaultValue
	}

	return Config{
		Server: ServerConfig{
			Host:       getEnvDefault("SERVER_HOST", "localhost"),
			Port:       serverPort,
			HTTPPort:   httpPort,
			EnableCORS: enableCORS,
		},
		Database: db.Config{
			Host:              getEnvDefault("POSTGRES_HOST", "localhost"),
			Port:              postgresPort,
			User:              getEnvDefault("POSTGRES_USER", "keyper"),
			Password:          getEnvDefault("POSTGRES_PASSWORD", "keyper_dev_password"),
			Database:          getEnvDefault("POSTGRES_DB", "keyper"),
			SSLMode:           getEnvDefault("POSTGRES_SSL_MODE", "disable"),
			MaxConns:          25,
			MinConns:          5,
			MaxConnLifetime:   time.Hour,
			MaxConnIdleTime:   30 * time.Minute,
			HealthCheckPeriod: time.Minute,
		},
		Auth: AuthConfig{
			JWTSecret: jwtSecret,
		},
		Limits: config.DefaultLimits(),
	}
}

//nolint:forbidigo // printVersion outputs to stdout for CLI version flag
func printVersion() {
	fmt.Printf("Keyper Server\n")
	fmt.Printf("Version:    %s\n", version)
	fmt.Printf("Commit:     %s\n", commit)
	fmt.Printf("Build Date: %s\n", buildDate)
	fmt.Printf("Go Version: %s\n", runtime.Version())
	fmt.Printf("OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

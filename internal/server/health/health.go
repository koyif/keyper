package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Status represents the health status of a component.
type Status string

const (
	// StatusHealthy indicates the component is healthy.
	StatusHealthy Status = "healthy"

	// StatusUnhealthy indicates the component is unhealthy.
	StatusUnhealthy Status = "unhealthy"

	// StatusDegraded indicates the component is partially functional.
	StatusDegraded Status = "degraded"
)

// Check represents a health check result for a component.
type Check struct {
	Name     string         `json:"name"`
	Status   Status         `json:"status"`
	Message  string         `json:"message,omitempty"`
	Duration time.Duration  `json:"duration"`
	Details  map[string]any `json:"details,omitempty"`
}

// Report represents the overall health status.
type Report struct {
	Status    Status           `json:"status"`
	Timestamp time.Time        `json:"timestamp"`
	Checks    map[string]Check `json:"checks"`
	Version   string           `json:"version,omitempty"`
}

// Checker defines the interface for health checks.
type Checker interface {
	Check(ctx context.Context) Check
}

// Service manages health checks for the application.
type Service struct {
	mu       sync.RWMutex
	checkers map[string]Checker
	version  string
}

// NewService creates a new health check service.
func NewService(version string) *Service {
	return &Service{
		checkers: make(map[string]Checker),
		version:  version,
	}
}

// RegisterChecker adds a new health checker.
func (s *Service) RegisterChecker(name string, checker Checker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkers[name] = checker
}

// CheckHealth runs all health checks and returns a report.
func (s *Service) CheckHealth(ctx context.Context) Report {
	s.mu.RLock()
	checkers := make(map[string]Checker, len(s.checkers))
	for name, checker := range s.checkers {
		checkers[name] = checker
	}
	s.mu.RUnlock()

	checks := make(map[string]Check, len(checkers))
	overallStatus := StatusHealthy

	// Run all checks
	for name, checker := range checkers {
		check := checker.Check(ctx)
		checks[name] = check

		// Update overall status
		if check.Status == StatusUnhealthy {
			overallStatus = StatusUnhealthy
		} else if check.Status == StatusDegraded && overallStatus != StatusUnhealthy {
			overallStatus = StatusDegraded
		}
	}

	return Report{
		Status:    overallStatus,
		Timestamp: time.Now(),
		Checks:    checks,
		Version:   s.version,
	}
}

// PostgresChecker checks the health of a PostgreSQL database.
type PostgresChecker struct {
	pool *pgxpool.Pool
}

// NewPostgresChecker creates a new PostgreSQL health checker.
func NewPostgresChecker(pool *pgxpool.Pool) *PostgresChecker {
	return &PostgresChecker{pool: pool}
}

// Check performs a database health check.
func (c *PostgresChecker) Check(ctx context.Context) Check {
	start := time.Now()

	// Try to ping the database
	err := c.pool.Ping(ctx)
	duration := time.Since(start)

	if err != nil {
		return Check{
			Name:     "postgres",
			Status:   StatusUnhealthy,
			Message:  fmt.Sprintf("database ping failed: %v", err),
			Duration: duration,
		}
	}

	// Get pool stats
	stats := c.pool.Stat()
	details := map[string]any{
		"max_conns":      stats.MaxConns(),
		"acquired_conns": stats.AcquiredConns(),
		"idle_conns":     stats.IdleConns(),
	}

	// Check if pool is degraded (more than 80% connections in use)
	acquiredConns := stats.AcquiredConns()
	maxConns := stats.MaxConns()
	utilizationPercent := float64(acquiredConns) / float64(maxConns) * 100

	status := StatusHealthy
	message := "database connection pool healthy"

	if utilizationPercent > 80 {
		status = StatusDegraded
		message = fmt.Sprintf("high connection pool utilization: %.1f%%", utilizationPercent)
	}

	details["utilization_percent"] = utilizationPercent

	return Check{
		Name:     "postgres",
		Status:   status,
		Message:  message,
		Duration: duration,
		Details:  details,
	}
}

// LivenessChecker is a simple liveness check that always returns healthy.
type LivenessChecker struct{}

// NewLivenessChecker creates a new liveness checker.
func NewLivenessChecker() *LivenessChecker {
	return &LivenessChecker{}
}

// Check always returns healthy (indicates the service is running).
func (c *LivenessChecker) Check(_ context.Context) Check {
	return Check{
		Name:     "liveness",
		Status:   StatusHealthy,
		Message:  "service is running",
		Duration: 0,
	}
}

// ReadinessChecker checks if the service is ready to accept requests.
type ReadinessChecker struct {
	checkers []Checker
}

// NewReadinessChecker creates a new readiness checker.
func NewReadinessChecker(checkers ...Checker) *ReadinessChecker {
	return &ReadinessChecker{checkers: checkers}
}

// Check runs all dependency checks to determine readiness.
func (c *ReadinessChecker) Check(ctx context.Context) Check {
	start := time.Now()

	for _, checker := range c.checkers {
		check := checker.Check(ctx)
		if check.Status == StatusUnhealthy {
			return Check{
				Name:     "readiness",
				Status:   StatusUnhealthy,
				Message:  "service not ready: " + check.Message,
				Duration: time.Since(start),
			}
		}
	}

	return Check{
		Name:     "readiness",
		Status:   StatusHealthy,
		Message:  "service is ready",
		Duration: time.Since(start),
	}
}

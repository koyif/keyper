package health

import (
	"context"
	"testing"
	"time"
)

func TestNewService(t *testing.T) {
	version := "1.0.0"
	service := NewService(version)

	if service == nil {
		t.Fatal("NewService() returned nil")
	}

	if service.version != version {
		t.Errorf("NewService() version = %v, want %v", service.version, version)
	}

	if service.checkers == nil {
		t.Error("NewService() checkers map is nil")
	}
}

func TestService_RegisterChecker(t *testing.T) {
	service := NewService("1.0.0")
	checker := NewLivenessChecker()

	service.RegisterChecker("test", checker)

	service.mu.RLock()
	defer service.mu.RUnlock()

	if _, exists := service.checkers["test"]; !exists {
		t.Error("RegisterChecker() did not register the checker")
	}
}

func TestService_CheckHealth(t *testing.T) {
	service := NewService("1.0.0")

	// Register test checkers
	service.RegisterChecker("liveness", NewLivenessChecker())
	service.RegisterChecker("mock_healthy", &mockChecker{status: StatusHealthy})
	service.RegisterChecker("mock_degraded", &mockChecker{status: StatusDegraded})

	report := service.CheckHealth(context.Background())

	// Verify report structure
	if report.Status != StatusDegraded {
		t.Errorf("CheckHealth() status = %v, want %v (degraded due to one degraded check)", report.Status, StatusDegraded)
	}

	if report.Version != "1.0.0" {
		t.Errorf("CheckHealth() version = %v, want %v", report.Version, "1.0.0")
	}

	if len(report.Checks) != 3 {
		t.Errorf("CheckHealth() checks count = %v, want 3", len(report.Checks))
	}

	// Verify individual checks
	if check, exists := report.Checks["liveness"]; exists {
		if check.Status != StatusHealthy {
			t.Errorf("liveness check status = %v, want %v", check.Status, StatusHealthy)
		}
	} else {
		t.Error("liveness check not found in report")
	}
}

func TestService_CheckHealth_Unhealthy(t *testing.T) {
	service := NewService("1.0.0")

	// Register checkers with one unhealthy
	service.RegisterChecker("healthy", &mockChecker{status: StatusHealthy})
	service.RegisterChecker("unhealthy", &mockChecker{status: StatusUnhealthy})

	report := service.CheckHealth(context.Background())

	if report.Status != StatusUnhealthy {
		t.Errorf("CheckHealth() status = %v, want %v", report.Status, StatusUnhealthy)
	}
}

func TestLivenessChecker_Check(t *testing.T) {
	checker := NewLivenessChecker()
	check := checker.Check(context.Background())

	if check.Name != "liveness" {
		t.Errorf("Check() name = %v, want 'liveness'", check.Name)
	}

	if check.Status != StatusHealthy {
		t.Errorf("Check() status = %v, want %v", check.Status, StatusHealthy)
	}

	if check.Duration != 0 {
		t.Errorf("Check() duration = %v, want 0", check.Duration)
	}
}

func TestReadinessChecker_Check_Healthy(t *testing.T) {
	checkers := []Checker{
		&mockChecker{status: StatusHealthy},
		&mockChecker{status: StatusHealthy},
	}

	readinessChecker := NewReadinessChecker(checkers...)
	check := readinessChecker.Check(context.Background())

	if check.Name != "readiness" {
		t.Errorf("Check() name = %v, want 'readiness'", check.Name)
	}

	if check.Status != StatusHealthy {
		t.Errorf("Check() status = %v, want %v", check.Status, StatusHealthy)
	}
}

func TestReadinessChecker_Check_Unhealthy(t *testing.T) {
	checkers := []Checker{
		&mockChecker{status: StatusHealthy},
		&mockChecker{status: StatusUnhealthy},
	}

	readinessChecker := NewReadinessChecker(checkers...)
	check := readinessChecker.Check(context.Background())

	if check.Status != StatusUnhealthy {
		t.Errorf("Check() status = %v, want %v", check.Status, StatusUnhealthy)
	}

	if check.Message == "" {
		t.Error("Check() message should not be empty for unhealthy status")
	}
}

func TestReadinessChecker_Check_Empty(t *testing.T) {
	readinessChecker := NewReadinessChecker()
	check := readinessChecker.Check(context.Background())

	if check.Status != StatusHealthy {
		t.Errorf("Check() with no checkers status = %v, want %v", check.Status, StatusHealthy)
	}
}

// mockChecker is a test implementation of the Checker interface.
type mockChecker struct {
	status  Status
	message string
}

func (m *mockChecker) Check(_ context.Context) Check {
	return Check{
		Name:     "mock",
		Status:   m.status,
		Message:  m.message,
		Duration: time.Millisecond,
	}
}

func TestCheck_AllStatuses(t *testing.T) {
	statuses := []Status{
		StatusHealthy,
		StatusUnhealthy,
		StatusDegraded,
	}

	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			check := Check{
				Name:     "test",
				Status:   status,
				Message:  "test message",
				Duration: time.Second,
			}

			if check.Status != status {
				t.Errorf("Check.Status = %v, want %v", check.Status, status)
			}
		})
	}
}

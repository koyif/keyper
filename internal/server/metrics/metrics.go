package metrics

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Metrics holds application metrics.
type Metrics struct {
	mu sync.RWMutex

	// Request metrics
	requestCount      map[string]int64
	requestDurations  map[string][]time.Duration
	requestErrors     map[string]int64
	activeConnections int64

	// Database metrics
	dbQueryCount  int64
	dbSlowQueries int64
	dbErrorCount  int64
}

// NewMetrics creates a new metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		requestCount:     make(map[string]int64),
		requestDurations: make(map[string][]time.Duration),
		requestErrors:    make(map[string]int64),
	}
}

// IncRequestCount increments the request count for a method.
func (m *Metrics) IncRequestCount(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.requestCount[method]++
}

// RecordRequestDuration records the duration of a request.
func (m *Metrics) RecordRequestDuration(method string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.requestDurations[method] = append(m.requestDurations[method], duration)

	// Keep only last 1000 entries per method
	if len(m.requestDurations[method]) > 1000 {
		m.requestDurations[method] = m.requestDurations[method][1:]
	}
}

// IncRequestErrors increments the error count for a method.
func (m *Metrics) IncRequestErrors(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.requestErrors[method]++
}

// IncActiveConnections increments active connection count.
func (m *Metrics) IncActiveConnections() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.activeConnections++
}

// DecActiveConnections decrements active connection count.
func (m *Metrics) DecActiveConnections() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.activeConnections--
}

// IncDBQueryCount increments database query count.
func (m *Metrics) IncDBQueryCount() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dbQueryCount++
}

// IncDBSlowQueries increments slow query count.
func (m *Metrics) IncDBSlowQueries() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dbSlowQueries++
}

// IncDBErrorCount increments database error count.
func (m *Metrics) IncDBErrorCount() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dbErrorCount++
}

// GetRequestCount returns the request count for a method.
func (m *Metrics) GetRequestCount(method string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.requestCount[method]
}

// GetRequestErrors returns the error count for a method.
func (m *Metrics) GetRequestErrors(method string) int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.requestErrors[method]
}

// GetActiveConnections returns the active connection count.
func (m *Metrics) GetActiveConnections() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.activeConnections
}

// GetDBMetrics returns database metrics.
func (m *Metrics) GetDBMetrics() (queryCount, slowQueries, errorCount int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.dbQueryCount, m.dbSlowQueries, m.dbErrorCount
}

// GetLatencyPercentiles returns latency percentiles for a method.
func (m *Metrics) GetLatencyPercentiles(method string) (p50, p95, p99 time.Duration) {
	m.mu.RLock()
	durations := make([]time.Duration, len(m.requestDurations[method]))
	copy(durations, m.requestDurations[method])
	m.mu.RUnlock()

	if len(durations) == 0 {
		return 0, 0, 0
	}

	// Sort durations
	sort := func(durations []time.Duration) {
		for i := 0; i < len(durations); i++ {
			for j := i + 1; j < len(durations); j++ {
				if durations[i] > durations[j] {
					durations[i], durations[j] = durations[j], durations[i]
				}
			}
		}
	}
	sort(durations)

	// Calculate percentiles
	p50 = durations[len(durations)*50/100]
	p95 = durations[len(durations)*95/100]
	p99 = durations[len(durations)*99/100]

	return p50, p95, p99
}

// Snapshot returns a snapshot of all metrics.
func (m *Metrics) Snapshot() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()

	snapshot := make(map[string]any)
	snapshot["active_connections"] = m.activeConnections
	snapshot["db_query_count"] = m.dbQueryCount
	snapshot["db_slow_queries"] = m.dbSlowQueries
	snapshot["db_error_count"] = m.dbErrorCount

	// Request counts
	requestCounts := make(map[string]int64)
	for method, count := range m.requestCount {
		requestCounts[method] = count
	}

	snapshot["request_counts"] = requestCounts

	// Request errors
	requestErrors := make(map[string]int64)
	for method, count := range m.requestErrors {
		requestErrors[method] = count
	}

	snapshot["request_errors"] = requestErrors

	return snapshot
}

// LogMetrics logs current metrics using the provided logger.
func (m *Metrics) LogMetrics(logger *zap.Logger) {
	snapshot := m.Snapshot()

	logger.Info("metrics snapshot",
		zap.Int64("active_connections", snapshot["active_connections"].(int64)),
		zap.Int64("db_query_count", snapshot["db_query_count"].(int64)),
		zap.Int64("db_slow_queries", snapshot["db_slow_queries"].(int64)),
		zap.Int64("db_error_count", snapshot["db_error_count"].(int64)),
		zap.Any("request_counts", snapshot["request_counts"]),
		zap.Any("request_errors", snapshot["request_errors"]),
	)
}

// StartPeriodicLogging starts periodic logging of metrics.
func (m *Metrics) StartPeriodicLogging(ctx context.Context, logger *zap.Logger, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.LogMetrics(logger)
		case <-ctx.Done():
			return
		}
	}
}

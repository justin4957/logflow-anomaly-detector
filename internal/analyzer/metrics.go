package analyzer

import (
	"sort"
	"sync"
	"time"

	"github.com/justin4957/logflow-anomaly-detector/pkg/models"
)

// responseTimePool reuses slices for response times to reduce allocations
var responseTimePool = sync.Pool{
	New: func() interface{} {
		slice := make([]float64, 0, 1024)
		return &slice
	},
}

// MetricsCollector collects and aggregates log metrics
type MetricsCollector struct {
	windowSize         int
	currentWindow      *MetricsWindow
	historicalMetrics  []models.Metrics
	maxHistoricalSize  int
	mu                 sync.RWMutex
}

// MetricsWindow represents a time window of metrics
type MetricsWindow struct {
	startTime       time.Time
	totalRequests   int
	errorCount      int
	responseTimes   []float64
	statusCodes     map[int]int
	paths           map[string]int
	ips             map[string]int
	userAgents      map[string]int
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(windowSize int) *MetricsCollector {
	return &MetricsCollector{
		windowSize:        windowSize,
		currentWindow:     newMetricsWindow(),
		historicalMetrics: make([]models.Metrics, 0),
		maxHistoricalSize: 100,
	}
}

func newMetricsWindow() *MetricsWindow {
	// Pre-allocate maps with reasonable capacity to reduce rehashing
	return &MetricsWindow{
		startTime:     time.Now(),
		statusCodes:   make(map[int]int, 10),
		paths:         make(map[string]int, 50),
		ips:           make(map[string]int, 100),
		userAgents:    make(map[string]int, 20),
		responseTimes: make([]float64, 0, 1000),
	}
}

// AddLogEntry adds a log entry to the current window
func (mc *MetricsCollector) AddLogEntry(entry *models.LogEntry) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.currentWindow.totalRequests++

	if entry.Level == "error" || entry.StatusCode >= 400 {
		mc.currentWindow.errorCount++
	}

	if entry.StatusCode > 0 {
		mc.currentWindow.statusCodes[entry.StatusCode]++
	}

	if entry.Path != "" {
		mc.currentWindow.paths[entry.Path]++
	}

	if entry.IPAddress != "" {
		mc.currentWindow.ips[entry.IPAddress]++
	}

	if entry.UserAgent != "" {
		mc.currentWindow.userAgents[entry.UserAgent]++
	}

	if entry.ResponseTime > 0 {
		mc.currentWindow.responseTimes = append(mc.currentWindow.responseTimes, entry.ResponseTime)
	}
}

// GetCurrentMetrics returns aggregated metrics for the current window
func (mc *MetricsCollector) GetCurrentMetrics() *models.Metrics {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	metrics := mc.computeMetrics(mc.currentWindow)

	// Archive current window and start new one
	mc.historicalMetrics = append(mc.historicalMetrics, *metrics)
	if len(mc.historicalMetrics) > mc.maxHistoricalSize {
		mc.historicalMetrics = mc.historicalMetrics[1:]
	}

	mc.currentWindow = newMetricsWindow()

	return metrics
}

// GetHistoricalMetrics returns historical metrics
func (mc *MetricsCollector) GetHistoricalMetrics() []models.Metrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// Return a copy
	historical := make([]models.Metrics, len(mc.historicalMetrics))
	copy(historical, mc.historicalMetrics)
	return historical
}

func (mc *MetricsCollector) computeMetrics(window *MetricsWindow) *models.Metrics {
	duration := time.Since(window.startTime).Seconds()
	if duration == 0 {
		duration = 1
	}

	requestsPerSec := float64(window.totalRequests) / duration
	errorRate := 0.0
	if window.totalRequests > 0 {
		errorRate = float64(window.errorCount) / float64(window.totalRequests)
	}

	avgResponseTime := 0.0
	if len(window.responseTimes) > 0 {
		sum := 0.0
		for _, rt := range window.responseTimes {
			sum += rt
		}
		avgResponseTime = sum / float64(len(window.responseTimes))
	}

	return &models.Metrics{
		Timestamp:       time.Now(),
		RequestsPerSec:  requestsPerSec,
		ErrorRate:       errorRate,
		AvgResponseTime: avgResponseTime,
		StatusCodes:     window.statusCodes,
		TopPaths:        getTopPaths(window.paths, 10),
		TopIPs:          getTopIPs(window.ips, 10),
		TopUserAgents:   getTopUserAgents(window.userAgents, 10),
	}
}

func getTopPaths(paths map[string]int, limit int) []models.PathCount {
	if len(paths) == 0 {
		return nil
	}

	type kv struct {
		Key   string
		Value int
	}

	// Pre-allocate slice with exact capacity needed
	sorted := make([]kv, 0, len(paths))
	for k, v := range paths {
		sorted = append(sorted, kv{k, v})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	// Calculate actual result size
	resultSize := limit
	if len(sorted) < limit {
		resultSize = len(sorted)
	}

	result := make([]models.PathCount, resultSize)
	for i := 0; i < resultSize; i++ {
		result[i] = models.PathCount{
			Path:  sorted[i].Key,
			Count: sorted[i].Value,
		}
	}

	return result
}

func getTopIPs(ips map[string]int, limit int) []models.IPCount {
	if len(ips) == 0 {
		return nil
	}

	type kv struct {
		Key   string
		Value int
	}

	// Pre-allocate slice with exact capacity needed
	sorted := make([]kv, 0, len(ips))
	for k, v := range ips {
		sorted = append(sorted, kv{k, v})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	// Calculate actual result size
	resultSize := limit
	if len(sorted) < limit {
		resultSize = len(sorted)
	}

	result := make([]models.IPCount, resultSize)
	for i := 0; i < resultSize; i++ {
		result[i] = models.IPCount{
			IP:    sorted[i].Key,
			Count: sorted[i].Value,
		}
	}

	return result
}

func getTopUserAgents(userAgents map[string]int, limit int) []models.UserAgentCount {
	if len(userAgents) == 0 {
		return nil
	}

	type kv struct {
		Key   string
		Value int
	}

	// Pre-allocate slice with exact capacity needed
	sorted := make([]kv, 0, len(userAgents))
	for k, v := range userAgents {
		sorted = append(sorted, kv{k, v})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	// Calculate actual result size
	resultSize := limit
	if len(sorted) < limit {
		resultSize = len(sorted)
	}

	result := make([]models.UserAgentCount, resultSize)
	for i := 0; i < resultSize; i++ {
		result[i] = models.UserAgentCount{
			UserAgent: sorted[i].Key,
			Count:     sorted[i].Value,
		}
	}

	return result
}

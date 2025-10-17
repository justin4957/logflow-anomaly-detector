package analyzer

import (
	"testing"
	"time"

	"github.com/justin4957/logflow-anomaly-detector/pkg/models"
)

// createTestLogEntry creates a test log entry
func createTestLogEntry(statusCode int, path string, responseTime float64) *models.LogEntry {
	return &models.LogEntry{
		Timestamp:    time.Now(),
		IPAddress:    "192.168.1.100",
		Method:       "GET",
		Path:         path,
		StatusCode:   statusCode,
		ResponseTime: responseTime,
		UserAgent:    "Mozilla/5.0 Test Agent",
		Level:        "info",
		Message:      "Test log entry",
	}
}

// BenchmarkMetricsCollection measures metrics aggregation performance
func BenchmarkMetricsCollection(b *testing.B) {
	collector := NewMetricsCollector(1000)
	entry := createTestLogEntry(200, "/api/users", 45.3)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		collector.AddLogEntry(entry)
	}
}

// BenchmarkMetricsCollectionVariedData tests with varied log data
func BenchmarkMetricsCollectionVariedData(b *testing.B) {
	collector := NewMetricsCollector(1000)

	// Pre-generate varied test data
	entries := make([]*models.LogEntry, 100)
	paths := []string{"/api/users", "/api/products", "/api/orders", "/health", "/metrics"}
	statusCodes := []int{200, 201, 400, 404, 500}

	for i := range entries {
		entries[i] = createTestLogEntry(
			statusCodes[i%len(statusCodes)],
			paths[i%len(paths)],
			float64(10+i%100),
		)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		collector.AddLogEntry(entries[i%len(entries)])
	}
}

// BenchmarkGetCurrentMetrics measures metrics computation speed
func BenchmarkGetCurrentMetrics(b *testing.B) {
	collector := NewMetricsCollector(1000)

	// Populate with sample data
	for i := 0; i < 1000; i++ {
		collector.AddLogEntry(createTestLogEntry(200, "/api/test", 50.0))
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = collector.GetCurrentMetrics()
	}
}

// BenchmarkTopPathsCalculation measures top-N path sorting performance
func BenchmarkTopPathsCalculation(b *testing.B) {
	// Create a map with many paths
	paths := make(map[string]int)
	for i := 0; i < 1000; i++ {
		paths["/api/endpoint"+string(rune(i))] = i * 10
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = getTopPaths(paths, 10)
	}
}

// BenchmarkTopIPsCalculation measures top-N IP sorting performance
func BenchmarkTopIPsCalculation(b *testing.B) {
	// Create a map with many IPs
	ips := make(map[string]int)
	for i := 0; i < 1000; i++ {
		ips["192.168."+string(rune(i/256))+"."+string(rune(i%256))] = i * 5
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = getTopIPs(ips, 10)
	}
}

// BenchmarkConcurrentMetricsCollection tests thread-safe performance
func BenchmarkConcurrentMetricsCollection(b *testing.B) {
	collector := NewMetricsCollector(10000)
	entry := createTestLogEntry(200, "/api/test", 50.0)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			collector.AddLogEntry(entry)
		}
	})
}

// BenchmarkHistoricalMetricsRetrieval measures historical data access
func BenchmarkHistoricalMetricsRetrieval(b *testing.B) {
	collector := NewMetricsCollector(1000)

	// Generate historical data
	for i := 0; i < 100; i++ {
		for j := 0; j < 1000; j++ {
			collector.AddLogEntry(createTestLogEntry(200, "/api/test", 50.0))
		}
		collector.GetCurrentMetrics() // Archive window
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = collector.GetHistoricalMetrics()
	}
}

// BenchmarkMetricsWindowCreation measures window initialization overhead
func BenchmarkMetricsWindowCreation(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = newMetricsWindow()
	}
}

// BenchmarkFullMetricsPipeline simulates complete metrics workflow
func BenchmarkFullMetricsPipeline(b *testing.B) {
	b.Run("Add-1000-Compute", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			collector := NewMetricsCollector(1000)

			// Add 1000 log entries
			for j := 0; j < 1000; j++ {
				collector.AddLogEntry(createTestLogEntry(200, "/api/test", 50.0))
			}

			// Compute metrics
			_ = collector.GetCurrentMetrics()
		}
	})

	b.Run("Add-10000-Compute", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			collector := NewMetricsCollector(10000)

			// Add 10000 log entries
			for j := 0; j < 10000; j++ {
				collector.AddLogEntry(createTestLogEntry(200, "/api/test", 50.0))
			}

			// Compute metrics
			_ = collector.GetCurrentMetrics()
		}
	})
}

// BenchmarkStatusCodeAggregation measures map operations for status codes
func BenchmarkStatusCodeAggregation(b *testing.B) {
	collector := NewMetricsCollector(10000)
	statusCodes := []int{200, 201, 204, 400, 401, 403, 404, 500, 502, 503}

	entries := make([]*models.LogEntry, len(statusCodes))
	for i, code := range statusCodes {
		entries[i] = createTestLogEntry(code, "/api/test", 50.0)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		collector.AddLogEntry(entries[i%len(entries)])
	}
}

// BenchmarkResponseTimeTracking measures response time slice operations
func BenchmarkResponseTimeTracking(b *testing.B) {
	collector := NewMetricsCollector(10000)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		entry := createTestLogEntry(200, "/api/test", float64(i%1000))
		collector.AddLogEntry(entry)
	}
}

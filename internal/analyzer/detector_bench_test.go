package analyzer

import (
	"testing"
	"time"

	"github.com/justin4957/logflow-anomaly-detector/pkg/models"
)

// createTestMetrics creates test metrics data
func createTestMetrics(reqPerSec, errorRate, avgRespTime float64) *models.Metrics {
	return &models.Metrics{
		Timestamp:       time.Now(),
		RequestsPerSec:  reqPerSec,
		ErrorRate:       errorRate,
		AvgResponseTime: avgRespTime,
		StatusCodes: map[int]int{
			200: 900,
			404: 50,
			500: 50,
		},
		TopPaths: []models.PathCount{
			{Path: "/api/users", Count: 500},
			{Path: "/api/products", Count: 300},
		},
		TopIPs: []models.IPCount{
			{IP: "192.168.1.100", Count: 400},
			{IP: "192.168.1.101", Count: 300},
		},
		TopUserAgents: []models.UserAgentCount{
			{UserAgent: "Mozilla/5.0", Count: 600},
			{UserAgent: "Chrome/90.0", Count: 400},
		},
	}
}

// generateHistoricalMetrics creates historical baseline data
func generateHistoricalMetrics(count int) []models.Metrics {
	historical := make([]models.Metrics, count)
	for i := 0; i < count; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}
	return historical
}

// BenchmarkAnomalyDetection measures detection algorithm performance
func BenchmarkAnomalyDetection(b *testing.B) {
	detector := &StdDevDetector{threshold: 3.0}
	current := createTestMetrics(150.0, 0.08, 75.0)
	historical := generateHistoricalMetrics(50)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = detector.Detect(current, historical)
	}
}

// BenchmarkStdDevDetector measures standard deviation detection
func BenchmarkStdDevDetector(b *testing.B) {
	b.Run("SmallHistory-10", func(b *testing.B) {
		detector := &StdDevDetector{threshold: 3.0}
		current := createTestMetrics(150.0, 0.08, 75.0)
		historical := generateHistoricalMetrics(10)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = detector.Detect(current, historical)
		}
	})

	b.Run("MediumHistory-50", func(b *testing.B) {
		detector := &StdDevDetector{threshold: 3.0}
		current := createTestMetrics(150.0, 0.08, 75.0)
		historical := generateHistoricalMetrics(50)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = detector.Detect(current, historical)
		}
	})

	b.Run("LargeHistory-100", func(b *testing.B) {
		detector := &StdDevDetector{threshold: 3.0}
		current := createTestMetrics(150.0, 0.08, 75.0)
		historical := generateHistoricalMetrics(100)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = detector.Detect(current, historical)
		}
	})
}

// BenchmarkCalculateStats measures statistical calculation performance
func BenchmarkCalculateStats(b *testing.B) {
	historical := generateHistoricalMetrics(100)

	b.Run("ErrorRate", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = calculateStats(historical, func(m models.Metrics) float64 {
				return m.ErrorRate
			})
		}
	})

	b.Run("RequestsPerSec", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = calculateStats(historical, func(m models.Metrics) float64 {
				return m.RequestsPerSec
			})
		}
	})

	b.Run("ResponseTime", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = calculateStats(historical, func(m models.Metrics) float64 {
				return m.AvgResponseTime
			})
		}
	})
}

// BenchmarkCalculateSeverity measures severity calculation overhead
func BenchmarkCalculateSeverity(b *testing.B) {
	testCases := []struct {
		name     string
		actual   float64
		expected float64
		stdDev   float64
	}{
		{"Low", 100.0, 95.0, 10.0},
		{"Medium", 120.0, 95.0, 10.0},
		{"High", 135.0, 95.0, 10.0},
		{"Critical", 150.0, 95.0, 10.0},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = calculateSeverity(tc.actual, tc.expected, tc.stdDev)
			}
		})
	}
}

// BenchmarkAnomalyDetectionWithAllocation tracks memory allocations
func BenchmarkAnomalyDetectionWithAllocation(b *testing.B) {
	detector := &StdDevDetector{threshold: 3.0}

	b.Run("NoAnomaly", func(b *testing.B) {
		current := createTestMetrics(100.0, 0.05, 50.0)
		historical := generateHistoricalMetrics(50)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = detector.Detect(current, historical)
		}
	})

	b.Run("SingleAnomaly", func(b *testing.B) {
		current := createTestMetrics(200.0, 0.05, 50.0)
		historical := generateHistoricalMetrics(50)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = detector.Detect(current, historical)
		}
	})

	b.Run("MultipleAnomalies", func(b *testing.B) {
		current := createTestMetrics(200.0, 0.15, 150.0)
		historical := generateHistoricalMetrics(50)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = detector.Detect(current, historical)
		}
	})
}

// BenchmarkDetectorThresholdVariations tests different threshold sensitivities
func BenchmarkDetectorThresholdVariations(b *testing.B) {
	current := createTestMetrics(150.0, 0.08, 75.0)
	historical := generateHistoricalMetrics(50)

	thresholds := []float64{2.0, 3.0, 4.0, 5.0}

	for _, threshold := range thresholds {
		b.Run("Threshold-"+string(rune(int(threshold))), func(b *testing.B) {
			detector := &StdDevDetector{threshold: threshold}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = detector.Detect(current, historical)
			}
		})
	}
}

// BenchmarkEndToEndDetectionPipeline simulates complete detection workflow
func BenchmarkEndToEndDetectionPipeline(b *testing.B) {
	b.Run("1000-Entries", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			collector := NewMetricsCollector(1000)
			detector := &StdDevDetector{threshold: 3.0}

			// Simulate log ingestion
			for j := 0; j < 1000; j++ {
				entry := createTestLogEntry(200, "/api/test", 50.0)
				collector.AddLogEntry(entry)
			}

			// Compute metrics
			current := collector.GetCurrentMetrics()

			// Generate baseline
			historical := generateHistoricalMetrics(50)

			// Detect anomalies
			_ = detector.Detect(current, historical)
		}
	})

	b.Run("10000-Entries", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			collector := NewMetricsCollector(10000)
			detector := &StdDevDetector{threshold: 3.0}

			// Simulate log ingestion
			for j := 0; j < 10000; j++ {
				entry := createTestLogEntry(200, "/api/test", 50.0)
				collector.AddLogEntry(entry)
			}

			// Compute metrics
			current := collector.GetCurrentMetrics()

			// Generate baseline
			historical := generateHistoricalMetrics(50)

			// Detect anomalies
			_ = detector.Detect(current, historical)
		}
	})
}

// BenchmarkParallelAnomalyDetection tests concurrent detection performance
func BenchmarkParallelAnomalyDetection(b *testing.B) {
	detector := &StdDevDetector{threshold: 3.0}
	current := createTestMetrics(150.0, 0.08, 75.0)
	historical := generateHistoricalMetrics(50)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = detector.Detect(current, historical)
		}
	})
}

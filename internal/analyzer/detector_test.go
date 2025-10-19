package analyzer

import (
	"testing"
	"time"

	"github.com/justin4957/logflow-anomaly-detector/pkg/models"
)

// createTestLogEntry creates a test log entry for testing
func createTestLogEntry(statusCode int, path string, responseTime float64) *models.LogEntry {
	return &models.LogEntry{
		Timestamp:    time.Now(),
		Level:        "info",
		Message:      "test message",
		StatusCode:   statusCode,
		Path:         path,
		ResponseTime: responseTime,
		IPAddress:    "192.168.1.1",
		UserAgent:    "TestAgent/1.0",
	}
}

// TestMovingAverageDetector_ColdStart tests behavior with insufficient data
func TestMovingAverageDetector_ColdStart(t *testing.T) {
	detector := NewMovingAverageDetector(1.0, 0.3)
	current := createTestMetrics(100.0, 0.05, 50.0)

	// Test with insufficient historical data
	historical := generateHistoricalMetrics(3)
	anomalies := detector.Detect(current, historical)

	if len(anomalies) != 0 {
		t.Errorf("Expected no anomalies with insufficient data, got %d", len(anomalies))
	}

	if detector.initialized {
		t.Error("Detector should not be initialized with insufficient data")
	}
}

// TestMovingAverageDetector_Initialization tests EWMA initialization
func TestMovingAverageDetector_Initialization(t *testing.T) {
	detector := NewMovingAverageDetector(1.0, 0.3)
	current := createTestMetrics(100.0, 0.05, 50.0)

	// Create baseline with consistent values
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	_ = detector.Detect(current, historical)

	if !detector.initialized {
		t.Error("Detector should be initialized after processing sufficient data")
	}

	// Check that EWMA values are initialized to baseline means
	expectedErrorRate := 0.05
	expectedRequestsPerSec := 100.0
	expectedResponseTime := 50.0

	if detector.ewmaErrorRate != expectedErrorRate {
		t.Errorf("Expected EWMA error rate %f, got %f", expectedErrorRate, detector.ewmaErrorRate)
	}
	if detector.ewmaRequestsPerSec != expectedRequestsPerSec {
		t.Errorf("Expected EWMA requests per sec %f, got %f", expectedRequestsPerSec, detector.ewmaRequestsPerSec)
	}
	if detector.ewmaAvgResponseTime != expectedResponseTime {
		t.Errorf("Expected EWMA response time %f, got %f", expectedResponseTime, detector.ewmaAvgResponseTime)
	}
}

// TestMovingAverageDetector_ErrorRateAnomaly tests error rate anomaly detection
func TestMovingAverageDetector_ErrorRateAnomaly(t *testing.T) {
	detector := NewMovingAverageDetector(0.5, 0.3)

	// Create stable baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize detector with baseline
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Create anomalous error rate (spike from 0.05 to 0.15)
	current := createTestMetrics(100.0, 0.15, 50.0)
	anomalies := detector.Detect(current, historical)

	// Should detect error rate anomaly
	foundErrorRateAnomaly := false
	for _, anomaly := range anomalies {
		if anomaly.Type == models.AnomalyTypeErrorRate {
			foundErrorRateAnomaly = true
			if anomaly.ActualValue != 0.15 {
				t.Errorf("Expected actual value 0.15, got %f", anomaly.ActualValue)
			}
		}
	}

	if !foundErrorRateAnomaly {
		t.Error("Expected to detect error rate anomaly")
	}
}

// TestMovingAverageDetector_TrafficSpikeAnomaly tests traffic spike detection
func TestMovingAverageDetector_TrafficSpikeAnomaly(t *testing.T) {
	detector := NewMovingAverageDetector(0.5, 0.3)

	// Create stable baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize detector
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Create traffic spike (from 100 to 300 requests/sec)
	current := createTestMetrics(300.0, 0.05, 50.0)
	anomalies := detector.Detect(current, historical)

	// Should detect traffic spike
	foundTrafficAnomaly := false
	for _, anomaly := range anomalies {
		if anomaly.Type == models.AnomalyTypeTrafficSpike {
			foundTrafficAnomaly = true
			if anomaly.ActualValue != 300.0 {
				t.Errorf("Expected actual value 300.0, got %f", anomaly.ActualValue)
			}
		}
	}

	if !foundTrafficAnomaly {
		t.Error("Expected to detect traffic spike anomaly")
	}
}

// TestMovingAverageDetector_ResponseTimeAnomaly tests response time detection
func TestMovingAverageDetector_ResponseTimeAnomaly(t *testing.T) {
	detector := NewMovingAverageDetector(0.5, 0.3)

	// Create stable baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize detector
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Create response time spike (from 50ms to 150ms)
	current := createTestMetrics(100.0, 0.05, 150.0)
	anomalies := detector.Detect(current, historical)

	// Should detect response time anomaly
	foundResponseTimeAnomaly := false
	for _, anomaly := range anomalies {
		if anomaly.Type == models.AnomalyTypeResponseTime {
			foundResponseTimeAnomaly = true
			if anomaly.ActualValue != 150.0 {
				t.Errorf("Expected actual value 150.0, got %f", anomaly.ActualValue)
			}
		}
	}

	if !foundResponseTimeAnomaly {
		t.Error("Expected to detect response time anomaly")
	}
}

// TestMovingAverageDetector_AdaptToSlowChanges tests baseline adaptation
func TestMovingAverageDetector_AdaptToSlowChanges(t *testing.T) {
	detector := NewMovingAverageDetector(0.5, 0.3)

	// Create baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize with baseline
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)
	initialEWMA := detector.ewmaRequestsPerSec

	// Gradually increase traffic over multiple observations
	for i := 0; i < 20; i++ {
		currentRequestRate := 100.0 + float64(i)*2.0 // Slowly increase
		current := createTestMetrics(currentRequestRate, 0.05, 50.0)
		_ = detector.Detect(current, historical)
	}

	// EWMA should have adapted to new baseline
	if detector.ewmaRequestsPerSec <= initialEWMA {
		t.Errorf("EWMA should have adapted upward, initial: %f, current: %f",
			initialEWMA, detector.ewmaRequestsPerSec)
	}
}

// TestMovingAverageDetector_SmoothingFactorEffect tests alpha parameter
func TestMovingAverageDetector_SmoothingFactorEffect(t *testing.T) {
	testCases := []struct {
		name  string
		alpha float64
	}{
		{"HighAlpha", 0.7},   // More responsive to recent changes
		{"MediumAlpha", 0.3}, // Balanced
		{"LowAlpha", 0.1},    // More weight on historical values
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detector := NewMovingAverageDetector(0.5, tc.alpha)

			// Create baseline
			historical := make([]models.Metrics, 10)
			for i := 0; i < 10; i++ {
				historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
			}

			// Initialize
			_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

			// Verify alpha is set correctly
			if detector.alpha != tc.alpha {
				t.Errorf("Expected alpha %f, got %f", tc.alpha, detector.alpha)
			}

			// Apply one update with a different value
			current := createTestMetrics(150.0, 0.05, 50.0)
			_ = detector.Detect(current, historical)

			// The EWMA should reflect the alpha parameter's influence
			// Higher alpha means more weight on recent observation
			expectedEWMA := tc.alpha*150.0 + (1-tc.alpha)*100.0
			if detector.ewmaRequestsPerSec != expectedEWMA {
				t.Errorf("Expected EWMA %f, got %f", expectedEWMA, detector.ewmaRequestsPerSec)
			}
		})
	}
}

// TestMovingAverageDetector_NoAnomalyOnStableMetrics tests no false positives
func TestMovingAverageDetector_NoAnomalyOnStableMetrics(t *testing.T) {
	detector := NewMovingAverageDetector(1.0, 0.3)

	// Create stable baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Test with stable metrics (small natural variation)
	current := createTestMetrics(102.0, 0.051, 51.0)
	anomalies := detector.Detect(current, historical)

	if len(anomalies) != 0 {
		t.Errorf("Expected no anomalies on stable metrics, got %d", len(anomalies))
	}
}

// TestMovingAverageDetector_InvalidAlpha tests alpha parameter validation
func TestMovingAverageDetector_InvalidAlpha(t *testing.T) {
	testCases := []struct {
		name          string
		alpha         float64
		expectedAlpha float64
	}{
		{"ZeroAlpha", 0.0, 0.3},
		{"NegativeAlpha", -0.5, 0.3},
		{"AlphaEqualOne", 1.0, 0.3},
		{"AlphaGreaterThanOne", 1.5, 0.3},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detector := NewMovingAverageDetector(1.0, tc.alpha)
			if detector.alpha != tc.expectedAlpha {
				t.Errorf("Expected alpha to default to %f, got %f", tc.expectedAlpha, detector.alpha)
			}
		})
	}
}

// TestMovingAverageDetector_SeverityLevels tests anomaly severity calculation
func TestMovingAverageDetector_SeverityLevels(t *testing.T) {
	detector := NewMovingAverageDetector(0.1, 0.3) // Low threshold for easier detection

	// Create baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	testCases := []struct {
		name             string
		requestsPerSec   float64
		expectedSeverity models.Severity
	}{
		{"MediumDeviation", 180.0, models.SeverityMedium},
		{"HighDeviation", 250.0, models.SeverityHigh},
		{"CriticalDeviation", 400.0, models.SeverityCritical},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset detector state
			detector = NewMovingAverageDetector(0.1, 0.3)
			_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

			current := createTestMetrics(tc.requestsPerSec, 0.05, 50.0)
			anomalies := detector.Detect(current, historical)

			if len(anomalies) == 0 {
				t.Errorf("Expected anomaly for %s", tc.name)
				return
			}

			for _, anomaly := range anomalies {
				if anomaly.Type == models.AnomalyTypeTrafficSpike {
					if anomaly.Severity != tc.expectedSeverity {
						t.Errorf("Expected severity %s, got %s", tc.expectedSeverity, anomaly.Severity)
					}
				}
			}
		})
	}
}

// TestMovingAverageDetector_MultipleAnomaliesSimultaneous tests concurrent anomalies
func TestMovingAverageDetector_MultipleAnomaliesSimultaneous(t *testing.T) {
	detector := NewMovingAverageDetector(0.5, 0.3)

	// Create baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Create metrics with multiple anomalies
	current := createTestMetrics(300.0, 0.15, 150.0)
	anomalies := detector.Detect(current, historical)

	// Should detect all three types of anomalies
	anomalyTypes := make(map[models.AnomalyType]bool)
	for _, anomaly := range anomalies {
		anomalyTypes[anomaly.Type] = true
	}

	expectedTypes := []models.AnomalyType{
		models.AnomalyTypeErrorRate,
		models.AnomalyTypeTrafficSpike,
		models.AnomalyTypeResponseTime,
	}

	for _, expectedType := range expectedTypes {
		if !anomalyTypes[expectedType] {
			t.Errorf("Expected to detect %s anomaly", expectedType)
		}
	}
}

// CUSUM Detector Tests

// TestCUSUMDetector_ColdStart tests behavior with insufficient data
func TestCUSUMDetector_ColdStart(t *testing.T) {
	detector := NewCUSUMDetector(0.5, 5.0)
	current := createTestMetrics(100.0, 0.05, 50.0)

	// Test with insufficient historical data
	historical := generateHistoricalMetrics(3)
	anomalies := detector.Detect(current, historical)

	if len(anomalies) != 0 {
		t.Errorf("Expected no anomalies with insufficient data, got %d", len(anomalies))
	}

	if detector.initialized {
		t.Error("Detector should not be initialized with insufficient data")
	}
}

// TestCUSUMDetector_Initialization tests reference value initialization
func TestCUSUMDetector_Initialization(t *testing.T) {
	detector := NewCUSUMDetector(0.5, 5.0)
	current := createTestMetrics(100.0, 0.05, 50.0)

	// Create baseline with consistent values
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	_ = detector.Detect(current, historical)

	if !detector.initialized {
		t.Error("Detector should be initialized after processing sufficient data")
	}

	// Check that reference values are initialized to baseline means
	expectedErrorRate := 0.05
	expectedRequestsPerSec := 100.0
	expectedResponseTime := 50.0

	if detector.referenceErrorRate != expectedErrorRate {
		t.Errorf("Expected reference error rate %f, got %f", expectedErrorRate, detector.referenceErrorRate)
	}
	if detector.referenceRequestsPerSec != expectedRequestsPerSec {
		t.Errorf("Expected reference requests per sec %f, got %f", expectedRequestsPerSec, detector.referenceRequestsPerSec)
	}
	if detector.referenceResponseTime != expectedResponseTime {
		t.Errorf("Expected reference response time %f, got %f", expectedResponseTime, detector.referenceResponseTime)
	}
}

// TestCUSUMDetector_UpwardShiftDetection tests detection of upward metric shifts
func TestCUSUMDetector_UpwardShiftDetection(t *testing.T) {
	detector := NewCUSUMDetector(0.5, 5.0)

	// Create stable baseline at 100 requests/sec
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize detector with baseline
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Simulate persistent upward shift (small increases that accumulate)
	// Each step is small (110 vs 100), but persistent
	for i := 0; i < 15; i++ {
		current := createTestMetrics(110.0, 0.05, 50.0)
		anomalies := detector.Detect(current, historical)

		// Should eventually detect the persistent upward shift
		if len(anomalies) > 0 {
			foundTrafficAnomaly := false
			for _, anomaly := range anomalies {
				if anomaly.Type == models.AnomalyTypeTrafficSpike {
					foundTrafficAnomaly = true
					if anomaly.Description != "Persistent traffic pattern change detected (upward shift)" {
						t.Errorf("Expected upward shift description, got %s", anomaly.Description)
					}
				}
			}
			if foundTrafficAnomaly {
				return // Test passed - detected upward shift
			}
		}
	}

	t.Error("Expected to detect persistent upward shift in traffic")
}

// TestCUSUMDetector_DownwardShiftDetection tests detection of downward metric shifts
func TestCUSUMDetector_DownwardShiftDetection(t *testing.T) {
	detector := NewCUSUMDetector(0.5, 5.0)

	// Create stable baseline at 100 requests/sec
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize detector
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Simulate persistent downward shift
	for i := 0; i < 15; i++ {
		current := createTestMetrics(90.0, 0.05, 50.0)
		anomalies := detector.Detect(current, historical)

		// Should eventually detect the persistent downward shift
		if len(anomalies) > 0 {
			foundTrafficAnomaly := false
			for _, anomaly := range anomalies {
				if anomaly.Type == models.AnomalyTypeTrafficSpike {
					foundTrafficAnomaly = true
					if anomaly.Description != "Persistent traffic pattern change detected (downward shift)" {
						t.Errorf("Expected downward shift description, got %s", anomaly.Description)
					}
				}
			}
			if foundTrafficAnomaly {
				return // Test passed - detected downward shift
			}
		}
	}

	t.Error("Expected to detect persistent downward shift in traffic")
}

// TestCUSUMDetector_ErrorRateShiftDetection tests error rate anomaly detection
func TestCUSUMDetector_ErrorRateShiftDetection(t *testing.T) {
	detector := NewCUSUMDetector(0.01, 3.0) // More sensitive for error rates

	// Create stable baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize detector
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Simulate persistent error rate increase (small but consistent)
	for i := 0; i < 10; i++ {
		current := createTestMetrics(100.0, 0.08, 50.0) // Error rate: 0.05 -> 0.08
		anomalies := detector.Detect(current, historical)

		if len(anomalies) > 0 {
			for _, anomaly := range anomalies {
				if anomaly.Type == models.AnomalyTypeErrorRate {
					if anomaly.ActualValue != 0.08 {
						t.Errorf("Expected actual error rate 0.08, got %f", anomaly.ActualValue)
					}
					return // Test passed
				}
			}
		}
	}

	t.Error("Expected to detect persistent error rate shift")
}

// TestCUSUMDetector_ResponseTimeShiftDetection tests response time anomaly detection
func TestCUSUMDetector_ResponseTimeShiftDetection(t *testing.T) {
	detector := NewCUSUMDetector(1.0, 4.0)

	// Create stable baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize detector
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Simulate persistent response time increase
	for i := 0; i < 10; i++ {
		current := createTestMetrics(100.0, 0.05, 60.0) // Response time: 50ms -> 60ms
		anomalies := detector.Detect(current, historical)

		if len(anomalies) > 0 {
			for _, anomaly := range anomalies {
				if anomaly.Type == models.AnomalyTypeResponseTime {
					if anomaly.ActualValue != 60.0 {
						t.Errorf("Expected actual response time 60.0, got %f", anomaly.ActualValue)
					}
					return // Test passed
				}
			}
		}
	}

	t.Error("Expected to detect persistent response time shift")
}

// TestCUSUMDetector_ResetAfterDetection tests that CUSUM resets after anomaly
func TestCUSUMDetector_ResetAfterDetection(t *testing.T) {
	detector := NewCUSUMDetector(0.5, 5.0)

	// Create baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Force cumulative sum to build up and trigger anomaly
	for i := 0; i < 20; i++ {
		current := createTestMetrics(110.0, 0.05, 50.0)
		anomalies := detector.Detect(current, historical)

		if len(anomalies) > 0 {
			// After anomaly detection, CUSUM should be reset
			if detector.cusumPosRequestsPerSec != 0 || detector.cusumNegRequestsPerSec != 0 {
				t.Error("CUSUM values should be reset to 0 after anomaly detection")
			}
			return
		}
	}
}

// TestCUSUMDetector_NoAnomalyOnStableMetrics tests no false positives
func TestCUSUMDetector_NoAnomalyOnStableMetrics(t *testing.T) {
	detector := NewCUSUMDetector(0.5, 5.0)

	// Create stable baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Test with stable metrics (within slack parameter tolerance)
	for i := 0; i < 20; i++ {
		current := createTestMetrics(100.2, 0.051, 50.1) // Very small variations
		anomalies := detector.Detect(current, historical)

		if len(anomalies) != 0 {
			t.Errorf("Expected no anomalies on stable metrics, got %d", len(anomalies))
		}
	}
}

// TestCUSUMDetector_ParameterValidation tests parameter defaults
func TestCUSUMDetector_ParameterValidation(t *testing.T) {
	testCases := []struct {
		name              string
		slack             float64
		threshold         float64
		expectedSlack     float64
		expectedThreshold float64
	}{
		{"ZeroSlack", 0.0, 5.0, 0.5, 5.0},
		{"NegativeSlack", -0.5, 5.0, 0.5, 5.0},
		{"ZeroThreshold", 0.5, 0.0, 0.5, 5.0},
		{"NegativeThreshold", 0.5, -1.0, 0.5, 5.0},
		{"ValidParameters", 1.0, 10.0, 1.0, 10.0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			detector := NewCUSUMDetector(tc.slack, tc.threshold)
			if detector.slackParameter != tc.expectedSlack {
				t.Errorf("Expected slack %f, got %f", tc.expectedSlack, detector.slackParameter)
			}
			if detector.decisionThreshold != tc.expectedThreshold {
				t.Errorf("Expected threshold %f, got %f", tc.expectedThreshold, detector.decisionThreshold)
			}
		})
	}
}

// TestCUSUMDetector_SeverityLevels tests anomaly severity calculation
func TestCUSUMDetector_SeverityLevels(t *testing.T) {
	// Use very low threshold to trigger anomalies more easily for testing
	detector := NewCUSUMDetector(0.1, 1.0)

	// Create baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Force a large shift to build up CUSUM quickly
	// The severity depends on CUSUM value relative to threshold
	for i := 0; i < 20; i++ {
		current := createTestMetrics(120.0, 0.05, 50.0)
		anomalies := detector.Detect(current, historical)

		if len(anomalies) > 0 {
			// Just verify that severity is calculated
			for _, anomaly := range anomalies {
				if anomaly.Severity == "" {
					t.Error("Anomaly should have a severity level")
				}
			}
			return
		}
	}
}

// TestCUSUMDetector_MultipleMetricShifts tests detecting shifts in multiple metrics
func TestCUSUMDetector_MultipleMetricShifts(t *testing.T) {
	detector := NewCUSUMDetector(0.5, 4.0)

	// Create baseline
	historical := make([]models.Metrics, 10)
	for i := 0; i < 10; i++ {
		historical[i] = *createTestMetrics(100.0, 0.05, 50.0)
	}

	// Initialize
	_ = detector.Detect(createTestMetrics(100.0, 0.05, 50.0), historical)

	// Apply shifts to all metrics simultaneously
	foundAnomalies := make(map[models.AnomalyType]bool)

	for i := 0; i < 20; i++ {
		// All metrics shifted
		current := createTestMetrics(115.0, 0.08, 60.0)
		anomalies := detector.Detect(current, historical)

		for _, anomaly := range anomalies {
			foundAnomalies[anomaly.Type] = true
		}

		// Check if we've detected all three types
		if len(foundAnomalies) == 3 {
			return // Successfully detected all shifts
		}
	}

	// Verify we detected at least some anomalies
	if len(foundAnomalies) == 0 {
		t.Error("Expected to detect at least one type of anomaly with multiple metric shifts")
	}
}

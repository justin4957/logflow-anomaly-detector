package analyzer

import (
	"context"
	"math"
	"time"

	"github.com/justin4957/logflow-anomaly-detector/internal/config"
	"github.com/justin4957/logflow-anomaly-detector/pkg/models"
)

// AnomalyDetector detects anomalies in log streams
type AnomalyDetector struct {
	config           config.DetectorConfig
	metricsCollector *MetricsCollector
	algorithm        DetectionAlgorithm
}

// DetectionAlgorithm interface for different detection strategies
type DetectionAlgorithm interface {
	Detect(metrics *models.Metrics, historical []models.Metrics) []models.Anomaly
}

// NewAnomalyDetector creates a new anomaly detector
func NewAnomalyDetector(cfg config.DetectorConfig) *AnomalyDetector {
	var algo DetectionAlgorithm
	switch cfg.Algorithm {
	case "moving_average":
		algo = &MovingAverageDetector{threshold: cfg.SensitivityLevel}
	case "cusum":
		algo = &CUSUMDetector{threshold: cfg.SensitivityLevel}
	default:
		algo = &StdDevDetector{threshold: cfg.SensitivityLevel}
	}

	return &AnomalyDetector{
		config:           cfg,
		metricsCollector: NewMetricsCollector(cfg.WindowSize),
		algorithm:        algo,
	}
}

// Start begins anomaly detection
func (ad *AnomalyDetector) Start(ctx context.Context, input <-chan interface{}, output chan<- interface{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case logEntry, ok := <-input:
			if !ok {
				return
			}
			if entry, ok := logEntry.(*models.LogEntry); ok {
				ad.metricsCollector.AddLogEntry(entry)
			}
		case <-ticker.C:
			// Compute current metrics
			metrics := ad.metricsCollector.GetCurrentMetrics()
			historical := ad.metricsCollector.GetHistoricalMetrics()

			// Detect anomalies
			anomalies := ad.algorithm.Detect(metrics, historical)

			// Send metrics and anomalies to dashboard
			output <- metrics
			for _, anomaly := range anomalies {
				output <- anomaly
			}
		}
	}
}

// StdDevDetector uses standard deviation for anomaly detection
type StdDevDetector struct {
	threshold float64
}

func (d *StdDevDetector) Detect(current *models.Metrics, historical []models.Metrics) []models.Anomaly {
	anomalies := []models.Anomaly{}

	if len(historical) < 10 {
		return anomalies // Not enough data for baseline
	}

	// Check error rate
	errorRateMean, errorRateStdDev := calculateStats(historical, func(m models.Metrics) float64 {
		return m.ErrorRate
	})

	if math.Abs(current.ErrorRate-errorRateMean) > d.threshold*errorRateStdDev {
		anomalies = append(anomalies, models.Anomaly{
			Timestamp:     time.Now(),
			Type:          models.AnomalyTypeErrorRate,
			Severity:      calculateSeverity(current.ErrorRate, errorRateMean, errorRateStdDev),
			Description:   "Abnormal error rate detected",
			Metric:        "error_rate",
			ActualValue:   current.ErrorRate,
			ExpectedValue: errorRateMean,
			Deviation:     math.Abs(current.ErrorRate - errorRateMean),
		})
	}

	// Check request rate
	reqRateMean, reqRateStdDev := calculateStats(historical, func(m models.Metrics) float64 {
		return m.RequestsPerSec
	})

	if math.Abs(current.RequestsPerSec-reqRateMean) > d.threshold*reqRateStdDev {
		anomalies = append(anomalies, models.Anomaly{
			Timestamp:     time.Now(),
			Type:          models.AnomalyTypeTrafficSpike,
			Severity:      calculateSeverity(current.RequestsPerSec, reqRateMean, reqRateStdDev),
			Description:   "Traffic spike or drop detected",
			Metric:        "requests_per_sec",
			ActualValue:   current.RequestsPerSec,
			ExpectedValue: reqRateMean,
			Deviation:     math.Abs(current.RequestsPerSec - reqRateMean),
		})
	}

	// Check response time
	respTimeMean, respTimeStdDev := calculateStats(historical, func(m models.Metrics) float64 {
		return m.AvgResponseTime
	})

	if current.AvgResponseTime > respTimeMean+d.threshold*respTimeStdDev {
		anomalies = append(anomalies, models.Anomaly{
			Timestamp:     time.Now(),
			Type:          models.AnomalyTypeResponseTime,
			Severity:      calculateSeverity(current.AvgResponseTime, respTimeMean, respTimeStdDev),
			Description:   "Response time degradation detected",
			Metric:        "avg_response_time",
			ActualValue:   current.AvgResponseTime,
			ExpectedValue: respTimeMean,
			Deviation:     current.AvgResponseTime - respTimeMean,
		})
	}

	return anomalies
}

// MovingAverageDetector uses moving average for detection
type MovingAverageDetector struct {
	threshold float64
}

func (d *MovingAverageDetector) Detect(current *models.Metrics, historical []models.Metrics) []models.Anomaly {
	// TODO: Implement moving average based detection
	return []models.Anomaly{}
}

// CUSUMDetector uses CUSUM algorithm for detection
type CUSUMDetector struct {
	threshold float64
}

func (d *CUSUMDetector) Detect(current *models.Metrics, historical []models.Metrics) []models.Anomaly {
	// TODO: Implement CUSUM algorithm
	return []models.Anomaly{}
}

// Helper functions
func calculateStats(metrics []models.Metrics, getValue func(models.Metrics) float64) (mean, stdDev float64) {
	if len(metrics) == 0 {
		return 0, 0
	}

	sum := 0.0
	for _, m := range metrics {
		sum += getValue(m)
	}
	mean = sum / float64(len(metrics))

	variance := 0.0
	for _, m := range metrics {
		diff := getValue(m) - mean
		variance += diff * diff
	}
	stdDev = math.Sqrt(variance / float64(len(metrics)))

	return mean, stdDev
}

func calculateSeverity(actual, expected, stdDev float64) models.Severity {
	deviation := math.Abs(actual - expected)
	if deviation > 4*stdDev {
		return models.SeverityCritical
	} else if deviation > 3*stdDev {
		return models.SeverityHigh
	} else if deviation > 2*stdDev {
		return models.SeverityMedium
	}
	return models.SeverityLow
}

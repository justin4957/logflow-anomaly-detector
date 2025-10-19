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
		algo = NewMovingAverageDetector(cfg.SensitivityLevel, cfg.SmoothingFactor)
	case "cusum":
		algo = NewCUSUMDetector(cfg.CUSUMSlack, cfg.CUSUMThreshold)
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

// MovingAverageDetector uses exponentially weighted moving average for detection
type MovingAverageDetector struct {
	threshold              float64
	alpha                  float64 // smoothing factor
	ewmaErrorRate          float64
	ewmaRequestsPerSec     float64
	ewmaAvgResponseTime    float64
	initialized            bool
}

// NewMovingAverageDetector creates a new moving average detector with configurable alpha
func NewMovingAverageDetector(threshold, alpha float64) *MovingAverageDetector {
	// Default alpha to 0.3 if not specified (gives more weight to recent observations)
	if alpha <= 0 || alpha >= 1 {
		alpha = 0.3
	}
	return &MovingAverageDetector{
		threshold:   threshold,
		alpha:       alpha,
		initialized: false,
	}
}

func (d *MovingAverageDetector) Detect(current *models.Metrics, historical []models.Metrics) []models.Anomaly {
	anomalies := []models.Anomaly{}

	// Handle cold start - need at least some historical data to establish baseline
	if !d.initialized {
		if len(historical) < 5 {
			return anomalies // Not enough data for baseline
		}
		// Initialize EWMA with mean of first few historical values
		d.initializeEWMA(historical)
		d.initialized = true
	}

	// Update EWMA with current values and check for anomalies
	// EWMA formula: EWMA(t) = α × value(t) + (1 - α) × EWMA(t-1)

	// Check error rate
	previousEWMAErrorRate := d.ewmaErrorRate
	d.ewmaErrorRate = d.alpha*current.ErrorRate + (1-d.alpha)*d.ewmaErrorRate
	deviation := math.Abs(current.ErrorRate - previousEWMAErrorRate)

	if deviation > d.threshold*previousEWMAErrorRate && previousEWMAErrorRate > 0.01 {
		anomalies = append(anomalies, models.Anomaly{
			Timestamp:     time.Now(),
			Type:          models.AnomalyTypeErrorRate,
			Severity:      calculateEWMASeverity(deviation, previousEWMAErrorRate),
			Description:   "Abnormal error rate detected",
			Metric:        "error_rate",
			ActualValue:   current.ErrorRate,
			ExpectedValue: previousEWMAErrorRate,
			Deviation:     deviation,
		})
	}

	// Check request rate
	previousEWMARequestsPerSec := d.ewmaRequestsPerSec
	d.ewmaRequestsPerSec = d.alpha*current.RequestsPerSec + (1-d.alpha)*d.ewmaRequestsPerSec
	deviation = math.Abs(current.RequestsPerSec - previousEWMARequestsPerSec)

	if deviation > d.threshold*previousEWMARequestsPerSec && previousEWMARequestsPerSec > 0 {
		anomalies = append(anomalies, models.Anomaly{
			Timestamp:     time.Now(),
			Type:          models.AnomalyTypeTrafficSpike,
			Severity:      calculateEWMASeverity(deviation, previousEWMARequestsPerSec),
			Description:   "Traffic spike or drop detected",
			Metric:        "requests_per_sec",
			ActualValue:   current.RequestsPerSec,
			ExpectedValue: previousEWMARequestsPerSec,
			Deviation:     deviation,
		})
	}

	// Check response time (only alert on increases, not decreases)
	previousEWMAResponseTime := d.ewmaAvgResponseTime
	d.ewmaAvgResponseTime = d.alpha*current.AvgResponseTime + (1-d.alpha)*d.ewmaAvgResponseTime
	deviation = current.AvgResponseTime - previousEWMAResponseTime

	if deviation > d.threshold*previousEWMAResponseTime && previousEWMAResponseTime > 0 {
		anomalies = append(anomalies, models.Anomaly{
			Timestamp:     time.Now(),
			Type:          models.AnomalyTypeResponseTime,
			Severity:      calculateEWMASeverity(deviation, previousEWMAResponseTime),
			Description:   "Response time degradation detected",
			Metric:        "avg_response_time",
			ActualValue:   current.AvgResponseTime,
			ExpectedValue: previousEWMAResponseTime,
			Deviation:     deviation,
		})
	}

	return anomalies
}

// initializeEWMA sets initial EWMA values using mean of historical data
func (d *MovingAverageDetector) initializeEWMA(historical []models.Metrics) {
	if len(historical) == 0 {
		return
	}

	sumErrorRate := 0.0
	sumRequestsPerSec := 0.0
	sumAvgResponseTime := 0.0

	for _, m := range historical {
		sumErrorRate += m.ErrorRate
		sumRequestsPerSec += m.RequestsPerSec
		sumAvgResponseTime += m.AvgResponseTime
	}

	count := float64(len(historical))
	d.ewmaErrorRate = sumErrorRate / count
	d.ewmaRequestsPerSec = sumRequestsPerSec / count
	d.ewmaAvgResponseTime = sumAvgResponseTime / count
}

// calculateEWMASeverity determines severity based on relative deviation
func calculateEWMASeverity(deviation, expected float64) models.Severity {
	if expected == 0 {
		return models.SeverityLow
	}

	relativeDeviation := deviation / expected
	if relativeDeviation > 2.0 {
		return models.SeverityCritical
	} else if relativeDeviation > 1.0 {
		return models.SeverityHigh
	} else if relativeDeviation > 0.5 {
		return models.SeverityMedium
	}
	return models.SeverityLow
}

// CUSUMDetector uses CUSUM (Cumulative Sum) algorithm for detecting subtle shifts
type CUSUMDetector struct {
	slackParameter     float64 // k: allowable deviation from mean
	decisionThreshold  float64 // h: threshold for triggering anomaly

	// State tracking for each metric - positive and negative cumulative sums
	cusumPosErrorRate      float64
	cusumNegErrorRate      float64
	cusumPosRequestsPerSec float64
	cusumNegRequestsPerSec float64
	cusumPosResponseTime   float64
	cusumNegResponseTime   float64

	// Reference values (target means) for each metric
	referenceErrorRate      float64
	referenceRequestsPerSec float64
	referenceResponseTime   float64

	initialized bool
}

// NewCUSUMDetector creates a new CUSUM detector with configurable parameters
func NewCUSUMDetector(slackParameter, decisionThreshold float64) *CUSUMDetector {
	// Default values if not specified
	if slackParameter <= 0 {
		slackParameter = 0.5
	}
	if decisionThreshold <= 0 {
		decisionThreshold = 5.0
	}

	return &CUSUMDetector{
		slackParameter:    slackParameter,
		decisionThreshold: decisionThreshold,
		initialized:       false,
	}
}

func (d *CUSUMDetector) Detect(current *models.Metrics, historical []models.Metrics) []models.Anomaly {
	anomalies := []models.Anomaly{}

	// Need baseline data to establish reference values
	if !d.initialized {
		if len(historical) < 10 {
			return anomalies // Not enough data for baseline
		}
		d.initializeReferences(historical)
		d.initialized = true
	}

	// Check error rate using CUSUM
	errorRateAnomaly := d.detectCUSUMAnomaly(
		current.ErrorRate,
		&d.cusumPosErrorRate,
		&d.cusumNegErrorRate,
		d.referenceErrorRate,
		"error_rate",
		models.AnomalyTypeErrorRate,
		"Persistent error rate shift detected",
	)
	if errorRateAnomaly != nil {
		anomalies = append(anomalies, *errorRateAnomaly)
	}

	// Check request rate using CUSUM
	requestRateAnomaly := d.detectCUSUMAnomaly(
		current.RequestsPerSec,
		&d.cusumPosRequestsPerSec,
		&d.cusumNegRequestsPerSec,
		d.referenceRequestsPerSec,
		"requests_per_sec",
		models.AnomalyTypeTrafficSpike,
		"Persistent traffic pattern change detected",
	)
	if requestRateAnomaly != nil {
		anomalies = append(anomalies, *requestRateAnomaly)
	}

	// Check response time using CUSUM
	responseTimeAnomaly := d.detectCUSUMAnomaly(
		current.AvgResponseTime,
		&d.cusumPosResponseTime,
		&d.cusumNegResponseTime,
		d.referenceResponseTime,
		"avg_response_time",
		models.AnomalyTypeResponseTime,
		"Persistent response time degradation detected",
	)
	if responseTimeAnomaly != nil {
		anomalies = append(anomalies, *responseTimeAnomaly)
	}

	return anomalies
}

// detectCUSUMAnomaly applies CUSUM algorithm to a single metric
func (d *CUSUMDetector) detectCUSUMAnomaly(
	currentValue float64,
	cusumPos *float64,
	cusumNeg *float64,
	referenceMean float64,
	metricName string,
	anomalyType models.AnomalyType,
	description string,
) *models.Anomaly {
	// CUSUM formulas:
	// S⁺(t) = max(0, S⁺(t-1) + (x(t) - μ - k))
	// S⁻(t) = max(0, S⁻(t-1) - (x(t) - μ + k))

	// Calculate positive CUSUM (detects upward shifts)
	*cusumPos = math.Max(0, *cusumPos + (currentValue - referenceMean - d.slackParameter))

	// Calculate negative CUSUM (detects downward shifts)
	*cusumNeg = math.Max(0, *cusumNeg - (currentValue - referenceMean + d.slackParameter))

	// Check if either cumulative sum exceeds the decision threshold
	if *cusumPos > d.decisionThreshold {
		// Upward shift detected
		severity := calculateCUSUMSeverity(*cusumPos, d.decisionThreshold)
		deviation := currentValue - referenceMean

		// Reset CUSUM after detection
		*cusumPos = 0
		*cusumNeg = 0

		return &models.Anomaly{
			Timestamp:     time.Now(),
			Type:          anomalyType,
			Severity:      severity,
			Description:   description + " (upward shift)",
			Metric:        metricName,
			ActualValue:   currentValue,
			ExpectedValue: referenceMean,
			Deviation:     deviation,
		}
	}

	if *cusumNeg > d.decisionThreshold {
		// Downward shift detected
		severity := calculateCUSUMSeverity(*cusumNeg, d.decisionThreshold)
		deviation := referenceMean - currentValue

		// Reset CUSUM after detection
		*cusumPos = 0
		*cusumNeg = 0

		return &models.Anomaly{
			Timestamp:     time.Now(),
			Type:          anomalyType,
			Severity:      severity,
			Description:   description + " (downward shift)",
			Metric:        metricName,
			ActualValue:   currentValue,
			ExpectedValue: referenceMean,
			Deviation:     deviation,
		}
	}

	return nil
}

// initializeReferences calculates reference values (target means) from historical data
func (d *CUSUMDetector) initializeReferences(historical []models.Metrics) {
	if len(historical) == 0 {
		return
	}

	sumErrorRate := 0.0
	sumRequestsPerSec := 0.0
	sumResponseTime := 0.0

	for _, m := range historical {
		sumErrorRate += m.ErrorRate
		sumRequestsPerSec += m.RequestsPerSec
		sumResponseTime += m.AvgResponseTime
	}

	count := float64(len(historical))
	d.referenceErrorRate = sumErrorRate / count
	d.referenceRequestsPerSec = sumRequestsPerSec / count
	d.referenceResponseTime = sumResponseTime / count
}

// calculateCUSUMSeverity determines severity based on how much CUSUM exceeds threshold
func calculateCUSUMSeverity(cusumValue, threshold float64) models.Severity {
	ratio := cusumValue / threshold
	if ratio > 3.0 {
		return models.SeverityCritical
	} else if ratio > 2.0 {
		return models.SeverityHigh
	} else if ratio > 1.5 {
		return models.SeverityMedium
	}
	return models.SeverityLow
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

package models

import (
	"time"
)

// LogEntry represents a parsed log entry
type LogEntry struct {
	Timestamp   time.Time         `json:"timestamp"`
	Level       string            `json:"level"`
	Message     string            `json:"message"`
	Source      string            `json:"source"`
	UserAgent   string            `json:"user_agent,omitempty"`
	IPAddress   string            `json:"ip_address,omitempty"`
	StatusCode  int               `json:"status_code,omitempty"`
	ResponseTime float64          `json:"response_time,omitempty"`
	Method      string            `json:"method,omitempty"`
	Path        string            `json:"path,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`
}

// Anomaly represents a detected anomaly
type Anomaly struct {
	Timestamp     time.Time   `json:"timestamp"`
	Type          AnomalyType `json:"type"`
	Severity      Severity    `json:"severity"`
	Description   string      `json:"description"`
	Metric        string      `json:"metric"`
	ActualValue   float64     `json:"actual_value"`
	ExpectedValue float64     `json:"expected_value"`
	Deviation     float64     `json:"deviation"`
	RelatedLogs   []LogEntry  `json:"related_logs,omitempty"`
}

// AnomalyType represents the type of anomaly detected
type AnomalyType string

const (
	AnomalyTypeErrorRate      AnomalyType = "error_rate"
	AnomalyTypeTrafficSpike   AnomalyType = "traffic_spike"
	AnomalyTypeResponseTime   AnomalyType = "response_time"
	AnomalyTypePattern        AnomalyType = "pattern"
	AnomalyTypeStatusCode     AnomalyType = "status_code"
)

// Severity represents anomaly severity
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Metrics represents aggregated metrics
type Metrics struct {
	Timestamp       time.Time         `json:"timestamp"`
	RequestsPerSec  float64           `json:"requests_per_sec"`
	ErrorRate       float64           `json:"error_rate"`
	AvgResponseTime float64           `json:"avg_response_time"`
	StatusCodes     map[int]int       `json:"status_codes"`
	TopPaths        []PathCount       `json:"top_paths"`
	TopIPs          []IPCount         `json:"top_ips"`
	TopUserAgents   []UserAgentCount  `json:"top_user_agents"`
}

// PathCount represents request count per path
type PathCount struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

// IPCount represents request count per IP
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// UserAgentCount represents request count per user agent
type UserAgentCount struct {
	UserAgent string `json:"user_agent"`
	Count     int    `json:"count"`
}

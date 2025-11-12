package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	LogPath         string           `yaml:"log_path"`
	LogFormat       string           `yaml:"log_format"`
	DetectorConfig  DetectorConfig   `yaml:"detector"`
	DashboardConfig DashboardConfig  `yaml:"dashboard"`
}

// DetectorConfig contains anomaly detection settings
type DetectorConfig struct {
	WindowSize         int     `yaml:"window_size"`
	SensitivityLevel   float64 `yaml:"sensitivity_level"`
	BaselineMinutes    int     `yaml:"baseline_minutes"`
	ErrorRateThreshold float64 `yaml:"error_rate_threshold"`
	Algorithm          string  `yaml:"algorithm"` // "moving_average", "cusum", or "stddev"
	SmoothingFactor    float64 `yaml:"smoothing_factor"` // Alpha parameter for moving average (0-1)
	CUSUMSlack         float64 `yaml:"cusum_slack"` // k parameter: slack/allowable deviation for CUSUM
	CUSUMThreshold     float64 `yaml:"cusum_threshold"` // h parameter: decision threshold for CUSUM
}

// DashboardConfig contains web dashboard settings
type DashboardConfig struct {
	Port           int    `yaml:"port"`
	Host           string `yaml:"host"`
	EnableTUI      bool   `yaml:"enable_tui"`
	RefreshRate    int    `yaml:"refresh_rate_ms"`
	MaxLogLines    int    `yaml:"max_log_lines"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		// Return default configuration if file doesn't exist
		return DefaultConfig(), nil
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		LogPath:   "/var/log/app.log",
		LogFormat: "json",
		DetectorConfig: DetectorConfig{
			WindowSize:         100,
			SensitivityLevel:   2.0,
			BaselineMinutes:    10,
			ErrorRateThreshold: 0.05,
			Algorithm:          "stddev",
			SmoothingFactor:    0.3,
			CUSUMSlack:         0.5,  // Default slack parameter
			CUSUMThreshold:     5.0,  // Default decision threshold
		},
		DashboardConfig: DashboardConfig{
			Port:           8080,
			Host:           "localhost",
			EnableTUI:      false,
			RefreshRate:    1000,
			MaxLogLines:    500,
		},
	}
}

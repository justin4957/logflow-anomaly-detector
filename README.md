# LogFlow Anomaly Detector

A real-time log file analyzer with intelligent anomaly detection capabilities. Monitor your application logs, detect traffic spikes, error rate anomalies, and performance degradation in real-time.

## Features

- **Real-Time Log Streaming**: Tail log files in real-time with support for multiple log formats
- **Multiple Log Format Support**: Parse Apache Combined, Common Log Format, and JSON-structured logs
- **Anomaly Detection Algorithms**:
  - Standard Deviation-based detection
  - Moving Average analysis
  - CUSUM (Cumulative Sum) algorithm
- **Pattern Recognition**: Group similar error messages and identify frequent user agents/IPs
- **Web Dashboard**: Live streaming dashboard with real-time metrics and anomaly alerts
- **Configurable Sensitivity**: Adjust detection thresholds to suit your needs

## Architecture

```
┌─────────────┐
│  Log Files  │
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│   Log Stream     │  ◄── Real-time file tailing
│   (fsnotify)     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Log Parser     │  ◄── Multi-format parsing
│ (JSON/Apache/etc)│
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Metrics Collector│  ◄── Aggregate metrics
│  (Window-based)  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Anomaly Detector │  ◄── Statistical analysis
│ (StdDev/CUSUM)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Web Dashboard   │  ◄── Real-time visualization
│   (WebSocket)    │
└──────────────────┘
```

## Installation

### Prerequisites

- Go 1.21 or higher
- Git

### Build from Source

```bash
# Clone the repository
git clone https://github.com/justin4957/logflow-anomaly-detector.git
cd logflow-anomaly-detector

# Install dependencies
make deps

# Build the application
make build
```

## Configuration

Create a `config.yaml` file (see `config.yaml.example`):

```yaml
log_path: "/var/log/app.log"
log_format: "json" # Options: json, apache, combined, common

detector:
  window_size: 100
  sensitivity_level: 2.0 # Standard deviations from mean
  baseline_minutes: 10
  error_rate_threshold: 0.05
  algorithm: "stddev" # Options: stddev, moving_average, cusum

dashboard:
  port: 8080
  host: "localhost"
  enable_tui: false
  refresh_rate_ms: 1000
  max_log_lines: 500
```

### Configuration Options

#### Detector Configuration

- `window_size`: Number of log entries in each analysis window
- `sensitivity_level`: Multiplier for standard deviation threshold (lower = more sensitive)
- `baseline_minutes`: Minutes of data needed to establish baseline behavior
- `error_rate_threshold`: Threshold for error rate alerts (0.05 = 5%)
- `algorithm`: Detection algorithm to use

#### Dashboard Configuration

- `port`: Port for the web dashboard
- `host`: Host address to bind to
- `enable_tui`: Enable text-based UI (terminal interface)
- `refresh_rate_ms`: Dashboard refresh rate in milliseconds
- `max_log_lines`: Maximum log lines to display in the dashboard

## Usage

### Run with Configuration File

```bash
./logflow --config config.yaml
```

### Using Make

```bash
# Run with default config
make run

# Run with example config
make run-example
```

### Access the Dashboard

Once started, open your browser to:

```
http://localhost:8080
```

## Log Format Support

### JSON Format

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "level": "error",
  "message": "Database connection failed",
  "ip_address": "192.168.1.100",
  "status_code": 500
}
```

### Apache Combined Log Format

```
127.0.0.1 - - [15/Jan/2025:10:30:00 -0700] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"
```

### Common Log Format

```
127.0.0.1 - - [15/Jan/2025:10:30:00 -0700] "GET /api/users HTTP/1.1" 200 1234
```

## Anomaly Detection

The application detects several types of anomalies:

1. **Error Rate Anomalies**: Unusual spikes in error rates
2. **Traffic Spikes/Drops**: Sudden changes in request volume
3. **Response Time Degradation**: Slower than expected response times
4. **Status Code Patterns**: Unusual distribution of HTTP status codes

### Detection Algorithms

#### Standard Deviation (StdDev)

Compares current metrics against historical mean and standard deviation:
- Alert triggered when: `|current - mean| > threshold * stddev`
- Best for: Detecting sharp deviations from normal behavior

#### Moving Average

Uses exponentially weighted moving averages:
- Adapts to slowly changing baselines
- Best for: Systems with gradual trend changes

#### CUSUM (Cumulative Sum)

Detects subtle shifts in metrics over time:
- Accumulates deviations from target value
- Best for: Detecting small, persistent changes

## Development

### Project Structure

```
.
├── cmd/
│   └── logflow/           # Main application entry point
├── internal/
│   ├── analyzer/          # Anomaly detection logic
│   ├── config/            # Configuration management
│   ├── dashboard/         # Web dashboard
│   ├── parser/            # Log format parsers
│   └── stream/            # Log streaming/tailing
├── pkg/
│   └── models/            # Shared data models
├── config.yaml.example    # Example configuration
├── go.mod                 # Go module definition
├── Makefile              # Build automation
└── README.md             # This file
```

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage
```

### Code Formatting

```bash
make fmt
```

## Metrics Displayed

The dashboard shows:

- **Requests/sec**: Current request rate
- **Error Rate**: Percentage of failed requests
- **Average Response Time**: Mean response time in milliseconds
- **Top Paths**: Most frequently accessed endpoints
- **Top IPs**: Most active IP addresses
- **Top User Agents**: Most common client user agents
- **Status Code Distribution**: Breakdown of HTTP status codes

## Contributing

Contributions are welcome! Please see the GitHub issues for areas that need work.

## License

MIT License - see LICENSE file for details

## Roadmap

See [GitHub Issues](https://github.com/justin4957/logflow-anomaly-detector/issues) for planned features and improvements.

## Support

For issues and questions, please use the [GitHub Issues](https://github.com/justin4957/logflow-anomaly-detector/issues) page.

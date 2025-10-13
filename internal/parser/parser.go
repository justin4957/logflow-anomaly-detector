package parser

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/justin4957/logflow-anomaly-detector/pkg/models"
)

// LogParser interface for parsing different log formats
type LogParser interface {
	Parse(line string) (*models.LogEntry, error)
}

// NewParser creates a parser based on the specified format
func NewParser(format string) LogParser {
	switch format {
	case "json":
		return &JSONParser{}
	case "apache", "combined":
		return &ApacheParser{}
	case "common":
		return &CommonLogParser{}
	default:
		return &JSONParser{}
	}
}

// JSONParser parses JSON-formatted logs
type JSONParser struct{}

func (p *JSONParser) Parse(line string) (*models.LogEntry, error) {
	var entry models.LogEntry
	if err := json.Unmarshal([]byte(line), &entry); err != nil {
		return nil, fmt.Errorf("failed to parse JSON log: %w", err)
	}
	return &entry, nil
}

// ApacheParser parses Apache Combined log format
type ApacheParser struct {
	regex *regexp.Regexp
}

func (p *ApacheParser) Parse(line string) (*models.LogEntry, error) {
	// Apache Combined Log Format:
	// %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"
	if p.regex == nil {
		p.regex = regexp.MustCompile(
			`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+) "([^"]*)" "([^"]*)"`,
		)
	}

	matches := p.regex.FindStringSubmatch(line)
	if len(matches) != 9 {
		return nil, fmt.Errorf("invalid Apache log format")
	}

	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])
	if err != nil {
		timestamp = time.Now()
	}

	statusCode, _ := strconv.Atoi(matches[5])

	entry := &models.LogEntry{
		Timestamp:  timestamp,
		IPAddress:  matches[1],
		Method:     matches[3],
		Path:       matches[4],
		StatusCode: statusCode,
		UserAgent:  matches[8],
		Message:    line,
	}

	// Determine log level based on status code
	if statusCode >= 500 {
		entry.Level = "error"
	} else if statusCode >= 400 {
		entry.Level = "warn"
	} else {
		entry.Level = "info"
	}

	return entry, nil
}

// CommonLogParser parses Common Log Format
type CommonLogParser struct {
	regex *regexp.Regexp
}

func (p *CommonLogParser) Parse(line string) (*models.LogEntry, error) {
	// Common Log Format: %h %l %u %t \"%r\" %>s %b
	if p.regex == nil {
		p.regex = regexp.MustCompile(
			`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+)`,
		)
	}

	matches := p.regex.FindStringSubmatch(line)
	if len(matches) != 7 {
		return nil, fmt.Errorf("invalid Common log format")
	}

	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2])
	if err != nil {
		timestamp = time.Now()
	}

	statusCode, _ := strconv.Atoi(matches[5])

	entry := &models.LogEntry{
		Timestamp:  timestamp,
		IPAddress:  matches[1],
		Method:     matches[3],
		Path:       matches[4],
		StatusCode: statusCode,
		Message:    line,
	}

	if statusCode >= 500 {
		entry.Level = "error"
	} else if statusCode >= 400 {
		entry.Level = "warn"
	} else {
		entry.Level = "info"
	}

	return entry, nil
}

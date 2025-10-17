package parser

import (
	"testing"
)

const (
	// Sample log lines for benchmarking
	sampleJSONLog = `{"timestamp":"2024-01-15T10:30:45Z","level":"info","ip_address":"192.168.1.100","method":"GET","path":"/api/users","status_code":200,"response_time":45.3,"user_agent":"Mozilla/5.0","message":"Request processed"}`

	sampleApacheLog = `192.168.1.100 - - [15/Jan/2024:10:30:45 -0700] "GET /api/users HTTP/1.1" 200 1234 "https://example.com/previous" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"`

	sampleCommonLog = `192.168.1.100 - - [15/Jan/2024:10:30:45 -0700] "GET /api/users HTTP/1.1" 200 1234`
)

// BenchmarkJSONParser measures JSON log parsing speed
func BenchmarkJSONParser(b *testing.B) {
	parser := &JSONParser{}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(sampleJSONLog)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// BenchmarkJSONParserAllocs measures allocations in JSON parsing
func BenchmarkJSONParserAllocs(b *testing.B) {
	parser := &JSONParser{}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(sampleJSONLog)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// BenchmarkApacheParser measures Apache log parsing speed
func BenchmarkApacheParser(b *testing.B) {
	parser := &ApacheParser{}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(sampleApacheLog)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// BenchmarkApacheParserAllocs measures allocations in Apache parsing
func BenchmarkApacheParserAllocs(b *testing.B) {
	parser := &ApacheParser{}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(sampleApacheLog)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// BenchmarkCommonLogParser measures Common log parsing speed
func BenchmarkCommonLogParser(b *testing.B) {
	parser := &CommonLogParser{}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(sampleCommonLog)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// BenchmarkCommonLogParserAllocs measures allocations in Common log parsing
func BenchmarkCommonLogParserAllocs(b *testing.B) {
	parser := &CommonLogParser{}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := parser.Parse(sampleCommonLog)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
	}
}

// BenchmarkParserFactoryOverhead measures overhead of parser creation
func BenchmarkParserFactoryOverhead(b *testing.B) {
	b.Run("JSON", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewParser("json")
		}
	})

	b.Run("Apache", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewParser("apache")
		}
	})

	b.Run("Common", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewParser("common")
		}
	})
}

// BenchmarkBatchParsing simulates batch processing multiple log lines
func BenchmarkBatchParsing(b *testing.B) {
	samples := []string{
		sampleJSONLog,
		sampleApacheLog,
		sampleCommonLog,
	}

	b.Run("JSON-Batch-100", func(b *testing.B) {
		parser := &JSONParser{}
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			for j := 0; j < 100; j++ {
				_, _ = parser.Parse(samples[0])
			}
		}
	})

	b.Run("Apache-Batch-100", func(b *testing.B) {
		parser := &ApacheParser{}
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			for j := 0; j < 100; j++ {
				_, _ = parser.Parse(samples[1])
			}
		}
	})
}

// BenchmarkParallelParsing tests parser performance under concurrent load
func BenchmarkParallelParsing(b *testing.B) {
	parser := &JSONParser{}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = parser.Parse(sampleJSONLog)
		}
	})
}

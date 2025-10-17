# Performance Optimization and Benchmarking

This document describes the performance optimizations implemented in LogFlow Anomaly Detector and provides guidelines for benchmarking and profiling.

## Table of Contents

- [Overview](#overview)
- [Performance Targets](#performance-targets)
- [Optimizations Implemented](#optimizations-implemented)
- [Running Benchmarks](#running-benchmarks)
- [Profiling](#profiling)
- [Performance Monitoring](#performance-monitoring)
- [Optimization Guidelines](#optimization-guidelines)

## Overview

LogFlow Anomaly Detector is designed to process high-volume log streams with minimal resource usage. This document outlines the performance characteristics and optimization strategies employed.

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| **Throughput** | 10,000 log entries/sec | On standard hardware (4 CPU, 8GB RAM) |
| **Memory Usage** | <100MB | For typical workload (sustained operation) |
| **Dashboard Latency** | <100ms | WebSocket message delivery time |
| **CPU Usage** | <30% | At sustained load |
| **GC Pause Time** | <10ms | 99th percentile |

## Optimizations Implemented

### 1. Log Parser Optimizations

#### Pre-compiled Regular Expressions
- **Before**: Regex patterns compiled on every parser instantiation
- **After**: Global pre-compiled regex patterns
- **Impact**: Eliminates allocation overhead and compilation time per request

```go
// Optimization: Pre-compiled regex at package level
var (
    apacheRegex = regexp.MustCompile(
        `^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+) "([^"]*)" "([^"]*)"`,
    )
    commonLogRegex = regexp.MustCompile(
        `^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\S+)`,
    )
)
```

**Expected Benefits**:
- 20-30% reduction in parsing overhead
- Eliminates repeated regex compilation
- Reduces memory allocations

### 2. Metrics Collection Optimizations

#### Pre-allocated Data Structures
- **Maps**: Initialized with reasonable capacity to reduce rehashing
- **Slices**: Pre-allocated with expected capacity

```go
func newMetricsWindow() *MetricsWindow {
    return &MetricsWindow{
        startTime:     time.Now(),
        statusCodes:   make(map[int]int, 10),        // ~10 status codes expected
        paths:         make(map[string]int, 50),     // ~50 unique paths
        ips:           make(map[string]int, 100),    // ~100 unique IPs
        userAgents:    make(map[string]int, 20),     // ~20 unique user agents
        responseTimes: make([]float64, 0, 1000),     // 1000 response times
    }
}
```

**Expected Benefits**:
- 15-25% reduction in allocation overhead
- Fewer map rehashing operations
- Better memory locality

#### Optimized Top-N Calculations
- **Before**: Used append with dynamic growth for result slices
- **After**: Pre-allocate exact result size, early exit for empty maps

```go
func getTopPaths(paths map[string]int, limit int) []models.PathCount {
    if len(paths) == 0 {
        return nil
    }

    // Pre-allocate exact size needed
    sorted := make([]kv, 0, len(paths))
    // ... sorting logic ...

    resultSize := limit
    if len(sorted) < limit {
        resultSize = len(sorted)
    }

    result := make([]models.PathCount, resultSize)
    // Direct assignment instead of append
    for i := 0; i < resultSize; i++ {
        result[i] = models.PathCount{
            Path:  sorted[i].Key,
            Count: sorted[i].Value,
        }
    }

    return result
}
```

**Expected Benefits**:
- 10-20% reduction in sorting and aggregation time
- Reduced allocations in hot path
- Better cache utilization

#### Sync.Pool for Temporary Objects
Added sync.Pool infrastructure for reusable objects (ready for future expansion):

```go
var responseTimePool = sync.Pool{
    New: func() interface{} {
        slice := make([]float64, 0, 1024)
        return &slice
    },
}
```

**Expected Benefits**:
- Reduced GC pressure
- Better memory reuse
- Lower allocation rate

### 3. Profiling Infrastructure

Added comprehensive pprof endpoints to the dashboard server:

```
/debug/pprof/          - Index of available profiles
/debug/pprof/heap      - Heap memory profile
/debug/pprof/goroutine - Goroutine profile
/debug/pprof/profile   - CPU profile (30s by default)
/debug/pprof/trace     - Execution trace
/debug/pprof/block     - Blocking profile
/debug/pprof/mutex     - Mutex contention profile
/debug/pprof/allocs    - All memory allocations
```

## Running Benchmarks

### Full Benchmark Suite

Run all benchmarks with memory statistics:

```bash
go test -bench=. -benchmem -benchtime=5s ./...
```

### Individual Component Benchmarks

#### Parser Benchmarks
```bash
go test -bench=. -benchmem ./internal/parser/
```

Expected benchmark output format:
```
BenchmarkJSONParser-8              500000    2500 ns/op    512 B/op    5 allocs/op
BenchmarkApacheParser-8            300000    3200 ns/op    768 B/op    8 allocs/op
BenchmarkCommonLogParser-8         400000    2800 ns/op    640 B/op    7 allocs/op
```

#### Metrics Benchmarks
```bash
go test -bench=. -benchmem ./internal/analyzer/
```

Expected components tested:
- `BenchmarkMetricsCollection` - Entry addition performance
- `BenchmarkGetCurrentMetrics` - Metrics computation overhead
- `BenchmarkTopPathsCalculation` - Top-N sorting performance
- `BenchmarkConcurrentMetricsCollection` - Thread-safe operations

#### Anomaly Detection Benchmarks
```bash
go test -bench=BenchmarkAnomalyDetection -benchmem ./internal/analyzer/
```

Expected components tested:
- `BenchmarkStdDevDetector` - Statistical detection algorithm
- `BenchmarkCalculateStats` - Mean/StdDev calculations
- `BenchmarkEndToEndDetectionPipeline` - Complete workflow

### Comparative Benchmarks

Run benchmarks before and after changes:

```bash
# Before optimization
go test -bench=. -benchmem ./... > bench-before.txt

# After optimization
go test -bench=. -benchmem ./... > bench-after.txt

# Compare using benchcmp
benchcmp bench-before.txt bench-after.txt
```

### Continuous Benchmarking

Add to CI pipeline:

```bash
# Run benchmarks and save results
go test -bench=. -benchmem -benchtime=5s ./... | tee bench-results.txt

# Fail if performance degrades by >10%
# (requires benchstat or custom tooling)
```

## Profiling

### CPU Profiling

#### Via pprof Endpoints (Recommended)
```bash
# Start the application
./logflow --config config.yaml

# Capture 30-second CPU profile
go tool pprof http://localhost:8080/debug/pprof/profile

# Interactive commands in pprof:
# - top10: Show top 10 functions by CPU time
# - list <function>: Show source code with CPU samples
# - web: Generate SVG call graph (requires graphviz)
```

#### Via Test Benchmarks
```bash
# Generate CPU profile during benchmarks
go test -bench=. -cpuprofile=cpu.prof ./internal/parser/

# Analyze the profile
go tool pprof cpu.prof
```

### Memory Profiling

#### Heap Analysis
```bash
# Capture heap snapshot
go tool pprof http://localhost:8080/debug/pprof/heap

# Commands:
# - top: Top memory consumers
# - list <function>: Allocation sites
# - alloc_space: Sort by total allocated
# - inuse_space: Sort by currently in use
```

#### Allocation Tracking
```bash
# Profile all allocations
go test -bench=. -memprofile=mem.prof ./...

# Analyze allocations
go tool pprof -alloc_space mem.prof
```

### Goroutine Analysis

```bash
# Check for goroutine leaks
curl http://localhost:8080/debug/pprof/goroutine?debug=2

# Full goroutine profile
go tool pprof http://localhost:8080/debug/pprof/goroutine
```

### Mutex Contention

```bash
# Enable mutex profiling (add to main.go):
# runtime.SetMutexProfileFraction(1)

# Analyze contention
go tool pprof http://localhost:8080/debug/pprof/mutex
```

### Execution Tracing

```bash
# Capture 5-second trace
curl http://localhost:8080/debug/pprof/trace?seconds=5 > trace.out

# Visualize trace
go tool trace trace.out
```

## Performance Monitoring

### Key Metrics to Track

1. **Throughput Metrics**
   - Log entries processed per second
   - End-to-end latency (ingestion to anomaly detection)
   - Dashboard update frequency

2. **Resource Metrics**
   - Heap memory usage
   - Goroutine count
   - CPU utilization
   - GC pause times

3. **Application Metrics**
   - Parser latency (p50, p95, p99)
   - Metrics collection overhead
   - Detection algorithm execution time
   - WebSocket broadcast latency

### Runtime Metrics Collection

Monitor Go runtime metrics:

```go
import (
    "runtime"
    "runtime/metrics"
)

// Key metrics to track:
// - /memory/classes/heap/objects:bytes
// - /gc/heap/goal:bytes
// - /gc/cycles/total:gc-cycles
// - /sched/goroutines:goroutines
```

## Optimization Guidelines

### General Principles

1. **Measure Before Optimizing**
   - Always benchmark before and after changes
   - Use profiling to identify actual bottlenecks
   - Focus on hot paths (>10% of CPU time)

2. **Memory Allocation Strategy**
   - Pre-allocate slices and maps with known capacity
   - Reuse objects via sync.Pool for high-frequency allocations
   - Avoid allocations in hot loops

3. **Concurrency Best Practices**
   - Minimize lock contention (use RWMutex when appropriate)
   - Consider lock-free data structures for counters
   - Profile mutex contention regularly

4. **String Handling**
   - Use string pooling for repeated values
   - Avoid unnecessary string conversions
   - Use strings.Builder for concatenation

### When to Optimize

**Optimize when**:
- Profiling shows a clear bottleneck (>5% CPU time)
- Memory usage exceeds targets
- GC pause times impact user experience
- Throughput is below requirements

**Don't optimize**:
- Without measuring first
- Premature optimization (before it's proven necessary)
- At the expense of code clarity (unless critical path)

### Benchmark-Driven Development

1. Write benchmarks for new features
2. Establish baseline performance
3. Implement feature
4. Verify performance hasn't regressed
5. Optimize if needed based on benchmarks

## Profiling in Production

### Safe Profiling Practices

1. **CPU Profiling**: Generally safe, adds ~5% overhead
2. **Heap Profiling**: Minimal overhead when not actively profiling
3. **Mutex Profiling**: Can add significant overhead, enable only when investigating
4. **Block Profiling**: Similar to mutex profiling, use sparingly

### Profiling Checklist

- [ ] Enable pprof endpoints (already implemented)
- [ ] Set up monitoring alerts for resource usage
- [ ] Document baseline performance metrics
- [ ] Create runbook for performance investigation
- [ ] Schedule regular performance reviews

## Performance Testing Scenarios

### Scenario 1: Sustained Load Test
```bash
# Generate 10,000 log entries per second for 5 minutes
# Monitor: CPU, memory, GC pauses
# Expected: <30% CPU, <100MB memory, <10ms GC pauses
```

### Scenario 2: Burst Traffic
```bash
# Spike to 50,000 entries/sec for 30 seconds
# Monitor: Backpressure handling, memory growth
# Expected: Graceful degradation, no OOM
```

### Scenario 3: Many Unique Values
```bash
# Generate logs with 10,000 unique paths, IPs
# Monitor: Map memory usage, rehashing overhead
# Expected: Memory growth stabilizes, no performance cliff
```

## Continuous Integration

### CI Benchmark Job

```yaml
name: Benchmarks
on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      - name: Run Benchmarks
        run: |
          go test -bench=. -benchmem -benchtime=5s ./... | tee bench-output.txt
      - name: Store Benchmark Results
        uses: benchmark-action/github-action-benchmark@v1
        with:
          tool: 'go'
          output-file-path: bench-output.txt
```

## Future Optimization Opportunities

1. **Parser Optimizations**
   - [ ] Implement string interning for repeated values
   - [ ] Use fasthttp/fastjson for JSON parsing
   - [ ] Batch log parsing (process 100 lines at once)

2. **Metrics Collection**
   - [ ] Implement lock-free counters using atomic operations
   - [ ] Use fixed-size ring buffers for response times
   - [ ] Implement approximate top-K with Count-Min Sketch

3. **Detection Algorithms**
   - [ ] Implement incremental statistics (avoid full recalculation)
   - [ ] Use SIMD instructions for batch calculations
   - [ ] Cache intermediate results

4. **General**
   - [ ] Profile-guided optimization (PGO) compilation
   - [ ] Investigate zero-copy techniques
   - [ ] Benchmark alternative data structures (e.g., radix tree for paths)

## References

- [Go Profiling Best Practices](https://go.dev/blog/pprof)
- [Benchmarking Guide](https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go)
- [Memory Management Patterns](https://go.dev/doc/effective_go#allocation)
- [Performance Optimization Techniques](https://github.com/dgryski/go-perfbook)

## Conclusion

This document provides a comprehensive overview of performance optimization efforts in LogFlow Anomaly Detector. Regular benchmarking, profiling, and monitoring will ensure the application meets its performance targets in production.

For questions or suggestions, please open an issue in the GitHub repository.

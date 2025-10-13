.PHONY: build run test clean install deps

# Build the application
build:
	go build -o logflow ./cmd/logflow

# Run the application
run: build
	./logflow --config config.yaml

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

# Install dependencies
deps:
	go mod download
	go mod tidy

# Clean build artifacts
clean:
	rm -f logflow
	rm -f coverage.out
	go clean

# Install the binary
install:
	go install ./cmd/logflow

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run

# Run the application with example config
run-example:
	cp config.yaml.example config.yaml
	$(MAKE) run

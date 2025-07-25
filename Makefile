# IIS Security Scanner Makefile

# Variables
BINARY_NAME=issmap
MAIN_FILE=main.go
BUILD_DIR=build
VERSION=1.0.0
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Default target
.PHONY: all
all: clean build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_FILE)
	@echo "Build completed: $(BUILD_DIR)/$(BINARY_NAME)"

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(MAIN_FILE)
	
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(MAIN_FILE)
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(MAIN_FILE)
	
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(MAIN_FILE)
	
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(MAIN_FILE)
	
	@echo "Multi-platform build completed"

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Lint code
.PHONY: lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Installing..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		golangci-lint run; \
	fi

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Install the binary
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installation completed"

# Uninstall the binary
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstallation completed"

# Run the scanner with example target
.PHONY: run-example
run-example: build
	@echo "Running example scan..."
	./$(BUILD_DIR)/$(BINARY_NAME) --target https://httpbin.org --verbose

# Create release package
.PHONY: release
release: build-all
	@echo "Creating release package..."
	@mkdir -p release
	
	# Create archives for each platform
	cd $(BUILD_DIR) && tar -czf ../release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64
	cd $(BUILD_DIR) && tar -czf ../release/$(BINARY_NAME)-$(VERSION)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64
	cd $(BUILD_DIR) && zip -q ../release/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	cd $(BUILD_DIR) && tar -czf ../release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64
	cd $(BUILD_DIR) && tar -czf ../release/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64
	
	# Copy documentation
	cp README.md release/
	cp LICENSE release/ 2>/dev/null || echo "LICENSE file not found, skipping..."
	
	@echo "Release packages created in release/ directory"

# Development server (for testing)
.PHONY: dev
dev:
	@echo "Starting development mode..."
	go run $(MAIN_FILE) --target https://httpbin.org --verbose --debug

# Security scan of the code
.PHONY: security
security:
	@echo "Running security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Installing..."; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
		gosec ./...; \
	fi

# Benchmark tests
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	@if command -v godoc >/dev/null 2>&1; then \
		echo "Starting godoc server at http://localhost:6060"; \
		godoc -http=:6060; \
	else \
		echo "godoc not installed. Installing..."; \
		go install golang.org/x/tools/cmd/godoc@latest; \
		echo "Starting godoc server at http://localhost:6060"; \
		godoc -http=:6060; \
	fi

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .
	docker tag $(BINARY_NAME):$(VERSION) $(BINARY_NAME):latest

# Docker run
.PHONY: docker-run
docker-run:
	@echo "Running Docker container..."
	docker run --rm -it $(BINARY_NAME):latest --target https://httpbin.org --verbose

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  build-all     - Build for multiple platforms"
	@echo "  deps          - Install dependencies"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  clean         - Clean build artifacts"
	@echo "  install       - Install binary to /usr/local/bin"
	@echo "  uninstall     - Remove binary from /usr/local/bin"
	@echo "  run-example   - Run example scan"
	@echo "  release       - Create release packages"
	@echo "  dev           - Start development mode"
	@echo "  security      - Run security scan"
	@echo "  bench         - Run benchmarks"
	@echo "  docs          - Generate documentation"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  help          - Show this help"
.PHONY: lint test build clean docker-build

# Lint runs custom namedreturns linter followed by golangci-lint
lint:
	@echo "Running namedreturns linter..."
	namedreturns ./...
	@echo "Running golangci-lint..."
	golangci-lint run

# Test runs all tests
test:
	go test -v -race -cover ./...

# Build compiles the bot binary
build:
	go build -o bin/diagnostic-slackbot ./cmd/bot

# Clean removes build artifacts
clean:
	rm -rf bin/

# Docker build creates the container image
docker-build:
	docker build -t diagnostic-slackbot:latest .

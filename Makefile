.PHONY: all build test e2e clean security fuzz race analysis

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS = -X main.version=$(VERSION)

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/sentryscan ./cmd/sentryscan

test:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

e2e:
	go test -tags=e2e -race ./cmd/...

clean:
	rm -rf bin/ coverage.out

# Install dependencies
deps:
	go mod download
	go install github.com/google/go-containerregistry/cmd/crane@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest

# Run linter
lint:
	golangci-lint run

# Run security scanner
security:
	gosec -quiet ./...

# Run static analysis
analysis:
	go vet ./...
	staticcheck ./...
	govulncheck ./...

# Run fuzz tests
fuzz:
	go test -run=^$ -fuzz=Fuzz -fuzztime=30s ./...

# Run race detector tests
race:
	go test -race ./...

# Generate SBOM
sbom:
	syft packages . -o cyclonedx-json > sbom.json

# Verify dependencies
verify:
	go mod verify
	go mod graph | grep -i gpl || true

# CI targets
ci: deps lint test e2e security analysis fuzz race verify

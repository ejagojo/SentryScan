.PHONY: build run fmt lint vet test

build:
	go build -o bin/sentryscan ./cmd/sentryscan

run:
	go run ./cmd/sentryscan

fmt:
	go fmt ./...

lint:
	golangci-lint run

vet:
	go vet ./...

test:
	go test ./...

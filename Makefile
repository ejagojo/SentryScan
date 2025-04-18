.PHONY: build run fmt lint vet test

build:
	mkdir -p bin
	go build -o bin/sentryscan ./cmd/sentryscan

run:
	make build
	./bin/sentryscan

fmt:
	go fmt ./...

lint:
	golangci-lint run

vet:
	go vet ./...

test:
	go test ./...

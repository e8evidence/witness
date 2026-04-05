MODULE := github.com/e8evidence/witness
CMD    := ./cmd/witness
BIN    := witness

# Embed version from git tag (falls back to "dev" when no tag exists).
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.DEFAULT_GOAL := build

.PHONY: all build test vet fmt lint tidy clean

all: fmt vet test build

build:
	go build $(LDFLAGS) -o $(BIN) $(CMD)

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint: vet
	staticcheck ./...

tidy:
	go mod tidy

clean:
	rm -f $(BIN)

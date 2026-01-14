.PHONY: all build clean test server client

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.1.0")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

all: build

build: server client

server:
	@echo "Building NoctWG Server..."
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/noctwg-server ./cmd/noctwg-server

client:
	@echo "Building NoctWG Client..."
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/noctwg-client ./cmd/noctwg-client

clean:
	@echo "Cleaning..."
	@rm -rf bin/

test:
	@echo "Running tests..."
	go test -v ./...

install: build
	@echo "Installing..."
	@cp bin/noctwg-server /usr/local/bin/
	@cp bin/noctwg-client /usr/local/bin/

# Development targets
run-server:
	go run ./cmd/noctwg-server --api-port 8080

run-client:
	go run ./cmd/noctwg-client --gui-port 8081

# Generate keys
genkey:
	@go run ./cmd/noctwg-server --genkey

# Cross-compilation
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/noctwg-server-linux-amd64 ./cmd/noctwg-server
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/noctwg-client-linux-amd64 ./cmd/noctwg-client

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/noctwg-server-windows-amd64.exe ./cmd/noctwg-server
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/noctwg-client-windows-amd64.exe ./cmd/noctwg-client

build-macos:
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/noctwg-server-darwin-amd64 ./cmd/noctwg-server
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/noctwg-client-darwin-amd64 ./cmd/noctwg-client
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/noctwg-server-darwin-arm64 ./cmd/noctwg-server
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/noctwg-client-darwin-arm64 ./cmd/noctwg-client

build-all: build-linux build-windows build-macos
	@echo "Built for all platforms"

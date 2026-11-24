.PHONY: build build-linux build-linux-arm64 test clean

BIN_DIR := bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo v1.0.0)
LDFLAGS := -s -w -X relay-download/internal/version.Version=$(VERSION)

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/relay-center ./cmd/relay-center
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/relay-agent-a ./cmd/relay-agent-a
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/relay-agent-b ./cmd/relay-agent-b

build-linux:
	@mkdir -p $(BIN_DIR)/linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/linux-amd64/relay-center ./cmd/relay-center
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/linux-amd64/relay-agent-a ./cmd/relay-agent-a
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/linux-amd64/relay-agent-b ./cmd/relay-agent-b

build-linux-arm64:
	@mkdir -p $(BIN_DIR)/linux-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/linux-arm64/relay-center ./cmd/relay-center
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/linux-arm64/relay-agent-a ./cmd/relay-agent-a
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/linux-arm64/relay-agent-b ./cmd/relay-agent-b

test:
	go test -v -race ./...

clean:
	rm -rf $(BIN_DIR)

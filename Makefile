VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -X main.version=$(VERSION) -s -w
BINARY = local-agent

.PHONY: build
build:
	go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY) ./cmd/agent

.PHONY: build-windows
build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/agent

.PHONY: build-linux
build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 ./cmd/agent

.PHONY: build-arm
build-arm:
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 ./cmd/agent

.PHONY: build-all
build-all: build-windows build-linux build-arm

.PHONY: test
test:
	go test ./...

.PHONY: clean
clean:
	rm -rf dist/

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

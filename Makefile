IMG ?= ghcr.io/sigeth/opslab-checker:dev
CONTAINER_TOOL ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: all build test lint image

all: lint test build

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/checker ./cmd/checker

test:
	go test -race ./...

lint:
	go vet ./...
	@unformatted=$$(gofmt -l cmd internal pkg); if [ -n "$$unformatted" ]; then echo "$$unformatted"; exit 1; fi

image:
	$(CONTAINER_TOOL) build --platform linux/amd64 -t $(IMG) .

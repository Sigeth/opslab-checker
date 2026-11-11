# Contract library, tested at its newest tag by contract-latest.
CORE_GO := github.com/Sigeth/opslab-core-go
IMG ?= ghcr.io/sigeth/opslab-checker:dev
CONTAINER_TOOL ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: all build test lint image contract-latest

all: lint test build

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/checker ./cmd/checker

test:
	go test -race ./...

lint:
	go vet ./...
	@unformatted=$$(gofmt -l cmd internal pkg); if [ -n "$$unformatted" ]; then echo "$$unformatted"; exit 1; fi

image:
	$(CONTAINER_TOOL) build --platform linux/amd64 -t $(IMG) .

## contract-latest: build and test against the newest opslab-core-go tag (CI),
## on a temporary copy of go.mod so the pinned version is not changed
contract-latest:
	@set -e; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	cp go.mod go.sum "$$tmp/"; \
	export GOWORK=off GOFLAGS="-modfile=$$tmp/go.mod"; \
	go get $(CORE_GO)@latest; \
	echo "== $$(go list -m $(CORE_GO))"; \
	go build ./...; \
	go test ./...

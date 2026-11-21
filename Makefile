GO ?= go
export GOTOOLCHAIN := local

.PHONY: build vet test check check-workflows verify-tasks

build:
	$(GO) build ./...
	$(GO) build -o bin/p0check ./cmd/p0check
	$(GO) build -o bin/checkpatch ./cmd/checkpatch
	$(GO) build -o bin/prepare ./cmd/prepare
	$(GO) build -o bin/session ./cmd/session

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

check: vet build test check-workflows

check-workflows:
	bash scripts/check-workflows.sh

verify-tasks: build
	bash scripts/verify-tasks.sh

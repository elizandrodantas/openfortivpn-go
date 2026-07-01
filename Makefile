BINARY    := openfortivpn
MODULE    := github.com/elizandrodantas/openfortivpn-go
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS   := -ldflags "-s -w -X $(MODULE)/pkg/version.Version=$(VERSION)"
CMD       := ./cmd/openfortivpn
DIST      := dist

TARGETS := \
	linux/amd64 \
	linux/arm64 \
	linux/arm \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: all build clean test lint help $(TARGETS)

## Default: build for current platform
all: build

## build: compile for the current platform
build:
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

## dist: cross-compile for all platforms (output in dist/)
dist: $(TARGETS)

$(TARGETS):
	$(eval OS   := $(word 1,$(subst /, ,$@)))
	$(eval ARCH := $(word 2,$(subst /, ,$@)))
	$(eval EXT  := $(if $(filter windows,$(OS)),.exe,))
	$(eval OUT  := $(DIST)/$(BINARY)_$(OS)_$(ARCH)$(EXT))
	@echo "  BUILD  $(OS)/$(ARCH)  →  $(OUT)"
	@mkdir -p $(DIST)
	@GOOS=$(OS) GOARCH=$(ARCH) CGO_ENABLED=0 go build $(LDFLAGS) -o $(OUT) $(CMD)

## test: run all tests with race detector
test:
	go test -race ./...

## lint: vet + staticcheck (install staticcheck if missing)
lint:
	go vet ./...
	@command -v staticcheck >/dev/null 2>&1 || \
		go install honnef.co/go/tools/cmd/staticcheck@latest
	staticcheck ./...

## clean: remove build artifacts
clean:
	rm -rf $(DIST) $(BINARY) $(BINARY).exe

## help: list available targets
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'

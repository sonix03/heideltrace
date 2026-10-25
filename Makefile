# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
#   make            build build/heideltrace (needs only Go)
#   make generate   recompile bpf/*.bpf.c after changing them (needs clang, llvm-strip)
#   make test       run the unit tests
#   make check      vet, unit tests, and a check that generated files are current
#
GO       ?= go
OUTPUT   := build
BINARY   := $(OUTPUT)/heideltrace
BPF_SRC  := $(wildcard bpf/*.bpf.c bpf/lib/*.h)

.PHONY: all build generate test vet check headers clean

all: build

# CGO is not needed, so the binary is static and can be copied to the
# GPU server as is.
build:
	@mkdir -p $(OUTPUT)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -o $(BINARY) ./cmd/heideltrace
	@echo "built $(BINARY)"

generate: $(BPF_SRC)
	$(GO) generate ./internal/bpf

test:
	$(GO) test ./...

vet:
	GOOS=linux $(GO) vet ./...

# Fails if bpf/ was changed without running `make generate`.
check: vet test
	$(GO) generate ./internal/bpf
	git diff --exit-code -- internal/bpf

# Refresh the vendored libbpf headers and vmlinux.h (needs bpftool).
headers:
	./bpf/headers/update.sh vmlinux

clean:
	rm -rf $(OUTPUT)

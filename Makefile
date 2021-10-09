GO		?= go
GOFMT		?= gofmt
WAST2JSON	?= wast2json
WAT2WASM	?= wat2wasm
PYTHON		?= python3
PERFLOCK	?= perflock
BENCHSTAT	?= benchstat

ARCH		:= $(shell $(GO) env GOARCH)

COMMON_PACKAGES	:= . $(patsubst %,./%/...,binary binding buffer compile errors internal/gen object section trap wa)
X86_PACKAGES	:= $(COMMON_PACKAGES) ./internal/isa/x86/...
ARM_PACKAGES	:= $(COMMON_PACKAGES) ./internal/isa/arm/...

ifeq ($(ARCH),amd64)
PACKAGES	:= $(X86_PACKAGES)
endif

ifeq ($(ARCH),arm64)
PACKAGES	:= $(ARM_PACKAGES)
endif

TEST		:=
ifneq ($(TEST),)
TESTFLAGS	+= -run="$(TEST)" -v
endif

BENCHFLAGS	+= -run=- -bench=.

-include config.mk

export GOFMT WAST2JSON WAT2WASM

.PHONY: build
build:
	$(GO) build $(BUILDFLAGS) -o bin/wasys ./cmd/wasys
	$(GO) build $(BUILDFLAGS) $(PACKAGES)
	$(GO) build $(BUILDFLAGS) -tags=wagamd64 $(X86_PACKAGES)
	$(GO) build $(BUILDFLAGS) -tags=wagarm64 $(ARM_PACKAGES)

	$(GO) vet $(BUILDFLAGS) $(PACKAGES)
	$(GO) vet $(BUILDFLAGS) -tags=wagamd64 $(X86_PACKAGES)
	$(GO) vet $(BUILDFLAGS) -tags=wagarm64 $(ARM_PACKAGES)

.PHONY: check
check: build
	$(GO) test $(TESTFLAGS) $(PACKAGES)

	cd testsuite && $(GO) vet $(BUILDFLAGS) ./...
	cd testsuite && $(GO) test $(TESTFLAGS) ./...

	bin/wasys $(WASYSFLAGS) testdata/hello.wasm
	bin/wasys $(WASYSFLAGS) testdata/rust/test.wasm

.PHONY: benchmark
benchmark:
	@ $(PERFLOCK) true
	$(PERFLOCK) $(GO) test $(BENCHFLAGS) $(PACKAGES) | tee bench-new.txt
	[ ! -e bench-old.txt ] || $(BENCHSTAT) bench-old.txt bench-new.txt

.PHONY: generate
generate:
	$(GO) generate
	cd testsuite && $(GO) generate

.PHONY: library
library:
	cd testsuite && $(GO) generate testdata/library.go

.PHONY: clean
clean:
	rm -f bin/wasys
	rm -rf testsuite/testdata/include
	rm -rf testsuite/testdata/specdata

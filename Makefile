GO		?= go
GOFMT		?= gofmt
STATICCHECK	?= staticcheck
WAST2JSON	?= wast2json
WAT2WASM	?= wat2wasm
PYTHON		?= python3
PERFLOCK	?= perflock
BENCHSTAT	?= benchstat

PACKAGES	:= . $(patsubst %,./%/...,binary binding buffer compile errors internal object section trap wa)

TEST		:=
ifneq ($(TEST),)
TESTFLAGS	+= -run="$(TEST)" -v
endif

BENCHFLAGS	+= -run=- -bench=.

-include config.mk

export GOFMT WAST2JSON WAT2WASM

.PHONY: build
build:
	GOARCH=amd64 $(GO) build $(BUILDFLAGS) $(PACKAGES)
	GOARCH=arm64 $(GO) build $(BUILDFLAGS) $(PACKAGES)
	$(GO) build $(BUILDFLAGS) -tags=wagamd64 $(PACKAGES)
	$(GO) build $(BUILDFLAGS) -tags=wagarm64 $(PACKAGES)

	GOARCH=amd64 $(GO) vet $(BUILDFLAGS) $(PACKAGES)
	GOARCH=arm64 $(GO) vet $(BUILDFLAGS) $(PACKAGES)
	$(GO) vet $(BUILDFLAGS) -tags=wagamd64 $(PACKAGES)
	$(GO) vet $(BUILDFLAGS) -tags=wagarm64 $(PACKAGES)

	$(STATICCHECK) ./...

.PHONY: check
check: build
	$(GO) test $(TESTFLAGS) $(PACKAGES)

	cd testsuite && $(GO) vet $(BUILDFLAGS) ./...
	cd testsuite && $(GO) test $(TESTFLAGS) ./...

.PHONY: benchmark
benchmark:
	@ $(PERFLOCK) true
	$(PERFLOCK) $(GO) test $(BENCHFLAGS) $(PACKAGES) | tee bench-new.txt
	[ ! -e bench-old.txt ] || $(BENCHSTAT) bench-old.txt bench-new.txt

.PHONY: generate
generate:
	GOARCH=amd64 $(GO) generate ./internal/isa/...
	GOARCH=arm64 $(GO) generate ./internal/isa/...
	cd testsuite && $(GO) generate

.PHONY: library
library:
	cd testsuite && $(GO) generate testdata/library.go

.PHONY: clean
clean:
	rm -f internal/isa/*/*.elf internal/isa/*/*.o
	rm -rf testsuite/testdata/include
	rm -rf testsuite/testdata/specdata

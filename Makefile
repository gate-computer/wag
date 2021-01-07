GO		?= go
GOFMT		?= gofmt
GOFUZZ		?= go-fuzz
PERFLOCK	?= perflock
BENCHCMP	?= benchstat

ARCH		:= $(shell $(GO) env GOARCH)

PACKAGES	:= . $(patsubst %,./%/...,binary binding buffer compile errors internal/gen object section trap wa)
X86_PACKAGES	:= ./internal/isa/x86/...
ARM_PACKAGES	:= ./internal/isa/arm/...

ifeq ($(ARCH),amd64)
ARCH_PACKAGES	:= $(X86_PACKAGES)
LINKFLAGS	:= -ldflags="-linkmode=internal"
MAINTESTENV	:=
endif

ifeq ($(ARCH),arm64)
ARCH_PACKAGES	:= $(ARM_PACKAGES)
LINKFLAGS	:=
MAINTESTENV	:= CGO_ENABLED=0
endif

TESTFLAGS	+= $(LINKFLAGS)
BENCHFLAGS	+= $(LINKFLAGS) -run=^TestBenchmark -bench=.

-include config.mk

export PATH	:= testdata/wabt/bin:$(PATH)

generate: testdata/wabt/bin/wat2wasm
	GOFMT=$(GOFMT) $(GO) generate

build: generate
	$(GO) build $(BUILDFLAGS) $(PACKAGES)
	$(GO) build $(BUILDFLAGS) -tags=wagamd64 $(PACKAGES)
	$(GO) build $(BUILDFLAGS) -tags=wagarm64 $(PACKAGES)
	$(GO) build $(BUILDFLAGS) -o bin/wasys ./cmd/wasys

vet: build
	$(GO) vet $(VETFLAGS) $(PACKAGES) $(ARCH_PACKAGES)
	$(GO) vet $(VETFLAGS) -tags=wagamd64 $(PACKAGES) $(X86_PACKAGES)
	$(GO) vet $(VETFLAGS) -tags=wagarm64 $(PACKAGES) $(ARM_PACKAGES)

check: vet
	$(MAINTESTENV) $(GO) test $(TESTFLAGS) $(PACKAGES)
	$(GO) test $(TESTFLAGS) $(ARCH_PACKAGES)
	$(GO) test $(TESTFLAGS) -tags=wagamd64 -run=^TestFuzz
	$(GO) test $(TESTFLAGS) -tags=wagarm64 -run=^TestFuzz
	bin/wasys $(WASYSFLAGS) testdata/hello.wasm
	bin/wasys $(WASYSFLAGS) testdata/rust/test.wasm

benchmark:
	$(PERFLOCK) true
	$(PERFLOCK) $(GO) test $(BENCHFLAGS) $(PACKAGES) $(ARCH_PACKAGES) | tee bench-new.txt
	[ ! -e bench-old.txt ] || $(BENCHCMP) bench-old.txt bench-new.txt

testdata/wabt/bin/wat2wasm:
	$(MAKE) -C testdata/wabt

fuzz-build:
	$(GOFUZZ)-build

fuzz:
	[ -e testdata/fuzz ]
	$(GOFUZZ) -bin=wag-fuzz.zip -workdir=testdata/fuzz

clean:
	$(MAKE) -C testdata/wabt clean
	rm -rf bin testdata/wabt/bin
	rm -f wag-fuzz.zip

.PHONY: generate build vet check benchmark fuzz-build fuzz clean

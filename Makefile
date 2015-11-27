GO	:= go
GOPATH	:= $(PWD)

export GOPATH

check:
	$(GO) fmt .
	$(GO) vet .
	$(GO) test -v .

.PHONY: check

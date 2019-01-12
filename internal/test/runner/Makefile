GO		?= go
GOOS		?= $(shell $(GO) env GOOS)
GOARCH		?= $(shell $(GO) env GOARCH)

runtime_$(GOOS)_$(GOARCH).syso: runtime/$(GOARCH).S Makefile
	$(CC) $(CFLAGS) -c -o $@ runtime/$(GOARCH).S

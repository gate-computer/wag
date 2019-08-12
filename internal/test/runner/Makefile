GO		?= go
GOOS		?= $(shell $(GO) env GOOS)
GOARCH		?= $(shell $(GO) env GOARCH)

CPPFLAGS	+= -DPIC -Iruntime/$(GOARCH)
CFLAGS		+= -fpic -fomit-frame-pointer -fno-stack-protector -Wall -Wextra

runtime_$(GOOS)_$(GOARCH).syso: Makefile runtime/runtime.c $(wildcard runtime/$(GOARCH)/*.h)
#	$(CC) $(CPPFLAGS) $(CFLAGS) -S -o /tmp/runtime.s runtime/runtime.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ runtime/runtime.c

**wag** is a [WebAssembly](http://webassembly.org) compiler implemented as a
[Go](https://golang.org) package.

- License: [3-clause BSD](LICENSE)
- Author: Timo Savola <timo.savola@iki.fi>


Features
--------

- Source is a wasm32 binary module.  The application embedding the compiler
  decides what import functions it provides.

- Supports x86-64.  Support for 64-bit ARM is planned.  (Support for non-64-bit
  or non-little-endian CPU architectures isn't planned.)

- Single-pass, low-latency ahead-of-time compilation.  Early functions can be
  executed while the latter functions are still being compiled, even while the
  source is still being downloaded.

- Generated code requires minimal runtime support.  It may be run e.g. in a
  strict [seccomp](https://en.wikipedia.org/wiki/Seccomp) sandbox.
  Note: calling standard library ABIs is not supported.

- Supports snapshot-and-restore across compiler versions and CPU architectures.


Status
------

- WebAssembly binary encoding version 1.

- Some floating-point instructions haven't been implemented yet.

- The Go package API hasn't been finalized.

- Cross-compilation will be supported once the backend interface stabilizes.

- Multithreading is not supported.  (WebAssembly doesn't define it yet.)

- Much debugging remains to be done...


Testing
-------

Requires Linux, Go, make, clang and libcapstone.  50% of the WebAssembly spec
testsuite is run, by first converting the tests to binary format:

1. `go get -t github.com/tsavola/wag`
2. `make -C $GOPATH/src/github.com/tsavola/wag/testdata/wabt`
3. `go test -v github.com/tsavola/wag`

The [wag-toolchain](https://github.com/tsavola/wag-toolchain) repository tests
input from a C/C++ compiler.


Screenshot
----------

```
=== RUN   TestSnapshot
--- PASS: TestSnapshot (0.00s)
	snapshot_test.go:73: print output:
		10
		--- snapshotting ---
		current memory limit: 0x6a96051ca000
		current stack ptr:    0x6a960533ffc0
		globals+memory addr:  0x6a96051ba000
		stack addr:           0x6a960533f000
		globals+memory size:  65536
		memory size:          65536
		stack offset:         4032
		stacktrace:
		#1  func-3
		#2  func-2
		--- shot snapped ---
		20
	snapshot_test.go:81: resuming
	snapshot_test.go:93: print output:
		20
		30
		330
		40
		440
```

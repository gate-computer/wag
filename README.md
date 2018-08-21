**wag** is a [WebAssembly](https://webassembly.org) compiler (or assembler?)
implemented as a [Go](https://golang.org) package.

- License: [3-clause BSD](LICENSE)
- Author: Timo Savola <timo.savola@iki.fi>


Features
--------

- The input is a wasm32 binary module.  The embedders of the compiler decide
  what kind of import functions they choose to implement and make available for
  the WebAssembly programs.

- The output is executable x86-64 machine code.  Support for 64-bit ARM is
  planned.  (Support for non-64-bit or non-little-endian CPU architectures
  isn't planned.)

- Single-pass, fast ahead-of-time compilation.  Early functions can be executed
  while the latter functions are still being compiled, even while the source is
  still being downloaded.

- The generated code requires minimal runtime support; it's designed to be
  executed in an isolated environment.  Calling standard library ABIs is not
  supported, but see [wasys](cmd/wasys) for an example program which exposes
  syscalls as WebAssembly import functions.

- Supports snapshot-and-restore across compiler versions and CPU architectures.


Status
------

- Implements WebAssembly binary encoding version 1.

- The Go package API hasn't been finalized.

- The snapshot-and-restore functionality is beta quality.


Testing
-------

Requires Linux, Go, make, clang and libcapstone.  About 75% of the WebAssembly
spec testsuite is run, by first converting the tests to binary format:

1. `go get -t github.com/tsavola/wag`
2. `make -C $GOPATH/src/github.com/tsavola/wag/testdata/wabt`
3. `go test -v github.com/tsavola/wag`


Screenshot #1
-------------

```
$ go get github.com/tsavola/wag/cmd/wasys
$ wasys -v $GOPATH/src/github.com/tsavola/wag/testdata/hello.wasm
import write(i32, i32, i32) i32
import open(i32, i32, i32) i32
import read(i32, i32, i32) i32
import close(i32) i32
import pipe2(i32, i32) i32
import _exit(i32)
hello, world
```

Screenshot #2
-------------

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

**wag** is a [WebAssembly](https://webassembly.org) compiler implemented as a
[Go](https://golang.org) package.

- License: [3-clause BSD](LICENSE)
- Author: Timo Savola <timo.savola@iki.fi>


Features
--------

- The input is a wasm binary module.

- The output is machine code.

- It is only a compiler.  A runtime environment for the compiled program,
  including all import functions, needs to be implemented separately.  (But see
  [wasys](cmd/wasys) for an example runtime.)

- Single-pass, fast ahead-of-time compilation.  Early functions can be executed
  while the latter functions are still being compiled, even while the source is
  still being downloaded.

- The generated code requires minimal runtime support; it's designed to be
  executed in an isolated environment.  Calling standard library ABIs is not
  directly supported, but see [wasys](cmd/wasys) for an example which exposes
  syscalls as WebAssembly import functions.

- Supports snapshot-and-restore across compiler versions and CPU architectures.

- Supports breakpoint debugging via recompilation.

- Cross-compilation is supported via Go build tags.  If `wagamd64` is
  specified, the x86-64 code generator is used regardless of host architecture,
  and CPU feature detection is disabled with pessimistic assumptions.  Likewise
  for `wagarm64` (but feature detection is not used for ARM64).


Status
------

- Supports WebAssembly version 1 (wasm32).  No wasm extensions are supported.

- Supports x86-64 and ARM64 code generation.

- Go package API and object code ABI are stable.

- Generated x86-64 code requires SSE4.1 ROUNDSS/ROUNDSD instructions.


Security
--------

[Spectre](https://spectreattack.com) variant 1: Out-of-bounds linear memory
access detection requires that addressable but unallocated memory is
inaccessible.  It naturally prevents conditional branch exploitation.

Spectre variant 2: On x86, [Retpoline](https://support.google.com/faqs/answer/7625886)
is used to protect the runtime environment (although user programs shouldn't be
able to inject arbitrary addresses into the branch target buffer).


Testing
-------

Requires Linux, Go, make, cmake, clang++ and libcapstone.  About 75% of the
WebAssembly spec testsuite is run, by first converting the tests to binary
format:

- `git clone --recurse-submodules https://github.com/tsavola/wag.git`
- `cd wag`
- `make check`


Screenshot #1
-------------

```
$ go get github.com/tsavola/wag/cmd/wasys
$ wasys -v $GOPATH/src/github.com/tsavola/wag/testdata/hello.wasm
import write(i32, i32, i32) i32
import openat(i32, i32, i32, i32) i32
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
    snapshot_test.go:80: print output:
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
    snapshot_test.go:88: resuming
    snapshot_test.go:100: print output:
        20
        30
        330
        40
        440
```

Wag is a [WebAssembly](https://webassembly.org) compiler implemented as a
[Go](https://golang.org) package.

- License: [3-clause BSD](LICENSE)
- Author: Timo Savola <timo.savola@iki.fi>


Features
--------

- The input is a wasm binary module.

- The output is machine code.

- It is only a compiler.  A runtime environment for the compiled program,
  including all import functions, needs to be implemented separately.  Wag has
  been developed for the [Gate](https://gate.computer/gate) runtime.  See
  [wasys](cmd/wasys) for a simple example runtime.

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

- Generated x86-64 code requires SSE4.1 floating-point instructions (available
  since 2007).


Security
--------

[Spectre](https://spectreattack.com) variant 1: Out-of-bounds linear memory
access detection requires that addressable but unallocated memory is
inaccessible.  It naturally prevents conditional branch exploitation.

Spectre variant 2: On x86-64, [Retpoline](https://support.google.com/faqs/answer/7625886)
is used to protect the runtime environment (although user programs shouldn't be
able to inject arbitrary addresses into the branch target buffer).


Testing
-------

Requires Linux, Make, Go, Python, [Capstone](https://www.capstone-engine.org),
and a recent version of [WABT](https://github.com/WebAssembly/wabt).
The applicable parts of the WebAssembly spec testsuite are
run[<sup>*</sup>](https://github.com/gate-computer/wag/issues/21).
Code execution tests are implemented in a separate Go module in the testsuite
subdirectory (to work around circular dependencies).  All tests can be run by
checking out Git submodules and running `make check`.


Screenshot
----------

	$ make
	$ bin/wasys -v testdata/hello.wasm
	import write(i32, i32, i32) i32
	import openat(i32, i32, i32, i32) i32
	import read(i32, i32, i32) i32
	import close(i32) i32
	import pipe2(i32, i32) i32
	import _exit(i32)
	hello, world


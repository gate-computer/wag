// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func run(text []byte, initialMemorySize int, memoryAddr uintptr, stack []byte, stackOffset, resumeResult, slaveFd int, arg int64) (trapId uint64, currentMemorySize int, stackPtr uintptr)
TEXT ·run(SB),NOSPLIT,$0-128
	MOVQ	text+0(FP), R15
	MOVQ	initialMemorySize+24(FP), R13
	MOVQ	memoryAddr+32(FP), R14	// memory ptr
	MOVQ	stack+40(FP), BX	// stack limit
	MOVQ	stackOffset+64(FP), CX
	MOVQ	resumeResult+72(FP), AX	// resume result (0 = don't resume)
	MOVQ	slaveFd+80(FP), DI	// slave fd
	MOVQ	arg+88(FP), DX		// arg
	JMP	run<>(SB)

// func ObjectRuntime() (slice []byte, addr uint64)
TEXT ·ObjectRuntime(SB),$0-32
	LEAQ	objectRuntimeStart<>(SB), AX
	LEAQ	objectRuntimeEnd<>(SB), BX
	SUBQ	AX, BX
	MOVQ	AX, slice+0(FP)		// data
	MOVQ	BX, slice+8(FP)		// len
	MOVQ	BX, slice+16(FP)	// cap
	MOVQ	AX, addr+24(FP)
	RET

TEXT objectRuntimeStart<>(SB),NOSPLIT,$0
	MOVQ	$0x300000000, AX
	MOVQ	(AX), CX		// stack frame size
	ADDQ	CX, AX			// at last item of stack frame data
	SHRQ	$3, CX			// stack item count
	JE	nocopy

copy:	MOVQ	(AX), BX
	SUBQ	$8, AX
	PUSHQ	BX
	LOOP	copy			// decrement CX and jump if not zero

nocopy:	XORL	AX, AX			// resume
	MOVQ	SP, BX			// stack ptr
	MOVQ	$0x100000, CX		// stack offset
	SUBQ	CX, BX			// stack limit
	XORL	DX, DX			// arg
	MOVL	$1023, DI		// slave fd
	MOVQ	$0x1000000, R13		// init memory size
	MOVQ	$0x400000000, R14	// memory
	MOVQ	$0x200000000, R15	// text

	SUBQ	$256, SP		// space for args and results
	CALL	run<>(SB)

	MOVL	$0, DI			// exit status
	MOVL	$231, AX		// exit_group syscall
	SYSCALL
	HLT

TEXT run<>(SB),NOSPLIT,$0-8
	ADDQ	R14, R13		// current memory limit
	ADDQ	BX, CX			// stack ptr
	ADDQ	$128, BX		// for imports and traps
	ADDQ	$16, BX			// call + stack check trap call
	MOVQ	DI, M6			// slave fd
	PUSHQ	DX			// arg
	MOVQ	SP, M7			// original stack
	MOVQ	CX, SP			// stack ptr
	LEAQ	16(R15), DI		// resume routine
	TESTQ	AX, AX
	JNE	resume
	ADDQ	$16, DI			// init routine
resume:	JMP	DI			// returns via trap handler

TEXT resume<>(SB),NOSPLIT,$0
	LEAQ	16(R15), DI		// resume routine
	JMP	DI

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	LEAQ	trapHandler<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT trapHandler<>(SB),NOSPLIT,$0-128
	CMPL	AX, $3			// CallStackExhausted
	JNE	skip
	TESTB	$1, BX
	JE	skip
	MOVL	$2, AX			// Suspended
skip:
	CMPL	AX, $1			// MissingFunction
	JE	pause

	MOVQ	SP, R11			// stack ptr
	MOVQ	M7, SP			// original stack
	ADDQ	$8, SP			// arg
	MOVQ	AX, trapId+96(FP)
	SUBQ	R14, R13
	MOVQ	R13, currentMemorySize+104(FP)
	MOVQ	R11, stackPtr+112(FP)
	RET				// return from run function

pause:
	PUSHQ	CX
	PUSHQ	SI
	PUSHQ	DI
	PUSHQ	R11

	MOVL	$1, AX		// sys_write
	MOVQ	M6, DI 		// fd
	LEAQ	-8(SP), SI	// buf
	MOVQ	$-2, (SI)	// buf content
	MOVL	$8, DX		// bufsize
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	XORL	AX, AX		// sys_read
	MOVL	$1, DX		// bufsize
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	POPQ	R11
	POPQ	DI
	POPQ	SI
	POPQ	CX

	SUBQ	$5, (SP)	// move return address before the call that got us here
	JMP	resume<>(SB)

fail:
	MOVQ	$3003, AX
	JMP	trapHandler<>(SB)

// func importSpectestPrint() uint64
TEXT ·importSpectestPrint(SB),$0-8
	LEAQ	spectestPrint<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT spectestPrint<>(SB),NOSPLIT,$0
	MOVQ	(SP), R9	// save link address

	MOVL	$1, AX		// sys_write
	MOVQ	M6, DI 		// fd
	MOVQ	BP, DX		// (argcount << 32) | sigindex
	SHRQ	$32, DX		// argcount
	INCL	DX		// 1 + argcount
	SHLL	$3, DX		// (1 + argcount) * wordsize = bufsize
	MOVQ	SP, SI		// buf
	MOVL	BP, BP		// sigindex
	MOVQ	BP, (SI)	// write sigindex before args (replace link address)
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	MOVQ	R9, (SP)	// restore link address
	XORL	AX, AX
	JMP	resume<>(SB)

fail:
	MOVQ	$3001, AX
	JMP	trapHandler<>(SB)

// func importPutns() uint64
TEXT ·importPutns(SB),$0-8
	LEAQ	putns<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT putns<>(SB),NOSPLIT,$0
	MOVQ	16(SP), R8	// relative addr
	MOVQ	8(SP), R9	// size

	ADDQ	R14, R8		// absolute addr
	CMPQ	R14, R8
	JG	fail1		// absolute addr out of lower bound

	MOVQ	R8, AX
	ADDQ	R9, AX		// absolute addr+size
	CMPQ	R13, AX
	JLE	fail2		// absolute addr+size out of upper bound

	MOVQ	M6, DI 		// fd
	LEAQ	-12(SP), SI	// buf
	MOVL	$12, DX		// bufsize

	MOVQ	$-3, (SI)	// command
	MOVL	R9, 8(SI)	// size

	MOVL	$1, AX		// sys_write
	SYSCALL
	CMPQ	DX, AX
	JNE	fail3

	MOVQ	R8, SI		// buf <- absolute addr
	MOVL	R9, DX		// bufsize <- size

	MOVL	$1, AX		// sys_write
	SYSCALL
	CMPQ	DX, AX
	JNE	fail4

	XORL	AX, AX
	JMP	resume<>(SB)

fail1:
	MOVQ	$3001, AX
	JMP	trapHandler<>(SB)

fail2:
	MOVQ	$3002, AX
	JMP	trapHandler<>(SB)

fail3:
	MOVQ	$3003, AX
	JMP	trapHandler<>(SB)

fail4:
	MOVQ	$3004, AX
	JMP	trapHandler<>(SB)

// func importBenchmarkBegin() uint64
TEXT ·importBenchmarkBegin(SB),$0-8
	LEAQ	benchmarkBegin<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT benchmarkBegin<>(SB),NOSPLIT,$0
	MOVQ	BX, R9

	CPUID			// serialize
	RDTSC
	SHLQ	$32, DX
	ORQ	DX, AX

	MOVQ	R9, BX
	JMP	resume<>(SB)

// func importBenchmarkEnd() uint64
TEXT ·importBenchmarkEnd(SB),$0-8
	LEAQ	benchmarkEnd<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT benchmarkEnd<>(SB),NOSPLIT,$0
	MOVQ	BX, R9

	RDTSC
	SHLQ	$32, DX
	ORQ	DX, AX
	SUBQ	8(SP), AX
	MOVL	$-1, DX
	MOVQ	$0x80000000, CX
	CMPQ	CX, AX
	CMOVLLE	DX, AX

	MOVQ	R9, BX
	JMP	resume<>(SB)

// func importBenchmarkBarrier() uint64
TEXT ·importBenchmarkBarrier(SB),$0-8
	LEAQ	benchmarkBarrier<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT benchmarkBarrier<>(SB),NOSPLIT,$0
	MOVQ	16(SP), AX
	JMP	resume<>(SB)

// func importGetArg() uint64
TEXT ·importGetArg(SB),$0-8
	LEAQ	getArg<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT getArg<>(SB),NOSPLIT,$0
	MOVQ	M7, AX			// original stack
	MOVQ	(AX), AX		// arg
	JMP	resume<>(SB)

// func importSnapshot() uint64
TEXT ·importSnapshot(SB),$0-8
	LEAQ	snapshot<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT snapshot<>(SB),NOSPLIT,$0
	MOVL	$1, AX		// sys_write
	MOVQ	M6, DI 		// fd
	LEAQ	-8(SP), SI	// buf
	MOVQ	$-1, (SI)	// buf contents
	MOVL	$8, DX		// bufsize
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	MOVL	$1, AX		// sys_write
	MOVQ	R13, (SI)	// buf contents
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	MOVL	$1, AX		// sys_write
	MOVQ	SP, (SI)	// buf contents
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	XORL	AX, AX		// sys_read
	SYSCALL
	SUBQ	DX, AX
	JNE	fail
	MOVQ	(SI), AX	// snapshot id

	JMP	resume<>(SB)

fail:
	MOVQ	$3002, AX
	JMP	trapHandler<>(SB)

// func importSuspendNextCall() uint64
TEXT ·importSuspendNextCall(SB),$0-8
	LEAQ	suspendNextCall<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT suspendNextCall<>(SB),NOSPLIT,$0
	MOVQ	$-8, BX		// even value doesn't suspend loops
	JMP	resume<>(SB)

fail:
	MOVQ	$3002, AX
	JMP	trapHandler<>(SB)

TEXT objectRuntimeEnd<>(SB),NOSPLIT,$0

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func run(text []byte, initialMemorySize int, memoryAddr, growMemorySize, roDataBase uintptr, stack []byte, stackOffset, resumeResult, slaveFd int, arg int64) (trapId uint64, currentMemorySize int, stackPtr uintptr)
TEXT ·run(SB),NOSPLIT,$0-144
	MOVQ	text+0(FP), R15
	MOVQ	initialMemorySize+24(FP), R13
	MOVQ	memoryAddr+32(FP), R14	// memory ptr
	MOVQ	growMemorySize+40(FP), R11
	ADDQ	R14, R13		// current memory limit
	ADDQ	R14, R11		// memory growth limit
	MOVQ	stack+56(FP), BX	// stack limit
	MOVQ	stackOffset+80(FP), CX
	ADDQ	BX, CX			// stack ptr
	ADDQ	$128, BX		// red zone (for imports and traps)
	MOVQ	resumeResult+88(FP), AX	// resume result (0 = don't resume)
	MOVQ	slaveFd+96(FP), M6	// slave fd
	MOVQ	arg+104(FP), DX		// arg
	LEAQ	trap<>(SB), R8
	MOVQ	R8, M0			// trap handler
	MOVQ	R11, M1			// memory growth limit
	PUSHQ	DX			// arg
	MOVQ	SP, M7			// original stack
	MOVQ	CX, SP			// stack ptr
	MOVQ	R15, DI
	ADDQ	$16, DI			// init routine address
	JMP	DI			// returns via trap handler

TEXT trap<>(SB),NOSPLIT,$0-144
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
	MOVQ	AX, trapId+112(FP)
	SUBQ	R14, R13
	MOVQ	R13, currentMemorySize+120(FP)
	MOVQ	R11, stackPtr+128(FP)
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
	XORL	DX, DX
	RET

fail:
	MOVQ	$3003, AX
	JMP	trap<>(SB)

// func importSpectestPrint() uint64
TEXT ·importSpectestPrint(SB),$0-8
	PUSHQ	AX
	LEAQ	spectestPrint<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
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
	XORL	DX, DX
	RET

fail:
	MOVQ	$3001, AX
	JMP	trap<>(SB)

// func importPutns() uint64
TEXT ·importPutns(SB),$0-8
	PUSHQ	AX
	LEAQ	putns<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
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
	XORL	DX, DX
	RET

fail1:
	MOVQ	$3001, AX
	JMP	trap<>(SB)

fail2:
	MOVQ	$3002, AX
	JMP	trap<>(SB)

fail3:
	MOVQ	$3003, AX
	JMP	trap<>(SB)

fail4:
	MOVQ	$3004, AX
	JMP	trap<>(SB)

// func importBenchmarkBegin() uint64
TEXT ·importBenchmarkBegin(SB),$0-8
	PUSHQ	AX
	LEAQ	benchmarkBegin<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
	RET

TEXT benchmarkBegin<>(SB),NOSPLIT,$0
	MOVQ	BX, R9

	CPUID			// serialize
	RDTSC
	SHLQ	$32, DX
	ORQ	DX, AX

	MOVQ	R9, BX
	XORL	DX, DX
	RET

// func importBenchmarkEnd() uint64
TEXT ·importBenchmarkEnd(SB),$0-8
	PUSHQ	AX
	LEAQ	benchmarkEnd<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
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
	XORL	DX, DX
	RET

// func importBenchmarkBarrier() uint64
TEXT ·importBenchmarkBarrier(SB),$0-8
	PUSHQ	AX
	LEAQ	benchmarkBarrier<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
	RET

TEXT benchmarkBarrier<>(SB),NOSPLIT,$0
	MOVQ	16(SP), AX

	XORL	DX, DX
	RET

// func importGetArg() uint64
TEXT ·importGetArg(SB),$0-8
	PUSHQ	AX
	LEAQ	getArg<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
	RET

TEXT getArg<>(SB),NOSPLIT,$0
	MOVQ	M7, AX			// original stack
	MOVQ	(AX), AX		// arg

	XORL	DX, DX
	RET

// func importSnapshot() uint64
TEXT ·importSnapshot(SB),$0-8
	PUSHQ	AX
	LEAQ	snapshot<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
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

	XORL	DX, DX
	RET

fail:
	MOVQ	$3002, AX
	JMP	trap<>(SB)

// func importSuspendNextCall() uint64
TEXT ·importSuspendNextCall(SB),$0-8
	PUSHQ	AX
	LEAQ	suspendNextCall<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
	RET

TEXT suspendNextCall<>(SB),NOSPLIT,$0
	MOVQ	$-8, BX		// even value doesn't suspend loops

	XORL	DX, DX
	RET

fail:
	MOVQ	$3002, AX
	JMP	trap<>(SB)

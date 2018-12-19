// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func clearInstructionCache()
TEXT ·clearInstructionCache(SB),$0
	DSB	$0xf
	ISB	$0xf
	RET

// func run(text []byte, initialMemorySize int, memoryAddr uintptr, stack []byte, stackOffset, resumeResult, slaveFd int, arg int64) (trapId uint64, currentMemorySize int, stackPtr uintptr)
TEXT ·run(SB),NOSPLIT,$0-120
	MOVD	text+0(FP), R27
	MOVD	initialMemorySize+24(FP), R7
	MOVD	memoryAddr+32(FP), R26
	MOVD	stack+40(FP), R2	// stack limit
	MOVD	stackOffset+64(FP), R3
	MOVD	resumeResult+72(FP), R0	// resume result
	MOVD	slaveFd+80(FP), R4	// slave fd
	MOVD	arg+88(FP), R5		// arg
	B	run<>(SB)

// func ObjectRuntime() (slice []byte, addr uint64)
TEXT ·ObjectRuntime(SB),$0-32
	BL	at
	MOVD	LR, R0
	BL	objectRuntimeEnd<>(SB)	// end address returned in R1
	SUB	R0, R1
	MOVD	R0, slice_base+0(FP)
	MOVD	R1, slice_len+8(FP)
	MOVD	R1, slice_cap+16(FP)
	MOVD	R0, addr+24(FP)
	RET

at:	BL	(LR)

start:	MOVD	$0, R0			// resume result
	MOVD	$0x80000000, R1		// grow memory size
	MOVD	$0x100000, R3		// stack offset
	SUB	R3, RSP, R2		// stack limit
	MOVD	$1023, R4		// slave fd
	MOVD	$0, R5			// arg
	MOVD	$0x1000000, R7		// init memory size
	MOVD	$0x300000000, R26	// memory
	MOVD	$0x200000000, R27	// text

	SUB	$256, RSP		// space for args and results
	BL	run<>(SB)

	MOVD	$0, R0			// exit status
	MOVD	$94, R8			// exit_group syscall
	SVC
	BRK

TEXT run<>(SB),NOSPLIT,$0-8
	DSB	$0xf
	ISB	$0xf

	ADD	R26, R7, R25		// current memory limit

	ADD	R2, R3, R29		// fake stack ptr
	MOVD	RSP, R6
	MOVD	R2, RSP			// real stack ptr

	MOVD	R5, 0(RSP)		// arg
	MOVD	R4, 8(RSP)		// slave fd
	MOVD	g, 16(RSP)
	MOVD	R6, 24(RSP)		// original stack ptr
	ADD	$32, R2

	ADD	$128, R2		// for imports and traps
	ADD	$16, R2			// call + stack check trap call
	LSR	$4, R2
	MOVD	R2, g			// stack limit / 16 (R28)

	MOVD	R27, R1
	ADD	$16, R1			// resume routine
	CBNZ	R0, resume
	ADD	$16, R1			// init routine
resume:	B	(R1)			// returns via trap handler

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	BL	after

	CMP	$3, R0			// CallStackExhausted
	BNE	nosusp
	TBNZ	$0, g, nosusp		// R28
	MOVD	$2, R0			// Suspended

nosusp:	CMP	$1, R0			// NoFunction
	BEQ	pause

return:	MOVD	16(RSP), g
	MOVD	24(RSP), R6		// original stack ptr
	MOVD	R6, RSP

	MOVD	R0, trapID+112(FP)
	SUB	R26, R25
	MOVD	R25, currentMemorySize+120(FP)
	MOVD	R29, stackPtr+128(FP)
	RET

pause:	MOVD	$64, R8		// sys_write
	MOVD	8(RSP), R0	// fd
	MOVD	R29, R1
	SUB	$8, R1		// buf
	MOVD	$-2, R3
	MOVD	R3, (R1)	// buf content
	MOVD	$8, R2		// bufsize
	SVC
	SUB	R2, R0
	BNE	fail

	MOVD	$63, R8		// sys_read
	MOVD	8(RSP), R0	// fd
	MOVD	$1, R2		// bufsize
	SVC
	SUB	R2, R0
	BNE	fail

	SUB	$4, LR		// move return address before the call that got us here
	B	resume<>(SB)

fail:	MOVD	$3003, R0
	MOVD	-16(R29), R1	// trap handler
	B	(R1)		// trap

after:	MOVD	LR, ret+0(FP)
	RET

TEXT resume<>(SB),NOSPLIT,$0
	MOVD	R27, R1
	ADD	$16, R1		// resume routine
	B	(R1)

// func importSpectestPrint() uint64
TEXT ·importSpectestPrint(SB),$0-8
	BL	after

impl:	MOVD	$64, R8		// sys_write
	MOVD	8(RSP), R0	// fd
	MOVD	R2, R3		// (argcount << 32) | sigindex
	LSR	$32, R2		// argcount
	ADD	$1, R2		// 1 + argcount
	LSL	$3, R2		// (1 + argcount) * wordsize = bufsize
	MOVD	R29, R1
	SUB	$8, R1		// buf
	LSRW	$0, R3		// sigindex
	MOVD	R3, (R1)	// write sigindex before args
	SVC
	SUBS	R2, R0
	BNE	fail
	B	resume<>(SB)

fail:	MOVD	$3001, R0
	MOVD	-16(R29), R1	// trap handler
	B	(R1)		// trap

after:	MOVD	LR, ret+0(FP)
	RET

// func importPutns() uint64
TEXT ·importPutns(SB),$0-8
	BL	after

impl:	BRK
	B	resume<>(SB)

after:	MOVD	LR, ret+0(FP)
	RET

// func importBenchmarkBegin() uint64
TEXT ·importBenchmarkBegin(SB),$0-8
	BL	after

impl:	BRK
	B	resume<>(SB)

after:	MOVD	LR, ret+0(FP)
	RET

// func importBenchmarkEnd() uint64
TEXT ·importBenchmarkEnd(SB),$0-8
	BL	after

impl:	BRK
	B	resume<>(SB)

after:	MOVD	LR, ret+0(FP)
	RET

// func importBenchmarkBarrier() uint64
TEXT ·importBenchmarkBarrier(SB),$0-8
	BL	after

impl:	BRK
	B	resume<>(SB)

after:	MOVD	LR, ret+0(FP)
	RET

// func importGetArg() uint64
TEXT ·importGetArg(SB),$0-8
	BL	after

impl:	MOVD	0(RSP), R0	// arg
	B	resume<>(SB)

after:	MOVD	LR, ret+0(FP)
	RET

// func importSnapshot() uint64
TEXT ·importSnapshot(SB),$0-8
	BL	after

impl:	BRK
	B	resume<>(SB)

after:	MOVD	LR, ret+0(FP)
	RET

// func importSuspendNextCall() uint64
TEXT ·importSuspendNextCall(SB),$0-8
	BL	after

impl:	BRK
	B	resume<>(SB)

after:	MOVD	LR, ret+0(FP)
	RET

TEXT objectRuntimeEnd<>(SB),NOSPLIT,$0
	// LR store instruction is inserted here	// 4 bytes
	BL	addr					// 4 bytes
	RET

addr:	SUB	$8, LR, R1				// 4+4 bytes
	B	(LR)

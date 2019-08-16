// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64,!cgo

#include "textflag.h"

#define import(func) \
	BL	after \
	B	func<>(SB) \
after:	MOVD	LR, ret+0(FP) \
	RET

#define call_C(func) \
	CALL	func(SB) \
	MOVD.P	16(RSP), LR		// it was stored by Go assembler

#define call_C_resume(func) \
	call_C(func) \
	B	resume<>(SB)

// func run(text []byte, memoryAddr uintptr, stack []byte, stackOffset, initOffset, slaveFd int, arg int64, resultFd int, forkStack []byte) int
TEXT ·run(SB),NOSPLIT,$0-128
	MOVD	text+0(FP), R0
	MOVD	memoryAddr+24(FP), R1
	MOVD	stack+32(FP), R2
	MOVD	stackOffset+56(FP), R3
	MOVD	initOffset+64(FP), R4
	MOVD	slaveFd+72(FP), R5
	MOVD	arg+80(FP), R6
	MOVD	resultFd+88(FP), R7
	MOVD	$state(SB), R8
	MOVD	forkStack+96(FP), R9
	ADD	$65536, R9
	MOVD	RSP, R10
	MOVD	R9, RSP
	SUB	$16, RSP
	MOVD	R8, 0(RSP)
	MOVD	R10, 8(RSP)
	CALL	run(SB)
	MOVD	8(RSP), R10
	MOVD	R10, RSP
	MOVD	R0, ret+120(FP)
	RET

TEXT resume<>(SB),NOSPLIT,$0
	ADD	$16, R27, R1		// resume routine
	B	(R1)

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),NOSPLIT,$0-8
	import(trapHandler)

TEXT trapHandler<>(SB),NOSPLIT,$0
	MOVD	R0, R2			// (result << 32) | trap_id
	LSL	$4, g, R0		// stack limit (g = R28)
	MOVD	R29, R1			// fake stack ptr
	MOVD	$state(SB), R3		// state
	call_C(trap_handler)
	SUB	$4, LR			// move return address before the call that got us here
	B	resume<>(SB)

// func importCurrentMemory() uint64
TEXT ·importCurrentMemory(SB),NOSPLIT,$0-8
	import(currentMemory)

TEXT currentMemory<>(SB),NOSPLIT,$0
	LSL	$4, g, R0		// stack limit (g = R28)
	call_C_resume(current_memory)

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),NOSPLIT,$0-8
	import(growMemory)

TEXT growMemory<>(SB),NOSPLIT,$0
	MOVD	R0, R3			// grow pages
	LSL	$4, g, R0		// stack limit (g = R28)
	MOVD	R26, R1			// memory addr
	MOVD	R27, R2			// text
	call_C_resume(grow_memory)

// func importSpectestPrint() uint64
TEXT ·importSpectestPrint(SB),NOSPLIT,$0-8
	import(spectestPrint)

TEXT spectestPrint<>(SB),NOSPLIT,$0
	MOVD	R2, R0			// (argcount << 32) | sigindex
	ADD	$16, RSP, R1		// args (RSP was adjusted by Go assembler)
	MOVD	$state(SB), R2		// state
	call_C_resume(spectest_print)

// func importPutns() uint64
TEXT ·importPutns(SB),NOSPLIT,$0-8
	import(putns)

TEXT putns<>(SB),NOSPLIT,$0
	// TODO: args
	call_C_resume(putns)

// func importBenchmarkBegin() uint64
TEXT ·importBenchmarkBegin(SB),NOSPLIT,$0-8
	import(resume)			// TODO

// func importBenchmarkEnd() uint64
TEXT ·importBenchmarkEnd(SB),NOSPLIT,$0-8
	import(resume)			// TODO

// func importBenchmarkBarrier() uint64
TEXT ·importBenchmarkBarrier(SB),NOSPLIT,$0-8
	import(resume)			// TODO

// func importGetArg() uint64
TEXT ·importGetArg(SB),NOSPLIT,$0-8
	import(getArg)

TEXT getArg<>(SB),NOSPLIT,$0
	MOVD	$state(SB), R0		// state
	call_C_resume(get_arg)

// func importSnapshot() uint64
TEXT ·importSnapshot(SB),NOSPLIT,$0-8
	import(snapshot)

TEXT snapshot<>(SB),NOSPLIT,$0
	LSL	$4, g, R0		// stack limit (g = R28)
	MOVD	R29, R1			// fake stack ptr
	MOVD	R26, R2			// memory addr
	MOVD	$state(SB), R3		// state
	call_C_resume(snapshot)

// func importSuspendNextCall() uint64
TEXT ·importSuspendNextCall(SB),NOSPLIT,$0-8
	import(resume)			// TODO

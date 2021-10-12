// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64,!cgo

#include "textflag.h"

#define import			\
	BL	after		\
	B	body		\
after:	MOVD	LR, ret+0(FP)	\
	RET			\
body:	MOVD.W	LR, -8(R29)

#define call_C(func) 		\
	CALL	func(SB)	\
	MOVD.P	8(R29), LR

#define call_C_resume(func)	\
	call_C(func)		\
	B	resume<>(SB)

// func run(text []byte, _ uintptr, stack []byte, stackOffset, initOffset, minionFd int, arg int64, resultFd int, forkStack []byte) int
TEXT ·run(SB),NOSPLIT,$0-128
	MOVD	text+0(FP), R0
	MOVD	stack+32(FP), R1
	MOVD	stackOffset+56(FP), R2
	MOVD	initOffset+64(FP), R3
	MOVD	minionFd+72(FP), R4
	MOVD	arg+80(FP), R5
	MOVD	resultFd+88(FP), R6
	MOVD	$state(SB), R7
	MOVD	forkStack+96(FP), R9
	MOVD	R7, 8(R1)		// store state ptr in stack vars
	ADD	$65536, R9
	MOVD	RSP, R10
	MOVD	R9, RSP
	SUB	$16, RSP
	MOVD	R7, 0(RSP)		// XXX: why is this needed?
	MOVD	R10, 8(RSP)
	CALL	run(SB)
	MOVD	8(RSP), R10
	MOVD	R10, RSP
	MOVD	R0, ret+120(FP)
	RET

TEXT resume<>(SB),NOSPLIT,$0
	ADD	$0x20, R27, R1		// resume routine
	B	(R1)

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),NOSPLIT,$0-8
	import
	MOVD	R0, R2			// (result << 32) | trap_id
	LSL	$4, g, R0		// stack limit (g = R28)
	MOVD	R29, R1			// fake stack ptr
	MOVD	$state(SB), R3		// state
	call_C(trap_handler)
	B	resume<>(SB)

// func importCurrentMemory() uint64
TEXT ·importCurrentMemory(SB),NOSPLIT,$0-8
	import
	LSL	$4, g, R0		// stack limit (g = R28)
	call_C_resume(current_memory)

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),NOSPLIT,$0-8
	import
	MOVD	R0, R3			// grow pages
	LSL	$4, g, R0		// stack limit (g = R28)
	MOVD	R26, R1			// memory addr
	MOVD	R27, R2			// text
	call_C_resume(grow_memory)

// func importSpectestPrint() uint64
TEXT ·importSpectestPrint(SB),NOSPLIT,$0-8
	import
	MOVD	R2, R0			// (argcount << 32) | sigindex
	ADD	$8, R29, R1		// args
	MOVD	$state(SB), R2		// state
	call_C_resume(spectest_print)

// func importPutns() uint64
TEXT ·importPutns(SB),NOSPLIT,$0-8
	import
	// TODO: args
	call_C_resume(putns)

// func importBenchmarkBegin() uint64
TEXT ·importBenchmarkBegin(SB),NOSPLIT,$0-8
	import
	call_C_resume(benchmark_begin)

// func importBenchmarkEnd() uint64
TEXT ·importBenchmarkEnd(SB),NOSPLIT,$0-8
	import
	MOVD	8(R29), R0		// begin
	call_C_resume(benchmark_end)

// func importBenchmarkBarrier() uint64
TEXT ·importBenchmarkBarrier(SB),NOSPLIT,$0-8
	import
	MOVD	16(R29), R0		// dummy
	MOVD.P	8(R29), LR
	B	resume<>(SB)

// func importGetArg() uint64
TEXT ·importGetArg(SB),NOSPLIT,$0-8
	import
	MOVD	$state(SB), R0		// state
	call_C_resume(get_arg)

// func importSnapshot() uint64
TEXT ·importSnapshot(SB),NOSPLIT,$0-8
	import
	LSL	$4, g, R0		// stack limit (g = R28)
	MOVD	R2, R1			// stack ptr for restarting caller
	MOVD	R26, R2			// memory addr
	MOVD	$state(SB), R3		// state
	MOVD	8(R29), R10		// wasm out addr
	ADD	R26, R10		// real out addr
	MOVW	$-1, R11
	MOVW	R11, (R10)
	MOVD	R2, R29			// -> fake stack ptr
	call_C(snapshot)
	MOVW	R0, (R10)
	B	resume<>(SB)

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

#define SYS_rt_sigreturn 15

// func run(text []byte, _ uintptr, stack []byte, stackOffset, initOffset, minionFd int, arg int64, resultFd int, forkStack []byte) int
TEXT ·run(SB),NOSPLIT,$0-128
	MOVQ	text+0(FP), DI
	MOVQ	stack+32(FP), SI
	MOVQ	stackOffset+56(FP), DX
	MOVQ	initOffset+64(FP), CX
	MOVQ	minionFd+72(FP), R8
	MOVQ	arg+80(FP), R9
	MOVQ	resultFd+88(FP), R10
	MOVQ	forkStack+96(FP), AX
	ADDQ	$65536, AX
	XCHGQ	AX, SP
	SUBQ	$32, SP
	MOVQ	AX, 24(SP)
	LEAQ	state(SB), AX
	MOVQ	AX, 8(SP)
	MOVQ	R10, 0(SP)
	CALL	run(SB)
	MOVQ	24(SP), SP
	MOVQ	AX, ret+120(FP)
	RET

TEXT resume<>(SB),NOSPLIT,$0
	LEAQ	16(R15), DI		// resume routine
	JMP	DI

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	LEAQ	trapHandler<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT trapHandler<>(SB),NOSPLIT,$0
	MOVQ	BX, DI			// stack limit
	MOVQ	SP, SI			// stack ptr
	MOVQ	AX, DX			// (result << 32) | trap_id
	LEAQ	state(SB), CX		// state
	CALL	trap_handler(SB)
	JMP	resume<>(SB)

// func importCurrentMemory() uint64
TEXT ·importCurrentMemory(SB),$0-8
	LEAQ	currentMemory<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT currentMemory<>(SB),NOSPLIT,$0
	MOVQ	BX, DI			// stack limit
	CALL	current_memory(SB)
	JMP	resume<>(SB)

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),$0-8
	LEAQ	growMemory<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT growMemory<>(SB),NOSPLIT,$0
	MOVQ	BX, DI			// stack limit
	MOVQ	R14, SI			// memory addr
	MOVQ	R15, DX			// text
	MOVD	AX, CX			// grow pages
	CALL	grow_memory(SB)
	JMP	resume<>(SB)

// func importSpectestPrint() uint64
TEXT ·importSpectestPrint(SB),$0-8
	LEAQ	spectestPrint<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT spectestPrint<>(SB),NOSPLIT,$0
	MOVQ	BP, DI			// (argcount << 32) | sigindex
	LEAQ	8(SP), SI		// args
	LEAQ	state(SB), DX		// state
	CALL	spectest_print(SB)
	JMP	resume<>(SB)

// func importPutns() uint64
TEXT ·importPutns(SB),$0-8
	LEAQ	putns<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT putns<>(SB),NOSPLIT,$0
	// TODO: args
	CALL	putns(SB)
	JMP	resume<>(SB)

// func importBenchmarkBegin() uint64
TEXT ·importBenchmarkBegin(SB),$0-8
	LEAQ	benchmarkBegin<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT benchmarkBegin<>(SB),NOSPLIT,$0
	CALL	benchmark_begin(SB)
	JMP	resume<>(SB)

// func importBenchmarkEnd() uint64
TEXT ·importBenchmarkEnd(SB),$0-8
	LEAQ	benchmarkEnd<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT benchmarkEnd<>(SB),NOSPLIT,$0
	MOVQ	8(SP), DI		// begin
	CALL	benchmark_end(SB)
	JMP	resume<>(SB)

// func importBenchmarkBarrier() uint64
TEXT ·importBenchmarkBarrier(SB),$0-8
	LEAQ	benchmarkBarrier<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT benchmarkBarrier<>(SB),NOSPLIT,$0
	MOVQ	16(SP), AX		// dummy
	JMP	resume<>(SB)

// func importGetArg() uint64
TEXT ·importGetArg(SB),$0-8
	LEAQ	getArg<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT getArg<>(SB),NOSPLIT,$0
	LEAQ	state(SB), DI		// state
	CALL	get_arg(SB)
	JMP	resume<>(SB)

// func importSnapshot() uint64
TEXT ·importSnapshot(SB),$0-8
	LEAQ	snapshot<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT snapshot<>(SB),NOSPLIT,$0
	MOVQ	BX, DI			// stack limit
	MOVQ	BP, SI			// stack ptr for restarting caller
	MOVQ	R14, DX			// memory addr
	LEAQ	state(SB), CX		// state
	MOVL	8(SP), R13		// wasm out addr
	ADDQ	R14, R13		// real out addr
	MOVL	$-1, (R13)
	CALL	snapshot(SB)
	MOVL	AX, (R13)
	MOVQ	BP, SP
	JMP	resume<>(SB)

TEXT sigsegv_handler(SB),NOSPLIT,$0
	MOVQ	160(DX), AX		// rsp in ucontext
	SUBQ	$8, AX
	MOVQ	AX, 160(DX)		// rsp in ucontext

	MOVQ	168(DX), BX		// rip in ucontext
	MOVQ	BX, (AX)

	LEAQ	sigsegvExit<>(SB), BX
	MOVQ	BX, 168(DX)		// rip in ucontext
	RET

TEXT sigsegvExit<>(SB),NOSPLIT,$0
	MOVD	$5, AX			// MemoryAccessOutOfBounds
	JMP	trapHandler<>(SB)

TEXT signal_restorer(SB),NOSPLIT,$0
	MOVD	$SYS_rt_sigreturn, AX
	SYSCALL
	HLT

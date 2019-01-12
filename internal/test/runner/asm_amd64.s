// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func run(text []byte, initialMemorySize int, memoryAddr uintptr, stack []byte, stackOffset, resumeResult, slaveFd int, arg int64) (trapId uint64, currentMemorySize int, stackPtr uintptr)
TEXT ·run(SB),NOSPLIT,$0-120
	MOVQ	text+0(FP), R15
	MOVQ	initialMemorySize+24(FP), R13
	MOVQ	memoryAddr+32(FP), R14	// memory ptr
	MOVQ	stack+40(FP), BX	// stack limit
	MOVQ	stackOffset+64(FP), CX
	MOVQ	resumeResult+72(FP), AX	// resume result (0 = don't resume)
	MOVQ	slaveFd+80(FP), DI	// slave fd
	MOVQ	arg+88(FP), DX		// arg
	JMP	run(SB)

// func ObjectRuntime() (slice []byte, addr uint64)
TEXT ·ObjectRuntime(SB),$0-32
	LEAQ	object_runtime_start(SB), AX
	LEAQ	object_runtime_end(SB), BX
	SUBQ	AX, BX
	MOVQ	AX, slice_base+0(FP)
	MOVQ	BX, slice_len+8(FP)
	MOVQ	BX, slice_cap+16(FP)
	MOVQ	AX, addr+24(FP)
	RET

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	LEAQ	trap_handler(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// func importSpectestPrint() uint64
TEXT ·importSpectestPrint(SB),$0-8
	LEAQ	spectest_print(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// func importPutns() uint64
TEXT ·importPutns(SB),$0-8
	LEAQ	putns(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// func importBenchmarkBegin() uint64
TEXT ·importBenchmarkBegin(SB),$0-8
	LEAQ	benchmark_begin(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// func importBenchmarkEnd() uint64
TEXT ·importBenchmarkEnd(SB),$0-8
	LEAQ	benchmark_end(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// func importBenchmarkBarrier() uint64
TEXT ·importBenchmarkBarrier(SB),$0-8
	LEAQ	benchmark_barrier(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// func importGetArg() uint64
TEXT ·importGetArg(SB),$0-8
	LEAQ	get_arg(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// func importSnapshot() uint64
TEXT ·importSnapshot(SB),$0-8
	LEAQ	snapshot(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// func importSuspendNextCall() uint64
TEXT ·importSuspendNextCall(SB),$0-8
	LEAQ	suspend_next_call(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func run(text []byte, initialMemorySize int, memoryAddr uintptr, stack []byte, stackOffset, initOffset, slaveFd int, arg int64, resultFd int) int
TEXT ·run(SB),NOSPLIT,$0-112 // too small
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

// func importCurrentMemory() uint64
TEXT ·importCurrentMemory(SB),$0-8
	LEAQ	current_memory(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),$0-8
	LEAQ	grow_memory(SB), AX
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

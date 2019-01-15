// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

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
	B	run(SB)

// func ObjectRuntime() (slice []byte, addr uint64)
TEXT ·ObjectRuntime(SB),$0-32
	BL	link_object_runtime_start(SB)
	MOVD	LR, R0
	BL	link_object_runtime_end(SB)
	MOVD	LR, R1
	SUB	R0, R1
	MOVD	R0, slice_base+0(FP)
	MOVD	R1, slice_len+8(FP)
	MOVD	R1, slice_cap+16(FP)
	MOVD	R0, addr+24(FP)
	RET

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	B	import_trap_handler(SB)

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),$0-8
	B	import_grow_memory(SB)

// func importSpectestPrint() uint64
TEXT ·importSpectestPrint(SB),$0-8
	B	import_spectest_print(SB)

// func importPutns() uint64
TEXT ·importPutns(SB),$0-8
	B	import_putns(SB)

// func importBenchmarkBegin() uint64
TEXT ·importBenchmarkBegin(SB),$0-8
	B	import_benchmark_begin(SB)

// func importBenchmarkEnd() uint64
TEXT ·importBenchmarkEnd(SB),$0-8
	B	import_benchmark_end(SB)

// func importBenchmarkBarrier() uint64
TEXT ·importBenchmarkBarrier(SB),$0-8
	B	import_benchmark_barrier(SB)

// func importGetArg() uint64
TEXT ·importGetArg(SB),$0-8
	B	import_get_arg(SB)

// func importSnapshot() uint64
TEXT ·importSnapshot(SB),$0-8
	B	import_snapshot(SB)

// func importSuspendNextCall() uint64
TEXT ·importSuspendNextCall(SB),$0-8
	B	import_suspend_next_call(SB)

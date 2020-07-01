// Copyright (c) 2019 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64,cgo

#include "textflag.h"

// func run(text []byte, memoryAddr uintptr, stack []byte, stackOffset, initOffset, minionFd int, arg int64, resultFd int, forkStack []byte) int
TEXT ·run(SB),NOSPLIT,$0-128
	BL	runtime·exit(SB)

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

// func importCurrentMemory() uint64
TEXT ·importCurrentMemory(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

// func importSpectestPrint() uint64
TEXT ·importSpectestPrint(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

// func importPutns() uint64
TEXT ·importPutns(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

// func importBenchmarkBegin() uint64
TEXT ·importBenchmarkBegin(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

// func importBenchmarkEnd() uint64
TEXT ·importBenchmarkEnd(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

// func importBenchmarkBarrier() uint64
TEXT ·importBenchmarkBarrier(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

// func importGetArg() uint64
TEXT ·importGetArg(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

// func importSnapshot() uint64
TEXT ·importSnapshot(SB),$0-8
	MOVD	$0, ret+0(FP)
	RET

TEXT sigsegv_handler(SB),DUPOK|NOSPLIT,$0
loop:	JMP	loop

TEXT signal_restorer(SB),DUPOK|NOSPLIT,$0
loop:	JMP	loop

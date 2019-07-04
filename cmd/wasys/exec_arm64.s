// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func exec(textBase, stackLimit, memoryBase, stackPtr uintptr)
TEXT ·exec(SB),NOSPLIT,$0-32
	MOVD	textBase+0(FP), R27
	MOVD	stackLimit+8(FP), R0
	MOVD	memoryBase+16(FP), R26
	MOVD	stackPtr+24(FP), R29	// RegFakeSP

	MOVD	R0, RSP			// RegRealSP
	ADD	$16, R0			// func call link addr + its stack check trap link addr
	LSR	$4, R0
	MOVD	R0, g			// RegStackLimit4 (R28)

	MOVD	R27, R1
	ADD	$32, R1			// init routine
	JMP	(R1)

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	BL	after

traphandler:
	CMPW	$0, R0
	BEQ	exittrap
	ADDW	$100, R0
	JMP	sysexit

exittrap:
	LSR	$32, R0			// exit code (higher 32 bits)
sysexit:
	MOVD	$94, R8			// exit_group syscall
	SVC
	BRK

after:	MOVD	LR, ret+0(FP)
	RET

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),$0-8
	BL	after

growmemory:
	BRK				// TODO: implementation

after:	MOVD	LR, ret+0(FP)
	RET

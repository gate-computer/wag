// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func exec(textBase, stackLimit, stackPtr uintptr)
TEXT ·exec(SB),NOSPLIT,$0-24
	MOVD	textBase+0(FP), R27
	MOVD	stackLimit+8(FP), R0
	MOVD	stackPtr+16(FP), R29	// RegFakeSP

	MOVD	R0, RSP			// RegRealSP
	LSR	$4, R0
	MOVD	R0, g			// RegStackLimit4 (R28)

	MOVD	R27, R1
	ADD	$0x30, R1		// enter routine
	JMP	(R1)

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	BL	after

traphandler:
	CMPW	$0, R2
	BEQ	exit

	ADDW	$100, R2, R0		// 100 + trap id

exit:
	MOVD	$94, R8			// exit_group syscall
	SVC
	BRK

after:	MOVD	LR, ret+0(FP)
	RET

// func importCurrentMemory() uint64
TEXT ·importCurrentMemory(SB),$0-8
	BL	after

currentmemory:
	BRK				// TODO: implementation

after:	MOVD	LR, ret+0(FP)
	RET

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),$0-8
	BL	after

growmemory:
	CBZ	R0, nop
	MOVD	$-1, R0
nop:
	RET

after:	MOVD	LR, ret+0(FP)
	RET

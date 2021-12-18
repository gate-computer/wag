// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func exec(textBase, stackLimit, stackPtr uintptr)
TEXT ·exec(SB),NOSPLIT,$0-24
	MOVQ	textBase+0(FP), R15
	MOVQ	stackLimit+8(FP), BX
	MOVQ	stackPtr+16(FP), CX

	MOVQ	CX, SP			// stack ptr

	XORL	AX, AX
	XORL	CX, CX
	XORL	BP, BP
	XORL	SI, SI
	XORL	DI, DI
	XORL	R8, R8
	XORL	R9, R9
	XORL	R10, R10
	XORL	R11, R11
	XORL	R12, R12
	XORL	R13, R13
	XORL	R14, R14

	MOVQ	R15, DX
	ADDQ	$0x30, DX		// enter routine
	JMP	DX

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	LEAQ	trapHandler<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT trapHandler<>(SB),NOSPLIT,$0
	MOVL	AX, DI			// exit code
	CMPL	DX, $0			// exit trap
	JE	exit

	ADDL	$100, DX		// 100 + trap id
	MOVL	DX, DI			// exit code

exit:
	MOVL	$231, AX		// exit_group syscall
	SYSCALL

// func importCurrentMemory() uint64
TEXT ·importCurrentMemory(SB),$0-8
	LEAQ	currentMemory<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT currentMemory<>(SB),NOSPLIT,$0
	HLT				// TODO: implementation

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),$0-8
	LEAQ	growMemory<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT growMemory<>(SB),NOSPLIT,$0
	TESTL	AX, AX
	JE	nop
	MOVL	$-1, AX
nop:
	RET

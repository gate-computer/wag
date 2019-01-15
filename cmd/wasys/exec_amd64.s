// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func exec(textBase, stackLimit, memoryBase, stackPtr uintptr)
TEXT ·exec(SB),NOSPLIT,$0-48
	MOVQ	textBase+0(FP), R15
	MOVQ	stackLimit+8(FP), BX
	MOVQ	memoryBase+16(FP), R14
	MOVQ	stackPtr+24(FP), CX

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

	MOVQ	R15, DX
	ADDQ	$32, DX			// init routine
	JMP	DX

// func importTrapHandler() uint64
TEXT ·importTrapHandler(SB),$0-8
	LEAQ	trapHandler<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT trapHandler<>(SB),NOSPLIT,$0
	CMPL	AX, $0			// exit trap (lower 32 bits)
	JE	exittrap
	ADDL	$100, AX		// 100 + trap id
	JMP	sysexit

exittrap:
	SHRQ	$32, AX			// exit code (higher 32 bits)
sysexit:
	MOVL	AX, DI
	MOVL	$231, AX		// exit_group syscall
	SYSCALL

// func importGrowMemory() uint64
TEXT ·importGrowMemory(SB),$0-8
	LEAQ	growMemory<>(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT growMemory<>(SB),NOSPLIT,$0
	HLT				// TODO: implementation

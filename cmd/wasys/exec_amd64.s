// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func exec(textBase, stackLimit, memoryBase, memoryLimit, memoryGrowLimit, stackPtr uintptr)
TEXT ·exec(SB),NOSPLIT,$0-48
	MOVQ	textBase+0(FP), R12
	MOVQ	stackLimit+8(FP), R13
	MOVQ	memoryBase+16(FP), R14
	MOVQ	memoryLimit+24(FP), R15
	MOVQ	memoryGrowLimit+32(FP), BX
	MOVQ	stackPtr+40(FP), CX

	LEAQ	traphandler<>(SB), AX
	MOVQ	AX, M0			// trap handler
	MOVQ	BX, M1			// memory grow limit
	MOVQ	CX, SP			// stack ptr

	XORL	AX, AX
	XORL	BX, BX
	XORL	CX, CX
	XORL	BP, BP
	XORL	SI, SI
	XORL	DI, DI
	XORL	R8, R8
	XORL	R9, R9			// suspend flag

	MOVQ	R12, DX
	ADDQ	$16, DX			// init code after trap trampoline
	JMP	DX

TEXT traphandler<>(SB),NOSPLIT,$0
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

TEXT ·callSys(SB),NOSPLIT,$0
	MOVQ	R8, R9			// arg 6 (suspend flag)
	MOVQ	DI, R8			// arg 5
	MOVQ	SI, R10			// arg 4
	MOVQ	BP, DX			// arg 3
	MOVQ	BX, SI			// arg 2
	MOVQ	CX, DI			// arg 1
	SYSCALL
	XORL	R9, R9			// suspend flag
	RET

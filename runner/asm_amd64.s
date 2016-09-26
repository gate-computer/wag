#include "textflag.h"

// func run(text, memory, stack []byte, arg, printFd int) (result int32, trap int, stackPtr uintptr)
TEXT ·run(SB),$0-112
	PUSHQ	AX
	PUSHQ	CX
	PUSHQ	DX
	PUSHQ	BX
	PUSHQ	BP
	PUSHQ	SI
	PUSHQ	DI
	PUSHQ	R8
	PUSHQ	R9
	PUSHQ	R10
	PUSHQ	R11
	PUSHQ	R12
	PUSHQ	R13
	PUSHQ	R14
	PUSHQ	R15

	MOVQ	text+0(FP), R12
	MOVQ	memory+24(FP), R14
	MOVQ	memory_len+32(FP), R15
	ADDQ	R14, R15		// memory limit
	MOVQ	stack+48(FP), R13	// stack limit
	MOVQ	stack_len+56(FP), CX
	MOVQ	arg+72(FP), DX
	MOVQ	printFd+80(FP), M6	// print fd
	CALL	run<>(SB)
	MOVL	AX, result+88(FP)
	MOVQ	DI, trap+96(FP)
	MOVQ	BX, stackPtr+104(FP)

	POPQ	R15
	POPQ	R14
	POPQ	R13
	POPQ	R12
	POPQ	R11
	POPQ	R10
	POPQ	R9
	POPQ	R8
	POPQ	DI
	POPQ	SI
	POPQ	BP
	POPQ	BX
	POPQ	DX
	POPQ	CX
	POPQ	AX
	RET

TEXT run<>(SB),NOSPLIT,$0
	MOVQ	SP, M7		// save original stack
	MOVQ	R13, SP
	ADDQ	CX, SP		// stack
	LEAQ	trap<>(SB), AX
	MOVQ	AX, M0		// trap handler
	SUBQ	$8, SP
	MOVQ	DX, (SP)	// arg
	CALL	R12
	// exits via trap handler

TEXT trap<>(SB),NOSPLIT,$0
	MOVQ	SP, BX		// stack ptr
	MOVQ	M7, SP		// restore original stack
	RET

// func importSpectestPrint() int64
TEXT ·importSpectestPrint(SB),$0-8
	PUSHQ	AX
	LEAQ	spectestPrint<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
	RET

TEXT spectestPrint<>(SB),NOSPLIT,$0
	MOVQ	(SP), R15	// save return address
	MOVQ	$1, AX		// sys_write
	MOVQ	M6, DI 		// print fd
	MOVQ	BX, (SP)	// write signature index over return address
	MOVQ	SP, SI		// buffer
	INCQ	DX		// arg count + 1
	SHLQ	$3, DX		// (arg count + 1) size
	SYSCALL
	MOVQ	R15, (SP)	// restore return address
	RET

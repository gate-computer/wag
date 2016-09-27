#include "textflag.h"

// func run(text []byte, initialMemorySize int, memory, stack []byte, arg, printFd int) (result int32, trap int, stackPtr uintptr)
TEXT ·run(SB),$0-120
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
	MOVQ	initialMemorySize+24(FP), R15
	MOVQ	memory+32(FP), R14
	MOVQ	memory_len+40(FP), BX
	ADDQ	R14, R15		// current memory limit
	ADDQ	R14, BX
	MOVQ	stack+56(FP), R13	// stack limit
	MOVQ	stack_len+64(FP), CX
	MOVQ	arg+80(FP), DX
	MOVQ	printFd+88(FP), M6	// print fd
	CALL	run<>(SB)
	MOVL	AX, result+96(FP)
	MOVQ	DI, trap+104(FP)
	MOVQ	BX, stackPtr+112(FP)

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
	MOVQ	BX, M1		// memory growth limit
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

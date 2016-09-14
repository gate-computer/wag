#include "textflag.h"

// func run(text, roData, stack []byte, arg int) (result int32, trap int)
TEXT ·run(SB),$0-96
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

	MOVQ	text+0(FP), R14
	MOVQ	roData+24(FP), R15
	MOVQ	stack+48(FP), R13	// stack limit
	MOVQ	stack_len+56(FP), CX
	MOVQ	arg+72(FP), DX
	CALL	run<>(SB)
	MOVL	AX, result+80(FP)
	MOVQ	DI, trap+88(FP)

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
	CALL	R14
	XORQ	DI, DI		// no trap
	MOVQ	M7, SP		// restore original stack
	RET

TEXT trap<>(SB),NOSPLIT,$0
	XORQ	AX, AX		// dummy result
	MOVQ	M7, SP		// restore original stack
	RET

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
	MOVQ	text+0(FP), DI
	MOVQ	roData+24(FP), SI
	MOVQ	stack+48(FP), AX
	MOVQ	stack_len+56(FP), CX
	MOVQ	arg+72(FP), DX
	CALL	run<>(SB)
	MOVL	AX, result+80(FP)
	MOVQ	DI, trap+88(FP)
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
	MOVQ	SP, R9		// save original stack
	MOVQ	AX, BP		// stack limit
	MOVQ	AX, SP
	ADDQ	CX, SP		// stack
	LEAQ	trap<>(SB), R8	// trap handler
	SUBQ	$8, SP
	MOVQ	DX, (SP)	// arg
	CALL	DI
	XORQ	DI, DI		// no trap
	MOVQ	R9, SP		// restore original stack
	RET

TEXT trap<>(SB),NOSPLIT,$0
	XORQ	AX, AX		// dummy result
	MOVQ	R9, SP		// restore original stack
	RET

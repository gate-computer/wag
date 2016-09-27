#include "textflag.h"

// func run(text []byte, initialMemorySize int, memory, stack []byte, stackOffset, resume, arg, slaveFd int) (result int32, trap int, currentMemorySize int, stackPtr uintptr)
TEXT ·run(SB),$0-144
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
	MOVQ	stackOffset+80(FP), CX
	MOVQ	resume+88(FP), R10
	MOVQ	arg+96(FP), DX
	MOVQ	slaveFd+104(FP), M6	// slave fd
	CALL	run<>(SB)
	MOVL	AX, result+112(FP)
	MOVQ	DI, trap+120(FP)
	SUBQ	R14, R15
	MOVQ	R15, currentMemorySize+128(FP)
	MOVQ	BX, stackPtr+136(FP)

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

	TESTQ	R10, R10	// resume?
	JNE	resume

	SUBQ	$8, SP
	MOVQ	DX, (SP)	// arg
	CALL	R12
	// exits via trap handler

resume:	// simulate return from snapshot function
	MOVQ	$-1, AX
	RET

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
	MOVQ	(SP), R10	// save return address

	MOVQ	$1, AX		// sys_write
	MOVQ	M6, DI 		// slave fd
	MOVQ	SP, SI		// buffer
	MOVQ	BX, (SI)	// write signature index over return address
	INCQ	DX		// arg count + 1
	SHLQ	$3, DX		// (arg count + 1) size
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	MOVQ	R10, (SP)	// restore return address
	RET

fail:	MOVQ	$3001, DI
	JMP	trap<>(SB)

// func importSnapshot() int64
TEXT ·importSnapshot(SB),$0-8
	PUSHQ	AX
	LEAQ	snapshot<>(SB), AX
	MOVQ	AX, ret+0(FP)
	POPQ	AX
	RET

TEXT snapshot<>(SB),NOSPLIT,$0
	MOVQ	$1, AX		// sys_write
	MOVQ	M6, DI 		// slave fd
	LEAQ	-8(SP), SI	// buffer
	MOVQ	$-1, (SI)	// write -1 over return address
	MOVQ	$8, DX		// bufsize
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	MOVQ	$1, AX		// sys_write
	MOVQ	R15, (SI)	// write current memory limit over return address
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	MOVQ	$1, AX		// sys_write
	MOVQ	SP, (SI)	// write stack ptr over return address
	SYSCALL
	SUBQ	DX, AX
	JNE	fail

	XORQ	AX, AX		// sys_read
	SYSCALL
	SUBQ	DX, AX
	JNE	fail
	MOVQ	(SI), AX	// snapshot id
	RET

fail:	MOVQ	$3002, DI
	JMP	trap<>(SB)

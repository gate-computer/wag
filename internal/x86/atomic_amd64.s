#include "textflag.h"

// func atomicPutUint32(b []byte, val uint32)
TEXT ·atomicPutUint32(SB),NOSPLIT,$0-28
	MOVQ	b+0(FP), BP
	MOVL	val+24(FP), AX
	XCHGL	AX, (BP)
	RET

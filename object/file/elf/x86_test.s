// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64

#include "textflag.h"

// func testText() []byte
TEXT ·testText(SB),$0-24
	LEAQ	testText32<>(SB), AX	// keep alive
	LEAQ	testText16<>(SB), AX	// keep alive
	LEAQ	testTextStart<>(SB), AX
	LEAQ	testTextEnd<>(SB), BX
	SUBQ	AX, BX
	MOVQ	AX, ret_base+0(FP)
	MOVQ	BX, ret_len+8(FP)
	MOVQ	BX, ret_cap+16(FP)
	RET

TEXT testTextStart<>(SB),NOSPLIT,$0	// offset 0
	RET
					// padding
TEXT testText16<>(SB),NOSPLIT,$0	// offset 16
	RET
					// padding
TEXT testText32<>(SB),NOSPLIT,$0	// offset 32
	MOVQ	(R14), DI		// memory
	SUBQ	$85400, DI
	SUBQ	-8(R14), DI		// globals
	MOVL	8(R15), AX		// text+8
	SYSCALL
	HLT

TEXT testTextEnd<>(SB),NOSPLIT,$0

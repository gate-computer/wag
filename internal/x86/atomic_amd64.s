// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// func atomicPutUint32(b []byte, val uint32)
TEXT ·atomicPutUint32(SB),NOSPLIT,$0-28
	MOVQ	b+0(FP), BP
	MOVL	val+24(FP), AX
	XCHGL	AX, (BP)
	RET

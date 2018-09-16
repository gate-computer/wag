// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

// PutUint32(b []byte, val uint32)
TEXT ·PutUint32(SB),NOSPLIT,$0-28
	MOVD	b+0(FP), R1
	MOVW	val+24(FP), R0
	STLRW	R0, (R1)
	RET

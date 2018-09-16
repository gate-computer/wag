// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64

#include "textflag.h"

// func testText() (slice []byte)
TEXT ·testText(SB),$0-24
	BL	at
	MOVD	LR, R0
	BL	after
	SUB	$4, LR, R1		// size of "after" routine
	SUB	R0, R1
	MOVD	R0, slice+0(FP)		// data
	MOVD	R1, slice+8(FP)		// len
	MOVD	R1, slice+16(FP)	// cap
	RET

at:	BL	(LR)

offs0:	BRK
	BRK
	BRK
	BRK

offs16:	BRK
	BRK
	BRK
	BRK

offs32:	MOVD	(R26), R0		// memory
	MOVD	$42700, R1
	MOVD	$42700, R2
	MOVD	-8(R26), R3		// globals
	SUB	R1, R0
	SUB	R2, R0
	SUB	R3, R0
	MOVD	8(R27), R8		// text+8
	SVC
	BRK

after:	BL	(LR)

// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build arm64

#include "textflag.h"

// func executeTestCode(exe []byte) uint64
TEXT ·executeTestCode(SB),NOSPLIT,$0-32
	MOVD	$0xbadc0debadb00613, R0
	MOVD	R0, R1
	MOVD	R0, R2
	MOVD	R0, R3
	MOVD	R0, R4
	MOVD	R0, R5
	MOVD	R0, R6
	MOVD	R0, R7
	MOVD	R0, R8
	MOVD	R0, R9
	MOVD	R0, R10
	MOVD	R0, R11
	MOVD	R0, R12
	MOVD	R0, R13
	MOVD	R0, R14
	MOVD	R0, R15

	MOVD	R0, R19
	MOVD	R0, R20
	MOVD	R0, R21
	MOVD	R0, R22
	MOVD	R0, R23
	MOVD	R0, R24

	MOVD	exe+0(FP), R25
	BL	(R25)
	MOVD	R0, ret+24(FP)
	RET

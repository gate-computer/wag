// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/isa/x86/in"
)

const (
	RegResult         = in.RegResult     // rax xmm0
	RegDividendLow    = reg.R(0)         // rax
	RegScratch        = in.RegScratch    // rcx xmm1
	RegCount          = reg.R(1)         // rcx
	RegZero           = in.RegZero       // rdx
	RegDividendHigh   = reg.R(2)         // rdx
	_                 = reg.R(2)         //     xmm2  <- AllocFloatFirst
	RegStackLimit     = in.RegStackLimit // rbx
	RegStackPtr       = reg.R(4)         // rsp
	RegImportVariadic = reg.R(5)         // rbp       <- AllocIntFirst
	_                 = reg.R(6)         // rsi
	_                 = reg.R(7)         // rdi
	_                 = reg.R(8)         // r8
	_                 = reg.R(9)         // r9
	_                 = reg.R(10)        // r10
	_                 = reg.R(11)        // r11
	_                 = reg.R(12)        // r12
	_                 = reg.R(13)        // r13       <- AllocIntLast
	RegMemoryBase     = in.RegMemoryBase // r14
	RegTextBase       = in.RegTextBase   // r15
	_                 = reg.R(15)        //     xmm15 <- AllocFloatLast
)

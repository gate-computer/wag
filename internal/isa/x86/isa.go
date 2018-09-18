// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/atomic"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/isa/x86/in"
	"github.com/tsavola/wag/internal/obj"
)

const (
	RegResult         = in.RegResult     // rax xmm0
	RegDividendLow    = reg.R(0)         // rax
	RegScratch        = in.RegScratch    // rcx xmm1
	RegCount          = reg.R(1)         // rcx
	RegZero           = in.RegZero       // rdx
	RegDividendHigh   = reg.R(2)         // rdx
	_                 = reg.R(2)         //     xmm2  <- AllocFloatFirst
	RegStackLimit     = reg.R(3)         // rbx
	RegSuspendBit     = reg.R(3)         // rbx
	RegStackPtr       = reg.R(4)         // rsp
	RegImportVariadic = reg.R(5)         // rbp       <- AllocIntFirst   (problematic base reg)
	_                 = reg.R(6)         // rsi
	_                 = reg.R(7)         // rdi
	_                 = reg.R(8)         // r8
	_                 = reg.R(9)         // r9
	_                 = reg.R(10)        // r10
	_                 = reg.R(11)        // r11
	_                 = reg.R(12)        // r12       <- AllocIntLast    (problematic base reg)
	RegMemoryLimit    = reg.R(13)        // r13                          (problematic base reg)
	RegMemoryBase     = in.RegMemoryBase // r14
	RegTextBase       = reg.R(15)        // r15
	_                 = reg.R(15)        //     xmm15 <- AllocFloatLast
)

const (
	RegTrapHandlerMMX     = reg.R(0) // mm0
	RegMemoryGrowLimitMMX = reg.R(1) // mm1
)

const (
	FuncAlignment = 16
	PaddingByte   = 0xcc // int3 instruction
)

type ISA struct{}

var isa ISA

func (ISA) AlignFunc(p *gen.Prog) {
	gap := p.Text.Extend((FuncAlignment - int(p.Text.Addr)) & (FuncAlignment - 1))
	for i := range gap {
		gap[i] = PaddingByte
	}
}

// UpdateNearBranches modifies 8-bit relocations of JMP and Jcc instructions.
func (ISA) UpdateNearBranches(text []byte, l *link.L) {
	labelAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		updateAddr8(text, retAddr, labelAddr-retAddr)
	}
}

// UpdateFarBranches modifies 32-bit relocations of JMP and Jcc instructions.
func (ISA) UpdateFarBranches(text []byte, l *link.L) {
	labelAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		updateAddr32(text, retAddr, labelAddr-retAddr)
	}
}

// UpdateStackCheck modifies the 32-bit displacement of a LEA instruction.
func (ISA) UpdateStackCheck(text []byte, addr int32, depth int) {
	updateAddr32(text, addr, int32(-depth*obj.Word))
}

// UpdateCalls modifies CALL instructions, possibly while they are being
// executed.
func (ISA) UpdateCalls(text []byte, l *link.L) {
	funcAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		atomic.PutUint32(text[retAddr-4:retAddr], uint32(funcAddr-retAddr))
	}
}

func updateAddr8(text []byte, addr, value int32) {
	if value < -0x80 || value >= 0x80 {
		panic(value)
	}
	text[addr-1] = uint8(value)
}

func updateAddr32(text []byte, addr, value int32) {
	binary.LittleEndian.PutUint32(text[addr-4:addr], uint32(value))
}

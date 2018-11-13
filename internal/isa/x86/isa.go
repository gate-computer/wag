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
	RegImportVariadic = reg.R(5)         // rbp       <- AllocIntFirst
	_                 = reg.R(6)         // rsi
	_                 = reg.R(7)         // rdi
	_                 = reg.R(8)         // r8
	_                 = reg.R(9)         // r9
	_                 = reg.R(10)        // r10
	_                 = reg.R(11)        // r11
	_                 = reg.R(12)        // r12       <- AllocIntLast
	RegMemoryLimit    = reg.R(13)        // r13
	RegMemoryBase     = in.RegMemoryBase // r14
	RegTextBase       = in.RegTextBase   // r15
	_                 = reg.R(15)        //     xmm15 <- AllocFloatLast
)

const (
	FuncAlignment = 16
	PaddingByte   = 0xcc // INT3 instruction
)

type ISA struct{}

var isa ISA

func (ISA) AlignData(p *gen.Prog, alignment int) {
	pad(p, PaddingByte, (alignment-int(p.Text.Addr))&(alignment-1))
}

func (ISA) AlignFunc(p *gen.Prog) {
	pad(p, PaddingByte, (FuncAlignment-int(p.Text.Addr))&(FuncAlignment-1))
}

func (ISA) PadUntil(p *gen.Prog, addr int32) {
	pad(p, PaddingByte, int(addr)-int(p.Text.Addr))
}

func pad(p *gen.Prog, filler byte, length int) {
	gap := p.Text.Extend(length)
	for i := range gap {
		gap[i] = filler
	}
}

// UpdateNearLoad modifies a 32-bit displacement.
func (ISA) UpdateNearLoad(text []byte, insnAddr int32) {
	accessAddr := int32(len(text))
	updateAddr32(text, insnAddr, accessAddr)
}

// UpdateNearBranch modifies the 8-bit relocation of a JMP or Jcc instruction.
func (ISA) UpdateNearBranch(text []byte, originAddr int32) {
	labelAddr := int32(len(text))
	updateAddr8(text, originAddr, labelAddr-originAddr)
}

// UpdateNearBranches modifies 8-bit relocations of JMP and Jcc instructions.
func (ISA) UpdateNearBranches(text []byte, l *link.L) {
	labelAddr := l.FinalAddr()
	for _, originAddr := range l.Sites {
		updateAddr8(text, originAddr, labelAddr-originAddr)
	}
}

// UpdateFarBranches modifies 32-bit relocations of JMP and Jcc instructions.
func (ISA) UpdateFarBranches(text []byte, l *link.L) {
	labelAddr := l.FinalAddr()
	for _, originAddr := range l.Sites {
		updateAddr32(text, originAddr, labelAddr-originAddr)
	}
}

// UpdateStackCheck modifies the 32-bit displacement of a LEA instruction.
func (ISA) UpdateStackCheck(text []byte, addr int32, depth int) {
	updateAddr32(text, addr, int32(-depth*obj.Word))
}

// UpdateCalls modifies CALL instructions.
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

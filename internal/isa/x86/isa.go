// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen/atomic"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/module"
)

const (
	// Don't use RegResult for effective addresses etc. to avoid information
	// leaks.  Void functions may leave information in the result register, and
	// call stack could be rewritten during snapshot/restore to cause void
	// function to return to a non-void call site.

	RegResult         = reg.Result // rax or xmm0
	RegShiftCount     = reg.R(1)   // rcx
	RegScratch        = reg.R(2)   // rdx or xmm2
	RegImportArgCount = reg.R(2)   // rdx
	RegImportSigIndex = reg.R(3)   // rbx
	RegStackPtr       = reg.R(4)   // rsp
	RegSuspendFlag    = reg.R(9)   // r9
	RegTextBase       = reg.R(12)  // r12
	RegStackLimit     = reg.R(13)  // r13
	RegMemoryBase     = reg.R(14)  // r14
	RegMemoryLimit    = reg.R(15)  // r15

	RegTrapHandlerMMX     = reg.R(0) // mm0
	RegMemoryGrowLimitMMX = reg.R(1) // mm1
	RegScratchMMX         = reg.R(2) // mm2
)

const (
	FuncAlignment = 16
	PaddingByte   = 0xcc // int3 instruction
)

var (
	paramRegs [2][]reg.R
	availRegs = reg.Bitmap(abi.Int, &paramRegs[abi.Int],
		false, // rax
		true,  // rcx
		false, // rdx
		true,  // rbx
		false, // rsp
		true,  // rbp
		true,  // rsi
		true,  // rdi
		true,  // r8
		false, // r9
		true,  // r10
		true,  // r11
		false, // r12
		false, // r13
		false, // r14
		false, // r15
	) | reg.Bitmap(abi.Float, &paramRegs[abi.Float],
		false, // xmm0
		true,  // xmm1
		false, // xmm2
		true,  // xmm3
		true,  // xmm4
		true,  // xmm5
		true,  // xmm6
		true,  // xmm7
		true,  // xmm8
		true,  // xmm9
		true,  // xmm10
		true,  // xmm11
		true,  // xmm12
		true,  // xmm13
		true,  // xmm14
		true,  // xmm15
	)
)

var nopSequences = [][]byte{
	{0x90},
	{0x66, 0x90},
	{0x0f, 0x1f, 0x00},
	{0x0f, 0x1f, 0x40, 0x00},
	{0x0f, 0x1f, 0x44, 0x00, 0x00},
	{0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},
	{0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},
	{0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
}

type ISA struct{}

func (ISA) AvailRegs() uint64     { return availRegs }
func (ISA) ParamRegs() [2][]reg.R { return paramRegs }
func (ISA) AlignFunc(m *module.M) { alignFunc(m) }

func alignFunc(m *module.M) {
	gap := m.Text.Extend((FuncAlignment - int(m.Text.Addr)) & (FuncAlignment - 1))
	for i := range gap {
		gap[i] = PaddingByte
	}
}

// UpdateBranches modifies 32-bit relocations of JMP and Jcc instructions.
func (ISA) UpdateBranches(text []byte, l *link.L) {
	labelAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		updateAddr(text, retAddr, labelAddr-retAddr)
	}
}

// updateLocalBranches modifies 8-bit relocations of JMP and Jcc instructions.
func updateLocalBranches(m *module.M, l *link.L) {
	labelAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		updateLocalAddr(m, retAddr, labelAddr-retAddr)
	}
}

// UpdateStackCheck modifies the 32-bit displacement of a LEA instruction.
func (ISA) UpdateStackCheck(text []byte, addr, disp int32) {
	updateAddr(text, addr, -disp)
}

// UpdateCalls modifies CALL instructions, possibly while they are being
// executed.
func (ISA) UpdateCalls(text []byte, l *link.L) {
	funcAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		atomic.PutUint32(text[retAddr-4:retAddr], uint32(funcAddr-retAddr))
	}
}

func updateAddr(text []byte, addr, value int32) {
	binary.LittleEndian.PutUint32(text[addr-4:addr], uint32(value))
}

func updateLocalAddr(m *module.M, addr, value int32) {
	if value < -0x80 || value >= 0x80 {
		panic(value)
	}
	m.Text.Bytes()[addr-1] = uint8(value)
}

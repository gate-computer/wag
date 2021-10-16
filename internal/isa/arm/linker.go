// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64
// +build arm64 wagarm64
// +build !wagamd64

package arm

import (
	"encoding/binary"
	"fmt"

	"gate.computer/wag/internal/gen/link"
	"gate.computer/wag/internal/isa/arm/in"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/wa"
)

const (
	MaxFuncSize = 4 * 1024 * 1024 // Conditional branch distance.
)

var linker Linker

type Linker struct{}

// UpdateNearLoad overwrites an instruction with an ADR instruction.
func (Linker) UpdateNearLoad(text []byte, addr int32) {
	loadAddr := addr - 4
	offset := int32(len(text)) - loadAddr
	insn := in.ADR.RdI19hiI2lo(RegScratch, uint32(offset)>>2, 0)
	binary.LittleEndian.PutUint32(text[loadAddr:], insn)
}

func (Linker) UpdateNearBranch(text []byte, site int32) {
	updateBranchInsn(text, site, int32(len(text)))
}

func (Linker) UpdateNearBranches(text []byte, sites []int32) {
	labelAddr := int32(len(text))
	for _, afterBranchAddr := range sites {
		updateBranchInsn(text, afterBranchAddr, labelAddr)
	}
}

func (Linker) UpdateFarBranches(text []byte, l *link.L) {
	labelAddr := l.FinalAddr()
	for _, afterBranchAddr := range l.Sites {
		updateBranchInsn(text, afterBranchAddr, labelAddr)
	}
}

func (Linker) UpdateStackCheck(text []byte, addr int32, depth int) {
	if maxFuncOffset := len(text) - int(addr); maxFuncOffset > MaxFuncSize {
		panic(module.Error("text size limit exceeded"))
	}

	// codegen.MaxFuncLocals ensures that alloc4 is not out of range.
	alloc3 := depth
	alloc4 := uint32(alloc3+1) >> 1 // Round up.

	// scratch    = limit/16 + alloc/16
	// scratch*16 = limit    + alloc
	insn := in.ADDi.RdRnI12S2(RegScratch, RegStackLimit4, alloc4, 0, wa.Size64)

	binary.LittleEndian.PutUint32(text[addr-4:addr], insn)
}

func (Linker) UpdateCalls(text []byte, l *link.L) {
	funcAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		updateCallInsn(text, retAddr, funcAddr)
	}
}

func updateBranchInsn(text []byte, addr, labelAddr int32) {
	branchAddr := addr - 4
	offset := (labelAddr - branchAddr) / 4

	insn := binary.LittleEndian.Uint32(text[branchAddr:])

	// MaxFuncSize ensures that offset is not out of range.
	switch {
	case insn>>25 == 0x2a: // Conditional branch.
		insn = insn&^(0x7ffff<<5) | in.Int19(offset)<<5

	case (insn>>26)&0x1f == 0x05: // Unconditional branch.
		insn = insn&^0x3ffffff | in.Int26(offset)

	default:
		panic(fmt.Sprintf("unknown branch instruction encoding: %#v", insn))
	}

	binary.LittleEndian.PutUint32(text[branchAddr:], insn)
}

func updateCallInsn(text []byte, addr, funcAddr int32) {
	callAddr := addr - 4
	offset := funcAddr - callAddr

	// compile.MaxTextSize ensures that offset is not out of range.
	insn := in.BL.I26(in.Int26(offset / 4))
	binary.LittleEndian.PutUint32(text[callAddr:], insn)
}

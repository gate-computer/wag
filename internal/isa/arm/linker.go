// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"encoding/binary"
	"fmt"

	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/wa"
)

const (
	MaxProgSize = 4 * 128 * 1024 * 1024 // Unconditional branch distance.
	MaxFuncSize = 4 * 1 * 1024 * 1024   // Conditional branch distance.
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
	// UpdateStackCheck is called at end of each function
	if len(text) > MaxProgSize {
		panic(fmt.Errorf("arm: program is too large (exceeds %d bytes)", MaxProgSize))
	}
	if approxFuncSize := len(text) - int(addr); approxFuncSize > MaxFuncSize {
		panic(fmt.Errorf("arm: function is too large (exceeds %d bytes)", MaxFuncSize))
	}

	alloc4 := uint32(depth+1) / 2 // round up
	if alloc4 > 4095 {
		panic(fmt.Errorf("arm: function has too many stack values: %d", depth))
	}

	// scratch    = limit/16 + alloc/16
	// scratch*16 = limit    + alloc
	insn := in.ADDi.RdRnI12S2(RegScratch, RegStackLimit4, alloc4, 0, wa.I64)

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

	insn := in.BL.I26(in.Int26(offset / 4))
	binary.LittleEndian.PutUint32(text[callAddr:], insn)
}

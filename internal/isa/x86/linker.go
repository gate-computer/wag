// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"encoding/binary"

	"gate.computer/wag/internal/gen/atomic"
	"gate.computer/wag/internal/gen/link"
	"gate.computer/wag/internal/obj"
)

var linker Linker

type Linker struct{}

// UpdateNearLoad modifies a 32-bit displacement.
func (Linker) UpdateNearLoad(text []byte, insnAddr int32) {
	accessAddr := int32(len(text))
	updateAddr32(text, insnAddr, accessAddr)
}

// UpdateNearBranch modifies the 8-bit relocation of a JMP or Jcc instruction.
func (Linker) UpdateNearBranch(text []byte, originAddr int32) {
	labelAddr := int32(len(text))
	updateAddr8(text, originAddr, labelAddr-originAddr)
}

// UpdateNearBranches modifies 8-bit relocations of JMP and Jcc instructions.
func (Linker) UpdateNearBranches(text []byte, originAddrs []int32) {
	labelAddr := int32(len(text))
	for _, originAddr := range originAddrs {
		updateAddr8(text, originAddr, labelAddr-originAddr)
	}
}

// UpdateFarBranches modifies 32-bit relocations of JMP and Jcc instructions.
func (Linker) UpdateFarBranches(text []byte, l *link.L) {
	labelAddr := l.FinalAddr()
	for _, originAddr := range l.Sites {
		updateAddr32(text, originAddr, labelAddr-originAddr)
	}
}

// UpdateStackCheck modifies the 32-bit displacement of a LEA instruction.
func (Linker) UpdateStackCheck(text []byte, addr int32, depth int) {
	updateAddr32(text, addr, int32(-depth*obj.Word))
}

// UpdateCalls modifies CALL instructions.
func (Linker) UpdateCalls(text []byte, l *link.L) {
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

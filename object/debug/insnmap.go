// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"sort"

	"gate.computer/wag/object"
)

// Instruction mapping from machine code to WebAssembly.  SourceOffset is zero
// if ObjectOffset contains non-executable data interleaved with the code.
type InsnMapping struct {
	ObjectOffset uint32 // Machine code offset in bytes.
	SourceOffset uint32 // WebAssembly code offset in bytes.
	BlockLen     int32  // Length of data block (when SourceOffset is 0).
}

// InsnMap is an object map which stores all available function, call, trap and
// instruction information.  The Mapper method must be used to obtain an actual
// ObjectMapper implementation.
type InsnMap struct {
	object.CallMap
	Insns []InsnMapping
}

func (m *InsnMap) PutInsnAddr(objectOffset, sourceOffset uint32) {
	m.putMapping(objectOffset, sourceOffset, 0)
}

func (m *InsnMap) PutDataBlock(objectOffset uint32, length int32) {
	m.putMapping(objectOffset, 0, length)
}

func (m *InsnMap) putMapping(objectOffset, sourceOffset uint32, blockLen int32) {
	prev := len(m.Insns) - 1
	if prev >= 0 && m.Insns[prev].ObjectOffset == objectOffset {
		// Replace previous mapping because no machine code was generated.
		m.Insns[prev].SourceOffset = sourceOffset
		m.Insns[prev].BlockLen = blockLen
	} else {
		m.Insns = append(m.Insns, InsnMapping{objectOffset, sourceOffset, blockLen})
	}
}

func (m *InsnMap) FindCall(retAddr uint32) (init bool, funcIndex, callIndex int, stackOffset int32, retOffset uint32) {
	init, funcIndex, callIndex, stackOffset, retOffset = m.CallMap.FindCall(retAddr)

	retIndex := sort.Search(len(m.Insns), func(i int) bool {
		return m.Insns[i].ObjectOffset >= retAddr
	})
	if retIndex > 0 && retIndex < len(m.Insns) {
		retOffset = m.Insns[retIndex].SourceOffset
	}
	return
}

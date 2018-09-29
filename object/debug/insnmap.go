// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"github.com/tsavola/wag/object"
)

// Instruction mapping from machine code to WebAssembly.  SourceIndex is -1 if
// ObjectOffset contains non-executable data interleaved with the code.
type InsnMapping struct {
	ObjectOffset int32 // Machine code byte position within a function
	SourceIndex  int32 // WebAssembly instruction index within a function
	BlockLength  int   // Length of data block (when SourceIndex is -1)
}

// InsnMap implements compile.ObjectMap.  It stores everything.
type InsnMap struct {
	object.CallMap
	FuncInsns [][]InsnMapping

	fun  int
	base int32
	ins  int32
}

func (m *InsnMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	m.CallMap.InitObjectMap(numImportFuncs, numOtherFuncs)
	m.FuncInsns = make([][]InsnMapping, numOtherFuncs)
	m.fun = -1
}

func (m *InsnMap) PutFuncAddr(pos int32) {
	m.CallMap.PutFuncAddr(pos)
	m.fun++
	m.base = pos
	m.ins = -1
}

func (m *InsnMap) PutInsnAddr(pos int32) {
	m.ins++
	m.putMapping(pos, m.ins, 0)
}

func (m *InsnMap) PutDataBlock(pos int32, length int) {
	m.putMapping(pos, -1, length)
}

func (m *InsnMap) putMapping(absPos, sourceIndex int32, blockLength int) {
	relPos := absPos - m.base

	prev := len(m.FuncInsns[m.fun]) - 1
	if prev >= 0 && m.FuncInsns[m.fun][prev].ObjectOffset == relPos {
		// Replace previous mapping because no machine code was generated
		m.FuncInsns[m.fun][prev].SourceIndex = sourceIndex
		m.FuncInsns[m.fun][prev].BlockLength = blockLength
	} else {
		m.FuncInsns[m.fun] = append(m.FuncInsns[m.fun], InsnMapping{relPos, sourceIndex, blockLength})
	}
}

func (m *InsnMap) GetFuncAddrs() []int32         { return m.FuncAddrs }
func (m *InsnMap) GetFuncInsns() [][]InsnMapping { return m.FuncInsns }

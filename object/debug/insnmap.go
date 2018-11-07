// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"sort"

	"github.com/tsavola/wag/object"
)

// Instruction mapping from machine code to WebAssembly.  SourceIndex is -1 if
// ObjectOffset contains non-executable data interleaved with the code.
type InsnMapping struct {
	ObjectOffset int32 // Machine code byte position within a function
	SourceIndex  int32 // WebAssembly instruction index within a function
	BlockLength  int   // Length of data block (when SourceIndex is -1)
}

// InsnMap implements compile.ObjectMapper.  It stores everything.
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

func (m *InsnMap) FindAddr(retAddr int32) (funcIndex, retInsnIndex, stackOffset int32, initial, ok bool) {
	funcIndex, _, stackOffset, initial, siteOk := m.CallMap.FindAddr(retAddr)
	if !siteOk {
		return
	}

	if initial {
		ok = true
		return
	}

	numImportFuncs := len(m.FuncAddrs) - len(m.FuncInsns)
	otherFuncIndex := int(funcIndex) - numImportFuncs
	insns := m.FuncInsns[otherFuncIndex]

	retMapIndex := sort.Search(len(insns), func(i int) bool {
		return insns[i].ObjectOffset >= retAddr
	})

	if retMapIndex > 0 {
		// The specific wasm instruction at the return address might not exist
		// in generated code; there might not even be any generated code after
		// the call.  The call instruction certaily exists in generated code,
		// and it's mapped before the one we found (or it's the last one if we
		// didn't find any).
		callMapIndex := retMapIndex - 1
		callInsnIndex := insns[callMapIndex].SourceIndex

		// Because FindAddr is called with a return address, we must return the
		// index of the wasm instruction at which the call would return.
		retInsnIndex = callInsnIndex + 1
		ok = true
	}
	return
}

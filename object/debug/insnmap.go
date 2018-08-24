// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"github.com/tsavola/wag/object"
)

// Instruction mapping from machine code to WebAssembly.
type InsnMapping struct {
	ObjectOffset int32 // Machine code byte position within a function
	SourceIndex  int32 // WebAssembly instruction count within a function
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

func (m *InsnMap) PutInsnAddr(absPos int32) {
	m.ins++
	relPos := absPos - m.base

	prev := len(m.FuncInsns[m.fun]) - 1
	if prev >= 0 && m.FuncInsns[m.fun][prev].ObjectOffset == relPos {
		// Replace previous mapping because no machine code was generated
		m.FuncInsns[m.fun][prev].SourceIndex = m.ins
	} else {
		m.FuncInsns[m.fun] = append(m.FuncInsns[m.fun], InsnMapping{relPos, m.ins})
	}
}

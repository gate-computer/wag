// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package insnmap

import (
	"github.com/tsavola/wag/callmap"
	"github.com/tsavola/wag/meta"
)

// Mapping from machine code instruction to WebAssembly instruction.
type Mapping struct {
	ObjectOffset int32 // Machine code byte position within a function
	SourceIndex  int32 // WebAssembly instruction count within a function
}

// Map implements Mapper.  It stores everything.
type Map struct {
	callmap.Map
	FuncInsns [][]Mapping

	fun  int
	base meta.TextAddr
	ins  int32
}

func (m *Map) InitModule(numImportFuncs, numOtherFuncs int) {
	m.Map.InitModule(numImportFuncs, numOtherFuncs)
	m.FuncInsns = make([][]Mapping, numOtherFuncs)
	m.fun = -1
}

func (m *Map) PutFuncAddr(pos meta.TextAddr) {
	m.Map.PutFuncAddr(pos)
	m.fun++
	m.base = pos
	m.ins = -1
}

func (m *Map) PutInsnAddr(absPos meta.TextAddr) {
	m.ins++
	relPos := int32(absPos - m.base)

	prev := len(m.FuncInsns[m.fun]) - 1
	if prev >= 0 && m.FuncInsns[m.fun][prev].ObjectOffset == relPos {
		// Replace previous mapping because no machine code was generated
		m.FuncInsns[m.fun][prev].SourceIndex = m.ins
	} else {
		m.FuncInsns[m.fun] = append(m.FuncInsns[m.fun], Mapping{relPos, m.ins})
	}
}

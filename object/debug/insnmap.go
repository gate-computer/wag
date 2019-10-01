// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"sort"

	"github.com/tsavola/wag/internal/reader"
	"github.com/tsavola/wag/object"
)

// Instruction mapping from machine code to WebAssembly.  SourcePos is zero if
// ObjectPos contains non-executable data interleaved with the code.
type InsnMapping struct {
	ObjectPos uint32 // Machine code offset in bytes.
	SourcePos uint32 // WebAssembly code offset in bytes.
	BlockLen  int32  // Length of data block (when SourcePos is 0).
}

// InsnMap implements compile.ObjectMapper.  It stores all available function,
// call, trap and instruction information.
//
// The WebAssembly module must be loaded using InsnMap's pass-through reader,
// or the source positions will be zero.
type InsnMap struct {
	TrapMap
	Insns []InsnMapping

	reader posReader
}

// Reader gets the pass-through reader.  It must not be wrapped in a buffered
// reader (the input reader can be).
func (m *InsnMap) Reader(input reader.R) reader.R {
	m.reader = posReader{r: input}
	return &m.reader
}

func (m *InsnMap) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	m.TrapMap.InitObjectMap(numImportFuncs, numOtherFuncs)
	m.reader.pos = 0
}

func (m *InsnMap) PutTrapSite(retAddr uint32, stackOffset int32) {
	m.TrapSites = append(m.TrapSites, object.CallSite{
		RetAddr:     retAddr,
		StackOffset: stackOffset,
	})
}

func (m *InsnMap) PutInsnAddr(objectPos uint32) {
	m.putMapping(objectPos, m.reader.pos, 0)
}

func (m *InsnMap) PutDataBlock(objectPos uint32, blockLen int32) {
	m.putMapping(objectPos, 0, blockLen)
}

func (m *InsnMap) putMapping(objectPos, sourcePos uint32, blockLen int32) {
	prev := len(m.Insns) - 1
	if prev >= 0 && m.Insns[prev].ObjectPos == objectPos {
		// Replace previous mapping because no machine code was generated.
		m.Insns[prev].SourcePos = sourcePos
		m.Insns[prev].BlockLen = blockLen
	} else {
		m.Insns = append(m.Insns, InsnMapping{objectPos, sourcePos, blockLen})
	}
}

func (m InsnMap) FindAddr(retAddr uint32,
) (init bool, funcIndex, callIndex int, stackOffset int32, retInsnPos uint32) {
	init, funcIndex, callIndex, stackOffset, retInsnPos = m.TrapMap.FindAddr(retAddr)

	retIndex := sort.Search(len(m.Insns), func(i int) bool {
		return m.Insns[i].ObjectPos >= retAddr
	})
	if retIndex > 0 && retIndex < len(m.Insns) {
		retInsnPos = m.Insns[retIndex].SourcePos
		ok = true
	}
	return
}

type posReader struct {
	r   reader.R
	pos uint32
}

func (pr *posReader) Read(b []byte) (n int, err error) {
	n, err = pr.r.Read(b)
	pr.pos += uint32(n)
	return
}

func (pr *posReader) ReadByte() (b byte, err error) {
	b, err = pr.r.ReadByte()
	if err == nil {
		pr.pos++
	}
	return
}

func (pr *posReader) UnreadByte() (err error) {
	err = pr.r.UnreadByte()
	if err == nil {
		pr.pos--
	}
	return
}

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
	ObjectPos int32 // Machine code offset in bytes.
	SourcePos int32 // WebAssembly code offset in bytes.
	BlockLen  int   // Length of data block (when SourcePos is 0).
}

// InsnMap implements compile.ObjectMapper.  It stores function addresses, call
// sites and instruction positions.
//
// The WebAssembly module must be loaded using InsnMap's pass-through reader,
// or the source positions will be zero.
type InsnMap struct {
	object.CallMap
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
	m.CallMap.InitObjectMap(numImportFuncs, numOtherFuncs)
	m.reader.pos = 0
}

func (m *InsnMap) PutInsnAddr(objectPos int32) {
	m.putMapping(objectPos, int32(m.reader.pos), 0)
}

func (m *InsnMap) PutDataBlock(objectPos int32, blockLen int) {
	m.putMapping(objectPos, 0, blockLen)
}

func (m *InsnMap) putMapping(objectPos, sourcePos int32, blockLen int) {
	prev := len(m.Insns) - 1
	if prev >= 0 && m.Insns[prev].ObjectPos == objectPos {
		// Replace previous mapping because no machine code was generated.
		m.Insns[prev].SourcePos = sourcePos
		m.Insns[prev].BlockLen = blockLen
	} else {
		m.Insns = append(m.Insns, InsnMapping{objectPos, sourcePos, blockLen})
	}
}

func (m *InsnMap) FindAddr(retAddr int32) (funcIndex, retInsnPos, stackOffset int32, initial, ok bool) {
	funcIndex, _, stackOffset, initial, siteOk := m.CallMap.FindAddr(retAddr)
	if !siteOk {
		return
	}

	if initial {
		ok = true
		return
	}

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
	pos int
}

func (pr *posReader) Read(b []byte) (n int, err error) {
	n, err = pr.r.Read(b)
	pr.pos += n
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

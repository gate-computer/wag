// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package debug

import (
	"sort"

	"github.com/tsavola/wag/internal/obj"
)

type antiMapper = obj.DummyDebugMapper

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
	TrapMap
	Insns []InsnMapping

	antiMapper // Conflict with TrapMap's ObjectMapper implementation.
}

func (m InsnMap) FindAddr(retAddr uint32,
) (init bool, funcIndex, callIndex int, stackOffset int32, retOffset uint32) {
	init, funcIndex, callIndex, stackOffset, retOffset = m.TrapMap.FindAddr(retAddr)

	retIndex := sort.Search(len(m.Insns), func(i int) bool {
		return m.Insns[i].ObjectOffset >= retAddr
	})
	if retIndex > 0 && retIndex < len(m.Insns) {
		retOffset = m.Insns[retIndex].SourceOffset
	}
	return
}

// Mapper creates a compile.DebugObjectMapper for the InsnMap.
//
// The source position teller is a special reader which must be used when
// loading (at least) the code section.  See NewReadTeller.
func (m *InsnMap) Mapper(source Teller) obj.ObjectMapper {
	return &insnMapper{
		m:      m,
		source: source,
	}
}

type insnMapper struct {
	m          *InsnMap
	source     Teller
	codeOffset int64
}

func (x *insnMapper) InitObjectMap(numImportFuncs, numOtherFuncs int) {
	x.m.TrapMap.InitObjectMap(numImportFuncs, numOtherFuncs)
	x.codeOffset = x.source.Tell()
}

func (x *insnMapper) PutFuncAddr(addr uint32) {
	x.m.TrapMap.PutFuncAddr(addr)
}

func (x *insnMapper) PutCallSite(retAddr uint32, stackOffset int32) {
	x.m.TrapMap.PutCallSite(retAddr, stackOffset)
}

func (x *insnMapper) PutTrapSite(addr uint32, stackOffset int32) {
	x.m.TrapMap.PutTrapSite(addr, stackOffset)
}

func (x *insnMapper) PutInsnAddr(off uint32) {
	x.putMapping(off, uint32(x.source.Tell()-x.codeOffset), 0)
}

func (x *insnMapper) PutDataBlock(off uint32, length int32) {
	x.putMapping(off, 0, length)
}

func (x *insnMapper) putMapping(objectOffset, sourceOffset uint32, blockLen int32) {
	prev := len(x.m.Insns) - 1
	if prev >= 0 && x.m.Insns[prev].ObjectOffset == objectOffset {
		// Replace previous mapping because no machine code was generated.
		x.m.Insns[prev].SourceOffset = sourceOffset
		x.m.Insns[prev].BlockLen = blockLen
	} else {
		x.m.Insns = append(x.m.Insns, InsnMapping{objectOffset, sourceOffset, blockLen})
	}
}

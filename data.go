// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"encoding/binary"
	"fmt"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
)

func putGlobalsData(buf []byte, offset int, globals []module.Global) []byte {
	size := offset + len(globals)*gen.WordSize

	if cap(buf) >= size {
		buf = buf[:size]
	} else {
		buf = make([]byte, size)
	}

	ptr := buf[offset:]

	for _, global := range globals {
		binary.LittleEndian.PutUint64(ptr, global.Init)
		ptr = ptr[8:]
	}

	return buf
}

func (m *Module) genDataGlobals() {
	align := m.MemoryAlignment
	if align == 0 {
		align = DefaultMemoryAlignment
	}

	globalsOffset := 0
	if n := m.GlobalsSize() & (align - 1); n > 0 {
		globalsOffset = align - n
	}

	m.DataBuf = putGlobalsData(m.DataBuf, globalsOffset, m.Globals)
	m.MemoryOffset = len(m.DataBuf)
}

func (m *Module) genDataMemory(load loader.L) {
	if debug {
		debugf("data section")
		debugDepth++
	}

	for i := range load.Count() {
		if debug {
			debugf("data segment")
			debugDepth++
		}

		if index := load.Varuint32(); index != 0 {
			panic(fmt.Errorf("unsupported memory index: %d", index))
		}

		offset := readOffsetInitExpr(load, m)

		size := load.Varuint32()

		needMemorySize := int64(offset) + int64(size)
		if needMemorySize > int64(m.MemoryLimitValues.Initial) {
			panic(fmt.Errorf("memory segment #%d exceeds initial memory size", i))
		}

		needDataSize := int64(m.MemoryOffset) + needMemorySize
		if needDataSize > int64(len(m.DataBuf)) {
			if int64(cap(m.DataBuf)) >= needDataSize {
				m.DataBuf = m.DataBuf[:needDataSize]
			} else {
				buf := make([]byte, needDataSize)
				copy(buf, m.DataBuf)
				m.DataBuf = buf
			}
		}

		dataOffset := m.MemoryOffset + int(offset)
		load.Into(m.DataBuf[dataOffset:needDataSize])

		if debug {
			debugDepth--
			debugf("data segmented: offset=0x%x size=0x%x", offset, size)
		}
	}

	if debug {
		debugDepth--
		debugf("data sectioned")
	}
}

func allocateRODataBeginning(oldArena []byte, size int32) (newArena []byte) {
	if len(oldArena) != 0 {
		panic("read-only data buffer length is non-zero")
	}

	newArena, _ = allocateROData(oldArena, size, 1)
	return
}

func allocateROData(oldArena []byte, size, alignment int32) (newArena []byte, addr int32) {
	oldSize := uint64(len(oldArena))
	addr64 := (oldSize + uint64(alignment-1)) &^ uint64(alignment-1)
	newSize := addr64 + uint64(size)
	if newSize <= uint64(cap(oldArena)) {
		newArena = oldArena[:newSize]
	} else {
		newArena = make([]byte, newSize)
		copy(newArena, oldArena)
	}
	addr = int32(addr64)
	return
}

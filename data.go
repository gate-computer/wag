// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"fmt"

	"github.com/tsavola/wag/internal/loader"
)

func (m *Module) genData(load loader.L) {
	if debug {
		debugf("data section")
		debugDepth++
	}

	if m.memoryOffset&15 != 0 {
		// not 16-byte aligned?  (assume at least 8-byte alignment.)
		n := len(m.globals)
		m.globals = append(m.globals, global{})
		m.data = appendGlobalsData(m.data, m.globals[n:])
		m.memoryOffset = len(m.data)
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
		if needMemorySize > int64(m.memoryLimits.initial) {
			panic(fmt.Errorf("memory segment #%d exceeds initial memory size", i))
		}

		needDataSize := int64(m.memoryOffset) + needMemorySize
		if needDataSize > int64(len(m.data)) {
			if int64(cap(m.data)) >= needDataSize {
				m.data = m.data[:needDataSize]
			} else {
				buf := make([]byte, needDataSize)
				copy(buf, m.data)
				m.data = buf
			}
		}

		dataOffset := m.memoryOffset + int(offset)
		load.Into(m.data[dataOffset:needDataSize])

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

type dataArena struct {
	buf []byte
}

func (arena *dataArena) alloc(size, alignment int32) int32 {
	oldSize := uint64(len(arena.buf))
	addr := (oldSize + uint64(alignment-1)) &^ uint64(alignment-1)
	newSize := addr + uint64(size)
	if newSize <= uint64(cap(arena.buf)) {
		arena.buf = arena.buf[:newSize]
	} else {
		newBuf := make([]byte, newSize)
		copy(newBuf, arena.buf)
		arena.buf = newBuf
	}
	return int32(addr)
}

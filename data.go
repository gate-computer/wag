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

func appendGlobalsData(buf []byte, globals []module.Global) []byte {
	oldSize := len(buf)
	newSize := oldSize + len(globals)*gen.WordSize

	if cap(buf) >= newSize {
		buf = buf[:newSize]
	} else {
		newBuf := make([]byte, newSize)
		copy(newBuf, buf)
		buf = newBuf
	}

	ptr := buf[oldSize:]

	for _, global := range globals {
		binary.LittleEndian.PutUint64(ptr, global.Init)
		ptr = ptr[8:]
	}

	return buf
}

func (m *Module) genData(load loader.L) {
	if debug {
		debugf("data section")
		debugDepth++
	}

	if m.MemoryOffset&15 != 0 {
		// not 16-byte aligned?  (assume at least 8-byte alignment.)
		n := len(m.Globals)
		m.Globals = append(m.Globals, module.Global{})
		m.DataBuf = appendGlobalsData(m.DataBuf, m.Globals[n:])
		m.MemoryOffset = len(m.DataBuf)
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

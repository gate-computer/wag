// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"encoding/binary"
	"fmt"

	"github.com/tsavola/wag/internal/loader"
)

func (m *Module) genDataGlobals() {
	align := m.MemoryAlignment
	if align == 0 {
		align = DefaultMemoryAlignment
	}

	size := m.GlobalsSize()

	offset := 0
	if n := size & (align - 1); n > 0 {
		offset = align - n
	}

	buf := m.DataBuffer.ResizeBytes(offset + size)

	ptr := buf[offset:]
	for _, global := range m.Globals {
		binary.LittleEndian.PutUint64(ptr, global.Init)
		ptr = ptr[8:]
	}

	m.MemoryOffset = len(buf)
}

func (m *Module) genDataMemory(load loader.L) {
	if debug {
		debugf("data section")
		debugDepth++
	}

	buf := m.DataBuffer.Bytes()

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

		needDataSize := m.MemoryOffset + int(needMemorySize)
		if needDataSize > len(buf) {
			buf = m.DataBuffer.ResizeBytes(needDataSize)
		}

		dataOffset := m.MemoryOffset + int(offset)
		load.Into(buf[dataOffset:needDataSize])

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

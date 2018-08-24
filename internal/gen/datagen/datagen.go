// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package datagen

import (
	"encoding/binary"
	"fmt"

	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
)

const (
	DefaultAlignment = 16 // for x86-64 SSE
)

func GenGlobals(m *module.M, align int) {
	if align == 0 {
		align = DefaultAlignment
	}

	size := len(m.Globals) * obj.Word

	offset := 0
	if n := size & (align - 1); n > 0 {
		offset = align - n
	}

	buf := m.Data.ResizeBytes(offset + size)

	ptr := buf[offset:]
	for _, global := range m.Globals {
		binary.LittleEndian.PutUint64(ptr, global.Init)
		ptr = ptr[obj.Word:]
	}

	m.MemoryOffset = len(buf)
}

func GenMemory(m *module.M, load loader.L) {
	buf := m.Data.Bytes()

	for i := range load.Count() {
		if index := load.Varuint32(); index != 0 {
			panic(fmt.Errorf("unsupported memory index: %d", index))
		}

		offset := ReadOffsetInitExpr(m, load)

		size := load.Varuint32()

		needMemorySize := int64(offset) + int64(size)
		if needMemorySize > int64(m.MemoryLimitValues.Initial) {
			panic(fmt.Errorf("memory segment #%d exceeds initial memory size", i))
		}

		needDataSize := m.MemoryOffset + int(needMemorySize)
		if needDataSize > len(buf) {
			buf = m.Data.ResizeBytes(needDataSize)
		}

		dataOffset := m.MemoryOffset + int(offset)
		load.Into(buf[dataOffset:needDataSize])
	}
}

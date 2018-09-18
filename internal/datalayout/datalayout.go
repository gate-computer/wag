// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package datalayout

import (
	"encoding/binary"
	"fmt"

	"github.com/tsavola/wag/internal/data"
	"github.com/tsavola/wag/internal/initexpr"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
)

const (
	MinAlignment = 16 // for x86-64 SSE
)

func CopyGlobalsAlign(buffer data.Buffer, m *module.M, alignment int) {
	size := len(m.Globals) * obj.Word

	offset := 0
	if n := size & (alignment - 1); n > 0 {
		offset = alignment - n
	}

	b := buffer.ResizeBytes(offset + size)
	copyGlobals(b[offset:], m)
}

func CopyGlobalsAtEnd(b []byte, m *module.M) {
	size := len(m.Globals) * obj.Word
	offset := len(b) - size
	copyGlobals(b[offset:], m)
}

func copyGlobals(b []byte, m *module.M) {
	for _, global := range m.Globals {
		binary.LittleEndian.PutUint64(b, global.Init)
		b = b[obj.Word:]
	}
}

func ReadMemory(buffer data.Buffer, load loader.L, m *module.M) {
	b := buffer.Bytes()
	memoryOffset := len(b)

	for i := range load.Count() {
		if index := load.Varuint32(); index != 0 {
			panic(fmt.Errorf("unsupported memory index: %d", index))
		}

		offset := initexpr.ReadOffset(m, load)

		size := load.Varuint32()

		needMemorySize := int64(offset) + int64(size)
		if needMemorySize > int64(m.MemoryLimitValues.Initial) {
			panic(fmt.Errorf("memory segment #%d exceeds initial memory size", i))
		}

		needDataSize := memoryOffset + int(needMemorySize)
		if needDataSize > len(b) {
			b = buffer.ResizeBytes(needDataSize)
		}

		dataOffset := memoryOffset + int(offset)
		load.Into(b[dataOffset:needDataSize])
	}
}

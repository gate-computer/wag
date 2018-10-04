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

func MemoryOffset(m *module.M, alignment int) int {
	globalsSize := len(m.Globals) * obj.Word

	mask := alignment - 1
	return (globalsSize + mask) &^ mask
}

func CopyGlobalsAlign(buffer data.Buffer, m *module.M, memoryOffset int) {
	globalsSize := len(m.Globals) * obj.Word
	globalsOffset := memoryOffset - globalsSize

	b := buffer.ResizeBytes(memoryOffset)
	b = b[globalsOffset:]

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

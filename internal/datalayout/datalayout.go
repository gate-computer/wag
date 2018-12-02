// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package datalayout

import (
	"encoding/binary"
	"io"
	"io/ioutil"
	"math"

	"github.com/tsavola/wag/internal/data"
	"github.com/tsavola/wag/internal/initexpr"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
)

const (
	MinAlignment = 16 // for x86-64 SSE
)

const (
	maxSegments = math.MaxInt32
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

	for i := range load.Count(maxSegments, "segment") {
		offset, size := readSegmentHeader(load, m, i)

		var (
			bufOffset = memoryOffset + int(offset)
			bufEnd    = bufOffset + int(size)
		)

		if bufEnd > len(b) {
			b = buffer.ResizeBytes(bufEnd)
		}

		load.Into(b[bufOffset:bufEnd])
	}
}

func ValidateMemory(load loader.L, m *module.M) {
	for i := range load.Count(maxSegments, "segment") {
		_, size := readSegmentHeader(load, m, i)

		if _, err := io.CopyN(ioutil.Discard, load.R, int64(size)); err != nil {
			panic(err)
		}
	}
}

func readSegmentHeader(load loader.L, m *module.M, segmentIndex int) (offset, size uint32) {
	if memoryIndex := load.Varuint32(); memoryIndex != 0 {
		panic(module.Errorf("unsupported memory index: %d", memoryIndex))
	}

	offset = initexpr.ReadOffset(m, load)
	size = load.Varuint32()

	if uint64(offset)+uint64(size) > uint64(m.MemoryLimitValues.Initial) {
		panic(module.Errorf("memory segment #%d exceeds initial memory size", segmentIndex))
	}

	return
}

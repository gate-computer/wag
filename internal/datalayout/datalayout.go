// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package datalayout

import (
	"encoding/binary"
	"io"
	"math"

	"gate.computer/wag/internal/data"
	"gate.computer/wag/internal/initexpr"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/internal/pan"
)

const (
	MinAlignment = 16 // for amd64 SSE
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

	for _, g := range m.Globals {
		value := m.EvaluateGlobalInitializer(int(g.InitImport), g.InitConst)
		binary.LittleEndian.PutUint64(b, value)
		b = b[obj.Word:]
	}
}

func ReadMemory(buffer data.Buffer, load *loader.L, m *module.M) {
	b := buffer.Bytes()
	memoryOffset := len(b)

	for i := range load.Span(maxSegments, "segment") {
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

func ValidateMemory(load *loader.L, m *module.M) {
	for i := range load.Span(maxSegments, "segment") {
		_, size := readSegmentHeader(load, m, i)
		pan.Must(io.CopyN(io.Discard, load, int64(size)))
	}
}

func readSegmentHeader(load *loader.L, m *module.M, segmentIndex int) (offset, size uint32) {
	if index := load.Varuint32(); index >= m.NumMemory() {
		pan.Panic(module.Errorf("unknown memory: %d", index))
	}

	offset = initexpr.ReadOffset(m, load)
	size = load.Varuint32()

	if uint64(offset)+uint64(size) > uint64(m.MemoryLimit.Init) {
		pan.Panic(module.Errorf("memory segment #%d exceeds initial memory size", segmentIndex))
	}

	return
}

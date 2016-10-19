package wag

import (
	"fmt"
)

func (m *Module) genData(r reader) {
	if debug {
		debugf("data section")
		debugDepth++
	}

	for i := range r.readCount() {
		if debug {
			debugf("data segment")
			debugDepth++
		}

		if index := r.readVaruint32(); index != 0 {
			panic(fmt.Errorf("unsupported memory index: %d", index))
		}

		offset := readOffsetInitExpr(r, m)

		size := r.readVaruint32()

		needMemorySize := int64(offset) + int64(size)
		if needMemorySize >= int64(m.memoryLimits.initial) {
			panic(fmt.Errorf("memory segment #%d exceeds initial memory size", i))
		}

		needDataSize := int64(m.memoryOffset) + needMemorySize
		if n := needDataSize - int64(m.data.Len()); n > 0 {
			m.data.Grow(int(n))
		}

		dataOffset := int(m.memoryOffset) + int(offset)
		r.read(m.data.Bytes()[dataOffset:needDataSize])

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

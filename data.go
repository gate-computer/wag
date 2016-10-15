package wag

import (
	"fmt"
)

func (m *Module) genData(r reader) {
	debugf("data section")
	debugDepth++

	for i := range r.readCount() {
		debugf("data segment")
		debugDepth++

		if index := r.readVaruint32(); index != 0 {
			panic(fmt.Errorf("unsupported memory index: %d", index))
		}

		offset := readOffsetInitExpr(r, m)

		size := r.readVaruint32()

		needSize := offset + uint64(size)
		if needSize >= uint64(m.memoryLimits.initial) {
			panic(fmt.Errorf("memory segment #%d exceeds initial memory size", i))
		}

		oldSize := uint64(len(m.data))
		if needSize > oldSize {
			buf := make([]byte, needSize)
			copy(buf, m.data)
			m.data = buf
		}

		r.read(m.data[offset:needSize])

		debugDepth--
		debugf("data segmented: offset=0x%x size=0x%x", offset, size)
	}

	debugDepth--
	debugf("data sectioned")
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

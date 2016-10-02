package wag

type dataArena struct {
	buf []byte
}

func (arena *dataArena) alloc(size, alignment int) (addr int) {
	oldSize := len(arena.buf)
	addr = (oldSize + (alignment - 1)) &^ (alignment - 1)
	newSize := addr + size
	if newSize <= cap(arena.buf) {
		arena.buf = arena.buf[:newSize]
	} else {
		newBuf := make([]byte, newSize)
		copy(newBuf, arena.buf)
		arena.buf = newBuf
	}
	return
}

func (m *Module) Data() (globals, data []byte) {
	var memory dataArena

	for _, s := range m.Memory.Segments {
		if s.Offset < len(memory.buf) {
			panic("data segment overlaps with previous segment")
		}

		skip := s.Offset - len(memory.buf)

		addr := memory.alloc(skip+len(s.Data), 1)
		copy(memory.buf[addr+skip:], s.Data)
	}

	data = memory.buf
	return
}

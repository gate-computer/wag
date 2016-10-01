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

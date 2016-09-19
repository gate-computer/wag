package wag

const (
	dataAlignment = 8
)

type dataAllocation struct {
	addr      int
	size      int
	populator func([]byte)
}

type dataArena struct {
	size   int
	allocs []*dataAllocation
}

func (arena *dataArena) allocate(size, alignment int, populator func([]byte)) (alloc *dataAllocation) {
	addr := (arena.size + (alignment - 1)) &^ (alignment - 1)
	alloc = &dataAllocation{addr, size, populator}

	arena.size = addr + size
	arena.allocs = append(arena.allocs, alloc)
	return
}

func (arena *dataArena) populate(buf []byte) []byte {
	if buf == nil {
		buf = make([]byte, arena.size)
	} else if arena.size <= len(buf) {
		buf = buf[:arena.size]
	} else {
		panic("read-only data buffer is too small")
	}

	for _, x := range arena.allocs {
		x.populator(buf[x.addr : x.addr+x.size])
	}

	return buf
}

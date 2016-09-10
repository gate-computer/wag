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

func (arena *dataArena) populate() (data []byte) {
	data = make([]byte, arena.size)
	for _, x := range arena.allocs {
		x.populator(data[x.addr : x.addr+x.size])
	}
	return
}

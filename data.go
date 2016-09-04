package wag

const (
	dataAlignment = 8
)

type dataAllocation struct {
	size      int
	populator func([]byte)
}

type dataArena struct {
	size   int
	allocs []*dataAllocation
}

func (arena *dataArena) allocate(size int) (alloc *dataAllocation, addr int) {
	addr = arena.size
	arena.size = ((arena.size + size) + (dataAlignment - 1)) &^ (dataAlignment - 1)
	alloc = &dataAllocation{size: size}
	arena.allocs = append(arena.allocs, alloc)
	return
}

func (arena *dataArena) populate() (data []byte) {
	data = make([]byte, arena.size)
	tail := data
	for _, alloc := range arena.allocs {
		alloc.populator(tail[:alloc.size])
		size := (alloc.size + (dataAlignment - 1)) &^ (dataAlignment - 1)
		tail = tail[size:]
	}
	return
}

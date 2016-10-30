package wag

import (
	"fmt"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/types"
)

func regIndex(cat gen.RegCategory, reg regs.R) uint8 {
	return uint8(reg<<1) + uint8(cat)
}

func regMask(cat gen.RegCategory, reg regs.R) uint64 {
	return uint64(1) << regIndex(cat, reg)
}

//
type regAllocator struct {
	avail uint64
	freed uint64
}

func (ra *regAllocator) init(avail uint64) {
	ra.avail = avail
	ra.freed = avail
}

func (ra *regAllocator) alloc(cat gen.RegCategory) (reg regs.R, ok bool) {
	for bits := ra.freed >> uint8(cat); bits != 0; bits >>= 2 {
		if (bits & 1) != 0 {
			ra.freed &^= regMask(cat, reg)
			ok = true

			debugf("reg alloc: %s %s", cat, reg)
			break
		}

		reg++
	}

	return
}

func (ra *regAllocator) allocSpecific(cat gen.RegCategory, reg regs.R) {
	debugf("reg alloc: %s %s specifically", cat, reg)

	mask := regMask(cat, reg)

	if (ra.freed & mask) == 0 {
		panic(reg)
	}

	ra.freed &^= mask
}

func (ra *regAllocator) free(cat gen.RegCategory, reg regs.R) {
	mask := regMask(cat, reg)

	if (ra.avail & mask) == 0 {
		debugf("reg free (nop): %s %s", cat, reg)
	} else {
		debugf("reg free: %s %s", cat, reg)
	}

	if (ra.freed & mask) != 0 {
		panic(reg)
	}

	if (ra.avail & mask) == 0 {
		return
	}

	ra.freed |= mask
}

func (ra *regAllocator) freeAll() {
	ra.freed = ra.avail
}

func (ra *regAllocator) allocated(cat gen.RegCategory, reg regs.R) bool {
	debugf("reg check allocation: %s %s", cat, reg)

	mask := regMask(cat, reg)

	return ((ra.avail &^ ra.freed) & mask) != 0
}

func (ra *regAllocator) assertNoneAllocated() {
	if ra.freed != ra.avail {
		panic(fmt.Sprintf("registers still allocated at end of function: %08x", (^ra.freed)&ra.avail))
	}
}

//
type regMap [64]uint8

func (rm *regMap) set(cat gen.RegCategory, reg regs.R, index int) {
	rm[regIndex(cat, reg)] = uint8(index) + 1
}

func (rm *regMap) clear(cat gen.RegCategory, reg regs.R) {
	rm[regIndex(cat, reg)] = 0
}

func (rm *regMap) get(cat gen.RegCategory, reg regs.R) (index int) {
	return int(rm[regIndex(cat, reg)]) - 1
}

//
type regIterator struct {
	counts [2]int
	regs   [2][]regs.R
}

func (ri *regIterator) init(paramRegs [2][]regs.R, paramTypes []types.T) (stackCount int32) {
	for i := int32(len(paramTypes)) - 1; i >= 0; i-- {
		cat := gen.TypeRegCategory(paramTypes[i])
		if ri.counts[cat] == len(paramRegs[cat]) {
			stackCount = i + 1
			break
		}
		ri.counts[cat]++
	}
	ri.initRegs(paramRegs)
	return
}

func (ri *regIterator) initRegs(paramRegs [2][]regs.R) {
	for cat, n := range ri.counts {
		ri.regs[cat] = paramRegs[cat][:n]
	}
}

func (ri *regIterator) iterForward(cat gen.RegCategory) (reg regs.R) {
	reg = ri.regs[cat][0]
	ri.regs[cat] = ri.regs[cat][1:]
	return
}

func (ri *regIterator) iterBackward(cat gen.RegCategory) (reg regs.R) {
	n := len(ri.regs[cat]) - 1
	reg = ri.regs[cat][n]
	ri.regs[cat] = ri.regs[cat][:n]
	return
}

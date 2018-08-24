// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package regalloc

import (
	"fmt"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/regs"
)

func regIndex(cat abi.Category, reg regs.R) uint8 {
	return uint8(reg<<1) + uint8(cat)
}

func regMask(cat abi.Category, reg regs.R) uint64 {
	return uint64(1) << regIndex(cat, reg)
}

type Allocator struct {
	avail uint64
	freed uint64
}

func MakeAllocator(avail uint64) Allocator {
	return Allocator{avail, avail}
}

func (a *Allocator) Alloc(t abi.Type) (reg regs.R, ok bool) {
	cat := t.Category()

	for bits := a.freed >> uint8(cat); bits != 0; bits >>= 2 {
		if (bits & 1) != 0 {
			a.freed &^= regMask(cat, reg)
			ok = true
			break
		}

		reg++
	}

	return
}

func (a *Allocator) AllocSpecific(t abi.Type, reg regs.R) {
	mask := regMask(t.Category(), reg)

	if (a.freed & mask) == 0 {
		panic(reg)
	}

	a.freed &^= mask
}

func (a *Allocator) SetAllocated(t abi.Type, reg regs.R) {
	mask := regMask(t.Category(), reg)

	a.freed &^= mask
}

func (a *Allocator) Free(t abi.Type, reg regs.R) {
	mask := regMask(t.Category(), reg)

	if (a.freed & mask) != 0 {
		panic(reg)
	}

	if (a.avail & mask) == 0 {
		return
	}

	a.freed |= mask
}

func (a *Allocator) FreeAll() {
	a.freed = a.avail
}

// Allocated indicates if we can hang onto a register returned by ISA ops.
func (a *Allocator) Allocated(t abi.Type, reg regs.R) bool {
	mask := regMask(t.Category(), reg)

	return ((a.avail &^ a.freed) & mask) != 0
}

func (a *Allocator) AssertNoneAllocated() {
	if a.freed != a.avail {
		panic(fmt.Sprintf("registers still allocated at end of function: %08x", (^a.freed)&a.avail))
	}
}

type Map [64]uint8

func (m *Map) Set(cat abi.Category, reg regs.R, index int) {
	m[regIndex(cat, reg)] = uint8(index) + 1
}

func (m *Map) Clear(cat abi.Category, reg regs.R) {
	m[regIndex(cat, reg)] = 0
}

func (m *Map) Get(cat abi.Category, reg regs.R) (index int) {
	return int(m[regIndex(cat, reg)]) - 1
}

type Iterator struct {
	counts [2]int
	regs   [2][]regs.R
}

func (iter *Iterator) Init(paramRegs [2][]regs.R, paramTypes []abi.Type) (stackCount int32) {
	for i := int32(len(paramTypes)) - 1; i >= 0; i-- {
		cat := paramTypes[i].Category()
		if iter.counts[cat] == len(paramRegs[cat]) {
			stackCount = i + 1
			break
		}
		iter.counts[cat]++
	}
	iter.InitRegs(paramRegs)
	return
}

func (iter *Iterator) InitRegs(paramRegs [2][]regs.R) {
	for cat, n := range iter.counts {
		iter.regs[cat] = paramRegs[cat][:n]
	}
}

func (iter *Iterator) IterForward(cat abi.Category) (reg regs.R) {
	reg = iter.regs[cat][0]
	iter.regs[cat] = iter.regs[cat][1:]
	return
}

func (iter *Iterator) IterBackward(cat abi.Category) (reg regs.R) {
	n := len(iter.regs[cat]) - 1
	reg = iter.regs[cat][n]
	iter.regs[cat] = iter.regs[cat][:n]
	return
}

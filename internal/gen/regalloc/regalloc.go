// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package regalloc

import (
	"fmt"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen/reg"
)

func regIndex(cat abi.Category, r reg.R) uint8 {
	return uint8(r<<1) + uint8(cat)
}

func regMask(cat abi.Category, r reg.R) uint64 {
	return uint64(1) << regIndex(cat, r)
}

type Allocator struct {
	avail uint64
	freed uint64
}

func MakeAllocator(avail uint64) Allocator {
	return Allocator{avail, avail}
}

func (a *Allocator) Alloc(t abi.Type) (r reg.R, ok bool) {
	cat := t.Category()

	for bits := a.freed >> uint8(cat); bits != 0; bits >>= 2 {
		if (bits & 1) != 0 {
			a.freed &^= regMask(cat, r)
			ok = true
			break
		}

		r++
	}

	return
}

func (a *Allocator) AllocSpecific(t abi.Type, r reg.R) {
	mask := regMask(t.Category(), r)

	if (a.freed & mask) == 0 {
		panic(r)
	}

	a.freed &^= mask
}

func (a *Allocator) SetAllocated(t abi.Type, r reg.R) {
	mask := regMask(t.Category(), r)

	a.freed &^= mask
}

func (a *Allocator) Free(t abi.Type, r reg.R) {
	mask := regMask(t.Category(), r)

	if (a.freed & mask) != 0 {
		panic(r)
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
func (a *Allocator) Allocated(t abi.Type, r reg.R) bool {
	mask := regMask(t.Category(), r)

	return ((a.avail &^ a.freed) & mask) != 0
}

func (a *Allocator) AssertNoneAllocated() {
	if a.freed != a.avail {
		panic(fmt.Sprintf("registers still allocated at end of function: %08x", (^a.freed)&a.avail))
	}
}

type Map [64]uint8

func (m *Map) Set(cat abi.Category, r reg.R, index int) {
	m[regIndex(cat, r)] = uint8(index) + 1
}

func (m *Map) Clear(cat abi.Category, r reg.R) {
	m[regIndex(cat, r)] = 0
}

func (m *Map) Get(cat abi.Category, r reg.R) (index int) {
	return int(m[regIndex(cat, r)]) - 1
}

type Iterator struct {
	counts [2]int
	reg    [2][]reg.R
}

func (iter *Iterator) Init(paramRegs [2][]reg.R, paramTypes []abi.Type) (stackCount int32) {
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

func (iter *Iterator) InitRegs(paramRegs [2][]reg.R) {
	for cat, n := range iter.counts {
		iter.reg[cat] = paramRegs[cat][:n]
	}
}

func (iter *Iterator) IterForward(cat abi.Category) (r reg.R) {
	r = iter.reg[cat][0]
	iter.reg[cat] = iter.reg[cat][1:]
	return
}

func (iter *Iterator) IterBackward(cat abi.Category) (r reg.R) {
	n := len(iter.reg[cat]) - 1
	r = iter.reg[cat][n]
	iter.reg[cat] = iter.reg[cat][:n]
	return
}

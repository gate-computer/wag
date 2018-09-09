// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package regalloc

import (
	"math/bits"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen/debug"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/isa/reglayout"
)

type bitmap uint32

const (
	numInt   = reglayout.AllocIntLast - reglayout.AllocIntFirst + 1
	numFloat = reglayout.AllocFloatLast - reglayout.AllocFloatFirst + 1

	allocatableInt   = bitmap((1<<numInt - 1) << reglayout.AllocIntFirst)
	allocatableFloat = bitmap((1<<numFloat - 1) << reglayout.AllocFloatFirst)
)

type Allocator struct {
	categories [2]state
}

func Make() (a Allocator) {
	a.categories[abi.Int].init(allocatableInt)
	a.categories[abi.Float].init(allocatableFloat)
	return
}

func (a *Allocator) AllocResult(t abi.Type) (r reg.R) {
	r = a.categories[t.Category()].allocResult()

	if r != reg.Result {
		debug.Printf("allocate %s register: %s", t.Category(), r)
	} else {
		debug.Printf("failed to allocate %s register", t.Category())
	}

	return
}

// Free can be called with reg.Result or reg.ScratchISA.
func (a *Allocator) Free(t abi.Type, r reg.R) {
	debug.Printf("free %s register: %s", t.Category(), r)

	a.categories[t.Category()].free(r)
}

func (a *Allocator) CheckNoneAllocated() {
	a.categories[abi.Int].checkNoneAllocated(allocatableInt, "int registers still allocated")
	a.categories[abi.Float].checkNoneAllocated(allocatableFloat, "float registers still allocated")
}

func (a *Allocator) DebugPrintAllocated() {
	a.categories[abi.Int].debugPrintAllocated(reglayout.AllocIntFirst, reglayout.AllocIntLast, "int")
	a.categories[abi.Float].debugPrintAllocated(reglayout.AllocFloatFirst, reglayout.AllocFloatLast, "float")
}

type state struct {
	available bitmap // registers
}

func (s *state) init(allocatable bitmap) {
	s.available = allocatable
}

func (s *state) allocResult() reg.R {
	i := uint(bits.TrailingZeros32(uint32(s.available)))
	s.available = s.available &^ (1 << i)
	return reg.R(i & 31) // convert 32 to 0 (result register)
}

func (s *state) free(r reg.R) {
	s.available |= (1 << r) &^ 0x3 // ignore result and scratch regs
}

func (s *state) checkNoneAllocated(allocatable bitmap, msg string) {
	if s.available != allocatable {
		panic(msg)
	}
}

func (s *state) debugPrintAllocated(first, last reg.R, kind string) {
	if debug.Enabled {
		for r := first; r <= last; r++ {
			if s.available&(1<<r) == 0 {
				debug.Printf("%s register is currently allocated: %s", kind, r)
			}
		}
	}
}

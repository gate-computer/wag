// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package regalloc

import (
	"testing"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
)

func TestAllocatorInit(t *testing.T) {
	for _, avail := range []uint64{0xffffffffffffffff, 0, 123456789} {
		t.Logf("avail: 0x%016x", avail)

		var a Allocator
		a.Init(avail)

		a.AssertNoneAllocated()
	}
}

func TestAlloc(t *testing.T) {
	for _, avail := range []uint64{0xffffffffffffffff, 0xf} {
		t.Logf("avail: 0x%016x", avail)

		var a Allocator
		a.Init(avail)

		r1, ok := a.Alloc(gen.RegCategoryInt)
		if !ok {
			t.Fatal("1")
		}
		if !a.Allocated(gen.RegCategoryInt, r1) {
			t.Fatal("2")
		}

		r2, ok := a.Alloc(gen.RegCategoryInt)
		if !ok {
			t.Fatal("3")
		}
		if !a.Allocated(gen.RegCategoryInt, r2) {
			t.Fatal("4")
		}
		if r1 == r2 {
			t.Fatal("5")
		}

		r1f, ok := a.Alloc(gen.RegCategoryFloat)
		if !ok {
			t.Fatal("6")
		}
		if !a.Allocated(gen.RegCategoryFloat, r1f) {
			t.Fatal("7")
		}
		t.Logf("r1  = %v", r1)
		t.Logf("r1f = %v", r1f)
		if r1 != r1f { // assume predictable allocation order
			t.Fatal("8")
		}
	}
}

func TestAllocSpecific(t *testing.T) {
	for _, avail := range []uint64{0xffffffffffffffff, 1 << (5 << 1)} {
		t.Logf("avail: 0x%016x", avail)

		var a Allocator
		a.Init(avail)

		t.Logf("cat = %#v", gen.RegCategoryInt)
		t.Logf("reg = %#v", regs.R(5))
		t.Logf("a = %#v", a)
		t.Logf("reg index = %v", regIndex(gen.RegCategoryInt, regs.R(5)))
		t.Logf("reg mask = %v", regMask(gen.RegCategoryInt, regs.R(5)))

		a.AllocSpecific(gen.RegCategoryInt, regs.R(5))
		if !a.Allocated(gen.RegCategoryInt, regs.R(5)) {
			t.Fatal("1")
		}

		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("2")
				}
			}()
			a.AllocSpecific(gen.RegCategoryInt, regs.R(5))
		}()
	}
}

func TestSetAllocated(t *testing.T) {
	for _, avail := range []uint64{0xffffffffffffffff, 1 << (5 << 1)} {
		t.Logf("avail: 0x%016x", avail)

		var a Allocator
		a.Init(avail)

		a.SetAllocated(gen.RegCategoryInt, regs.R(5))
		if !a.Allocated(gen.RegCategoryInt, regs.R(5)) {
			t.Fatal("1")
		}

		a.SetAllocated(gen.RegCategoryInt, regs.R(5))
		if !a.Allocated(gen.RegCategoryInt, regs.R(5)) {
			t.Fatal("2")
		}

		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("3")
				}
			}()
			a.AllocSpecific(gen.RegCategoryInt, regs.R(5))
		}()
	}
}

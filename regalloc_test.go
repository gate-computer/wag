package wag

import (
	"testing"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
)

func TestRegAllocInit(t *testing.T) {
	for _, avail := range []uint64{0xffffffffffffffff, 0, 123456789} {
		t.Logf("avail: 0x%016x", avail)

		var ra regAllocator
		ra.init(avail)

		ra.assertNoneAllocated()
	}
}

func TestRegAlloc(t *testing.T) {
	for _, avail := range []uint64{0xffffffffffffffff, 0xf} {
		t.Logf("avail: 0x%016x", avail)

		var ra regAllocator
		ra.init(avail)

		r1, ok := ra.alloc(gen.RegCategoryInt)
		if !ok {
			t.Fatal("1")
		}
		if !ra.allocated(gen.RegCategoryInt, r1) {
			t.Fatal("2")
		}

		r2, ok := ra.alloc(gen.RegCategoryInt)
		if !ok {
			t.Fatal("3")
		}
		if !ra.allocated(gen.RegCategoryInt, r2) {
			t.Fatal("4")
		}
		if r1 == r2 {
			t.Fatal("5")
		}

		r1f, ok := ra.alloc(gen.RegCategoryFloat)
		if !ok {
			t.Fatal("6")
		}
		if !ra.allocated(gen.RegCategoryFloat, r1f) {
			t.Fatal("7")
		}
		t.Logf("r1  = %v", r1)
		t.Logf("r1f = %v", r1f)
		if r1 != r1f { // assume predictable allocation order
			t.Fatal("8")
		}
	}
}

func TestRegAllocSpecific(t *testing.T) {
	for _, avail := range []uint64{0xffffffffffffffff, 1 << (5 << 1)} {
		t.Logf("avail: 0x%016x", avail)

		var ra regAllocator
		ra.init(avail)

		t.Logf("cat = %#v", gen.RegCategoryInt)
		t.Logf("reg = %#v", regs.R(5))
		t.Logf("ra = %#v", ra)
		t.Logf("reg index = %v", regIndex(gen.RegCategoryInt, regs.R(5)))
		t.Logf("reg mask = %v", regMask(gen.RegCategoryInt, regs.R(5)))

		ra.allocSpecific(gen.RegCategoryInt, regs.R(5))
		if !ra.allocated(gen.RegCategoryInt, regs.R(5)) {
			t.Fatal("1")
		}

		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("2")
				}
			}()
			ra.allocSpecific(gen.RegCategoryInt, regs.R(5))
		}()
	}
}

func TestRegAllocSet(t *testing.T) {
	for _, avail := range []uint64{0xffffffffffffffff, 1 << (5 << 1)} {
		t.Logf("avail: 0x%016x", avail)

		var ra regAllocator
		ra.init(avail)

		ra.setAllocated(gen.RegCategoryInt, regs.R(5))
		if !ra.allocated(gen.RegCategoryInt, regs.R(5)) {
			t.Fatal("1")
		}

		ra.setAllocated(gen.RegCategoryInt, regs.R(5))
		if !ra.allocated(gen.RegCategoryInt, regs.R(5)) {
			t.Fatal("2")
		}

		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("3")
				}
			}()
			ra.allocSpecific(gen.RegCategoryInt, regs.R(5))
		}()
	}
}

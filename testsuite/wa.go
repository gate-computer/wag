// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math"
	"testing"

	"gate.computer/wag/wa"
)

type arg struct {
	wa.Type
	Value uint64
}

func (a arg) equal(t *testing.T, b arg) bool {
	if a.Type != b.Type {
		return false
	}

	switch a.Type {
	case wa.Void:
		return true

	case wa.F32:
		return equalF32(t, a.Value, b.Value)

	case wa.F64:
		return equalF64(t, a.Value, b.Value)

	case wa.I32:
		return uint32(a.Value) == uint32(b.Value)

	default:
		return a.Value == b.Value
	}
}

func (a arg) String() string {
	switch {
	case a.Type == wa.Void:
		return a.Type.String()

	case a.Type == wa.F32:
		if isF32NaN(a.Value) {
			return fmt.Sprintf("%s(NaN:%#08x)", a.Type, uint32(a.Value))
		} else {
			return fmt.Sprintf("%s(%f)", a.Type, math.Float32frombits(uint32(a.Value)))
		}

	case a.Type == wa.F64:
		if isF64NaN(a.Value) {
			return fmt.Sprintf("%s(NaN:%#016x)", a.Type, a.Value)
		} else {
			return fmt.Sprintf("%s(%f)", a.Type, math.Float64frombits(a.Value))
		}

	case a.Type.Category() == wa.Int && a.Value < 256:
		return fmt.Sprintf("%s(%d)", a.Type, uint32(a.Value))

	case a.Type.Category() == wa.Int:
		return fmt.Sprintf("%s(%#x)", a.Type, a.Value)

	default:
		return a.Type.String()
	}
}

func equalF32(t *testing.T, a, b uint64) bool {
	if isF32NaN(a) {
		if isF32NaN(b) {
			return true // equalF32NaN(t, a, b)
		}
		return false
	}

	x := math.Float32frombits(uint32(a))
	y := math.Float32frombits(uint32(b))
	return x == y
}

func equalF64(t *testing.T, a, b uint64) bool {
	if isF64NaN(a) {
		if isF64NaN(b) {
			return true // equalF64NaN(t, a, b)
		}
		return false
	}

	x := math.Float64frombits(a)
	y := math.Float64frombits(b)
	return x == y
}

func isF32NaN(a uint64) bool {
	return a&0x7f000000 == 0x7f000000 && a&0xffffff != 0
}

func isF64NaN(a uint64) bool {
	return a&0x7ff0000000000000 == 0x7ff0000000000000 && a&0xfffffffffffff != 0
}

// func equalF32NaN(t *testing.T, a0, b0 uint64) bool {
// 	a := a0 & 0x7fffff
// 	b := b0 & 0x7fffff
//
// 	// Canonical NaN.
// 	if a == 0 {
// 		return b == 0
// 	}
// 	if b == 0 {
// 		return false
// 	}
//
// 	t.Logf("non-canonical NaN: %#08x == %#08x", a0, b0)
//
// 	// Arithmetic NaN.
// 	if a == 0x400000 && b == 0x400000 {
// 		return true
// 	}
//
// 	// Other NaNs.
// 	return true
// }
//
// func equalF64NaN(t *testing.T, a0, b0 uint64) bool {
// 	a := a0 & 0x7ffffffffffff
// 	b := b0 & 0x7ffffffffffff
//
// 	// Canonical NaN.
// 	if a == 0 {
// 		return b == 0
// 	}
// 	if b == 0 {
// 		return false
// 	}
//
// 	t.Logf("non-canonical NaN: %#016x == %#016x", a0, b0)
//
// 	// Arithmetic NaN.
// 	if a == 0x4000000000000 && b == 0x4000000000000 {
// 		return true
// 	}
//
// 	// Other NaNs.
// 	return true
// }

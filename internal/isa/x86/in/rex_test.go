// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"testing"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen/reg"
)

func TestTypeRexW(t *testing.T) {
	if bit := typeRexW(abi.I32); bit != 0 {
		t.Errorf("typeRexW(abi.I32) = 0x%x", bit)
	}
	if bit := typeRexW(abi.I64); bit != RexW {
		t.Errorf("typeRexW(abi.I64) = 0x%x", bit)
	}
	if bit := typeRexW(abi.F32); bit != 0 {
		t.Errorf("typeRexW(abi.F32) = 0x%x", bit)
	}
	if bit := typeRexW(abi.F64); bit != RexW {
		t.Errorf("typeRexW(abi.F64) = 0x%x", bit)
	}
}

func TestRegRexR(t *testing.T) {
	for r := reg.R(0); r <= reg.R(7); r++ {
		if bit := regRexR(r); bit != 0 {
			t.Errorf("regRexR(%s) = 0x%x", r, bit)
		}
	}
	for r := reg.R(8); r <= reg.R(15); r++ {
		if bit := regRexR(r); bit != RexR {
			t.Errorf("regRexR(%s) = 0x%x", r, bit)
		}
	}
}

func TestRegRexX(t *testing.T) {
	for r := reg.R(0); r <= reg.R(7); r++ {
		if bit := regRexX(r); bit != 0 {
			t.Errorf("regRexX(%s) = 0x%x", r, bit)
		}
	}
	for r := reg.R(8); r <= reg.R(15); r++ {
		if bit := regRexX(r); bit != RexX {
			t.Errorf("regRexX(%s) = 0x%x", r, bit)
		}
	}
}

func TestRegRexB(t *testing.T) {
	for r := reg.R(0); r <= reg.R(7); r++ {
		if bit := regRexB(r); bit != 0 {
			t.Errorf("regRexB(%s) = 0x%x", r, bit)
		}
	}
	for r := reg.R(8); r <= reg.R(15); r++ {
		if bit := regRexB(r); bit != RexB {
			t.Errorf("regRexB(%s) = 0x%x", r, bit)
		}
	}
}

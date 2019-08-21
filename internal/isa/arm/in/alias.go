// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package in

import (
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/wa"
)

func LogicalShiftLeft(rd, rn reg.R, uimm uint32, t wa.Type) uint32 {
	var s, r uint32
	if t.Size() == 4 {
		r = (32 - uimm) & 31
		s = (31 - uimm&31)
	} else {
		r = (64 - uimm) & 63
		s = (63 - uimm&63)
	}
	return UBFM.RdRnI6sI6r(rd, rn, s, r, t)
}

func PushIntReg(r reg.R) uint32 {
	return STRpre.RtRnI9(r, RegFakeSP, Int9(-obj.Word), wa.I64)
}

func PopIntReg(r reg.R) uint32 {
	return LDRpost.RtRnI9(r, RegFakeSP, Int9(obj.Word), wa.I64)
}

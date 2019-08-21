// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/wa"
)

func moveIntImm(text *code.Buf, r reg.R, val int64) {
	var o output
	var data = uint64(val)

	switch {
	case val == 0:
		o.uint32(in.MOVZ.RdI16Hw(r, 0, 0, wa.I64))

	case val > 0:
		insn := in.MOVZ // First chunk clears surroundings.

		for i := uint32(0); i < 4; i++ {
			if chunk := in.Uint16(data); chunk != 0 {
				o.uint32(insn.RdI16Hw(r, chunk, i, wa.I64))
				insn = in.MOVK // Secondary chunks keep surroundings.
			}
			data >>= 16
		}

	case val == -1:
		o.uint32(in.MOVN.RdI16Hw(r, 0, 0, wa.I64))

	case val < -1:
		var i uint32

		for i = 0; i < 4; i++ {
			if chunk := uint16(data); chunk != 0xffff {
				o.uint32(in.MOVN.RdI16Hw(r, uint32(^chunk), i, wa.I64)) // Set surrounding bits.
				break
			}
			data >>= 16
		}

		for i++; i < 4; i++ {
			data >>= 16
			if chunk := uint16(data); chunk != 0xffff {
				o.uint32(in.MOVK.RdI16Hw(r, uint32(chunk), i, wa.I64)) // Keep surrounding bits.
			}
		}
	}

	o.copy(text.Extend(o.size()))
}

func moveUintImm32(o *output, r reg.R, data uint32) {
	switch {
	case data == 0:
		o.uint32(in.MOVZ.RdI16Hw(r, 0, 0, wa.I64))

	default:
		insn := in.MOVZ // First chunk clears surroundings.

		if chunk := data & 0xffff; chunk != 0 {
			o.uint32(insn.RdI16Hw(r, chunk, 0, wa.I64))
			insn = in.MOVK // Secondary chunks keep surroundings.
		}

		if chunk := data >> 16; chunk != 0 {
			o.uint32(insn.RdI16Hw(r, chunk, 1, wa.I64))
		}
	}
}

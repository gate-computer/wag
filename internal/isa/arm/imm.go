// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64
// +build arm64 wagarm64
// +build !wagamd64

package arm

import (
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/isa/arm/in"
	"gate.computer/wag/wa"
)

func (o *outbuf) moveIntImm(r reg.R, val int64) {
	data := uint64(val)

	switch {
	case val == 0:
		o.insn(in.MOVZ.RdI16Hw(r, 0, 0, wa.Size64))

	case val > 0:
		insn := in.MOVZ // First chunk clears surroundings.

		for i := uint32(0); i < 4; i++ {
			if chunk := in.Uint16(data); chunk != 0 {
				o.insn(insn.RdI16Hw(r, chunk, i, wa.Size64))
				insn = in.MOVK // Secondary chunks keep surroundings.
			}
			data >>= 16
		}

	case val == -1:
		o.insn(in.MOVN.RdI16Hw(r, 0, 0, wa.Size64))

	case val < -1:
		var i uint32

		for i = 0; i < 4; i++ {
			if chunk := uint16(data); chunk != 0xffff {
				o.insn(in.MOVN.RdI16Hw(r, uint32(^chunk), i, wa.Size64)) // Set surrounding bits.
				break
			}
			data >>= 16
		}

		for i++; i < 4; i++ {
			data >>= 16
			if chunk := uint16(data); chunk != 0xffff {
				o.insn(in.MOVK.RdI16Hw(r, uint32(chunk), i, wa.Size64)) // Keep surrounding bits.
			}
		}
	}
}

func (o *outbuf) moveUintImm32(r reg.R, data uint32) {
	switch {
	case data == 0:
		o.insn(in.MOVZ.RdI16Hw(r, 0, 0, wa.Size64))

	default:
		insn := in.MOVZ // First chunk clears surroundings.

		if chunk := data & 0xffff; chunk != 0 {
			o.insn(insn.RdI16Hw(r, chunk, 0, wa.Size64))
			insn = in.MOVK // Secondary chunks keep surroundings.
		}

		if chunk := data >> 16; chunk != 0 {
			o.insn(insn.RdI16Hw(r, chunk, 1, wa.Size64))
		}
	}
}

// moveImm80 moves 0x80000000 or 0x8000000000000000 depending on size.
func (o *outbuf) moveImm0x80(r reg.R, t wa.Size) {
	hw := uint32(t)>>2 | 1 // 1 or 3
	o.insn(in.MOVZ.RdI16Hw(r, 0x8000, hw, wa.Size64))
}

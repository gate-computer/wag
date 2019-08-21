// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/internal/isa/prop"
	"github.com/tsavola/wag/wa"
)

func (MacroAssembler) Convert(f *gen.Func, props uint16, resultType wa.Type, source operand.O) (result operand.O) {
	switch uint8(props) {
	case prop.ConvertExtend:
		op := in.Bitfield(props >> 8)
		r, _ := allocResultReg(f, source)
		f.Text.PutUint32(op.Opcode().RdRnI6sI6r(r, r, 31, 0, wa.I64))
		return operand.Reg(resultType, r)

	default:
		return TODO(props, resultType, source).(operand.O)
	}
}

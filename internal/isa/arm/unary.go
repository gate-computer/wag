// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/internal/isa/prop"
	"github.com/tsavola/wag/wa"
)

func (MacroAssembler) Unary(f *gen.Func, props uint16, x operand.O) operand.O {
	switch props {
	case prop.IntEqz:
		r, _ := getScratchReg(f, x)
		f.Text.PutUint32(in.SUBSi.RdRnI12S2(RegDiscard, r, 0, 0, x.Type))
		f.Regs.Free(x.Type, r)
		return operand.Flags(condition.Eq)

	case prop.IntClz:
		r, _ := allocResultReg(f, x)
		f.Text.PutUint32(in.CLZ.RdRn(r, r, x.Type))
		return operand.Reg(x.Type, r)

	case prop.IntCtz:
		return clz(f, x)

	case prop.IntPopcnt:
		return popcnt(f, x)

	default:
		return TODO(props, x).(operand.O)
	}
}

func clz(f *gen.Func, x operand.O) operand.O {
	var o output

	r, _ := allocResultReg(f, x)

	o.uint32(in.RBIT.RdRn(r, r, x.Type))
	o.uint32(in.CLZ.RdRn(r, r, x.Type))
	o.copy(f.Text.Extend(o.size()))

	return operand.Reg(x.Type, r)
}

func popcnt(f *gen.Func, x operand.O) operand.O {
	var o output

	count := f.Regs.AllocResult(x.Type)
	pop, _ := getScratchReg(f, x)

	o.uint32(in.MOVZ.RdI16Hw(count, 0, 0, wa.I64))
	o.uint32(in.CBZ.RtI19(pop, 5, x.Type)) // Skip to end.

	// Loop:
	o.uint32(in.ADDi.RdRnI12S2(count, count, 1, 0, wa.I64))
	o.uint32(in.SUBi.RdRnI12S2(RegScratch2, pop, 1, 0, x.Type))
	o.uint32(in.ANDSs.RdRnI6RmS2(pop, pop, 0, RegScratch2, 0, x.Type))
	o.uint32(in.Bc.CondI19(in.NE, in.Int19(-3))) // Loop.

	o.copy(f.Text.Extend(o.size()))

	f.Regs.Free(x.Type, pop)
	return operand.Reg(x.Type, count)
}

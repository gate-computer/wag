// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64

package arm64

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/isa/arm64/in"
	"gate.computer/wag/internal/isa/prop"
	"gate.computer/wag/wa"
)

func (MacroAssembler) Unary(f *gen.Func, props uint64, x operand.O) operand.O {
	var o outbuf

	switch props & prop.MaskUnary {
	case prop.UnaryIntEqz:
		r := o.getScratchReg(f, x)
		o.insn(in.SUBSi.RdRnI12S2(RegDiscard, r, 0, 0, x.Size()))
		o.copy(f.Text.Extend(o.size))

		f.Regs.Free(x.Type, r)
		return operand.Flags(condition.Eq)

	case prop.UnaryIntClz:
		r := o.allocResultReg(f, x)
		o.insn(in.CLZ.RdRn(r, r, x.Size()))
		o.copy(f.Text.Extend(o.size))

		return operand.Reg(x.Type, r)

	case prop.UnaryIntCtz:
		r := o.allocResultReg(f, x)
		o.insn(in.RBIT.RdRn(r, r, x.Size()))
		o.insn(in.CLZ.RdRn(r, r, x.Size()))
		o.copy(f.Text.Extend(o.size))

		return operand.Reg(x.Type, r)

	case prop.UnaryIntPopcnt:
		count := f.Regs.AllocResult(x.Type)
		pop := o.getScratchReg(f, x)

		o.insn(in.MOVZ.RdI16Hw(count, 0, 0, wa.Size64))
		o.insn(in.CBZ.RtI19(pop, 5, x.Size())) // Skip to end.

		// Loop:
		o.insn(in.ADDi.RdRnI12S2(count, count, 1, 0, wa.Size64))
		o.insn(in.SUBi.RdRnI12S2(RegScratch2, pop, 1, 0, x.Size()))
		o.insn(in.ANDSs.RdRnI6RmS2(pop, pop, 0, RegScratch2, 0, x.Size()))
		o.insn(in.Bc.CondI19(in.NE, in.Int19(-3))) // Loop.
		o.copy(f.Text.Extend(o.size))

		f.Regs.Free(x.Type, pop)
		return operand.Reg(x.Type, count)

	case prop.UnaryFloat:
		return convertFloat(f, props, x.Type, x)
	}

	panic(props)
}

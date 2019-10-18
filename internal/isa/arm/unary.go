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
	return unaryOps[props&prop.MaskUnary](f, props, x)
}

var unaryOps = [prop.MaskUnary + 1]func(*gen.Func, uint16, operand.O) operand.O{
	prop.UnaryIntEqz:    unaryIntEqz,
	prop.UnaryIntClz:    unaryIntClz,
	prop.UnaryIntCtz:    unaryIntCtz,
	prop.UnaryIntPopcnt: unaryIntPopcnt,
	prop.UnaryFloat:     unaryFloat,
}

func unaryIntEqz(f *gen.Func, _ uint16, x operand.O) operand.O {
	var o outbuf

	r := o.getScratchReg(f, x)
	o.insn(in.SUBSi.RdRnI12S2(RegDiscard, r, 0, 0, x.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(x.Type, r)
	return operand.Flags(condition.Eq)
}

func unaryIntClz(f *gen.Func, _ uint16, x operand.O) operand.O {
	var o outbuf

	r := o.allocResultReg(f, x)
	o.insn(in.CLZ.RdRn(r, r, x.Size()))
	o.copy(f.Text.Extend(o.size))

	return operand.Reg(x.Type, r)
}

func unaryIntCtz(f *gen.Func, _ uint16, x operand.O) operand.O {
	var o outbuf

	r := o.allocResultReg(f, x)
	o.insn(in.RBIT.RdRn(r, r, x.Size()))
	o.insn(in.CLZ.RdRn(r, r, x.Size()))
	o.copy(f.Text.Extend(o.size))

	return operand.Reg(x.Type, r)
}

func unaryIntPopcnt(f *gen.Func, _ uint16, x operand.O) operand.O {
	var o outbuf

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
}

func unaryFloat(f *gen.Func, props uint16, x operand.O) operand.O {
	return convertFloat(f, props, x.Type, x)
}

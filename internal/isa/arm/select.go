// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/isa/arm/in"
	"gate.computer/wag/wa"
)

func (MacroAssembler) Select(f *gen.Func, a, b, condOperand operand.O) operand.O {
	var o outbuf

	cond := condOperand.FlagsCond() // Default case (value unspecified until storage checked).

	switch condOperand.Storage {
	case storage.Stack:
		o.insn(in.PopReg(RegScratch, wa.I32))
		f.StackValueConsumed()
		o.insn(in.SUBSi.RdRnI12S2(RegDiscard, RegScratch, 0, 0, wa.Size32))
		cond = condition.Ne

	case storage.Imm:
		o.moveUintImm32(RegScratch, uint32(condOperand.ImmValue()))
		condOperand = operand.Reg(wa.I32, RegScratch)
		fallthrough

	case storage.Reg:
		r := condOperand.Reg()
		o.insn(in.SUBSi.RdRnI12S2(RegDiscard, r, 0, 0, wa.Size32))
		f.Regs.Free(wa.I32, r)
		cond = condition.Ne
	}

	bReg := o.allocResultReg(f, b)
	aReg := o.getScratchReg(f, a)

	if a.Type.Category() == wa.Int {
		o.selectInt(aReg, bReg, cond, a.Size())
	} else {
		o.selectFloat(aReg, bReg, cond, a.Size())
	}
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(a.Type, aReg)
	return operand.Reg(a.Type, bReg)
}

func (o *outbuf) selectInt(aReg, bReg reg.R, cond condition.C, t wa.Size) {
	o.insn(in.CSEL.RdRnCondRm(bReg, aReg, conditions[cond], bReg, t))
}

func (o *outbuf) selectFloat(aReg, bReg reg.R, cond condition.C, t wa.Size) {
	switch cond {
	case condition.OrderedAndEq:
		o.insn(in.Bc.CondI19(in.VS, 2)) // Skip FCSEL if unordered.

	case condition.UnorderedOrEq:
		// If unordered, copy aReg to bReg so that the second FCSEL will
		// select between identical values.
		o.insn(in.FCSEL.RdRnCondRm(bReg, aReg, in.VS, bReg, t))
	}

	o.insn(in.FCSEL.RdRnCondRm(bReg, aReg, conditions[cond], bReg, t))
}

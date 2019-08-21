// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/wa"
)

func (MacroAssembler) Select(f *gen.Func, a, b, condOperand operand.O) operand.O {
	var o output
	var cond condition.C

	switch condOperand.Storage {
	case storage.Stack:
		o.uint32(in.PopIntReg(RegScratch))
		f.StackValueConsumed()
		o.uint32(in.SUBSi.RdRnI12S2(RegDiscard, RegScratch, 0, 0, wa.I32))
		cond = condition.Ne

	case storage.Imm:
		moveUintImm32(&o, RegScratch, uint32(condOperand.ImmValue()))
		condOperand = operand.Reg(wa.I32, RegScratch)
		fallthrough

	case storage.Reg:
		r := condOperand.Reg()
		o.uint32(in.SUBSi.RdRnI12S2(RegDiscard, r, 0, 0, wa.I32))
		f.Regs.Free(wa.I32, r)
		cond = condition.Ne

	case storage.Flags:
		cond = condOperand.FlagsCond()
	}

	targetReg, _ := allocResultReg(f, b)

	switch a.Type.Category() {
	case wa.Int:
		aReg, _ := getScratchReg(f, a)
		o.uint32(in.CSEL.RdRnCondRm(targetReg, aReg, conditions[cond], targetReg, a.Type))
		f.Regs.Free(a.Type, aReg)

	default:
		TODO(cond, a, targetReg)
	}

	o.copy(f.Text.Extend(o.size()))

	return operand.Reg(a.Type, targetReg)
}

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || wagamd64) && !wagarm64

package amd64

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/isa/amd64/in"
	"gate.computer/wag/wa"
)

func (MacroAssembler) Select(f *gen.Func, a, b, condOperand operand.O) operand.O {
	var cond condition.C

	switch condOperand.Storage {
	case storage.Stack:
		in.POPo.RegScratch(&f.Text)
		f.StackValueConsumed()
		in.TEST.RegReg(&f.Text, wa.I32, RegScratch, RegScratch)
		cond = condition.Ne

	case storage.Imm:
		asm.Move(f, RegScratch, condOperand)
		condOperand = operand.Reg(wa.I32, RegScratch)
		fallthrough

	case storage.Reg:
		r := condOperand.Reg()
		in.TEST.RegReg(&f.Text, wa.I32, r, r)
		f.Regs.Free(wa.I32, r)
		cond = condition.Ne

	case storage.Flags:
		cond = condOperand.FlagsCond()
	}

	targetReg, _ := allocResultReg(f, b)

	switch a.Type.Category() {
	case wa.Int:
		move := conditionInsns[cond].CmovccOpcode()

		aReg, _ := getScratchReg(f, a)
		move.RegReg(&f.Text, a.Type, targetReg, aReg)
		f.Regs.Free(a.Type, aReg)

	case wa.Float:
		movJumps := make([]int32, 0, 1)
		endJumps := make([]int32, 0, 2)

		condInv := condition.Inverted[cond]
		jumpInv := conditionInsns[condInv].JccOpcodeCb()

		switch {
		case cond >= condition.MinUnorderedOrCondition:
			movJumps = append(movJumps, in.JPcb.Stub8(&f.Text)) // Take a if unordered, else
			endJumps = append(endJumps, jumpInv.Stub8(&f.Text)) // keep b if not cond, else

		case cond >= condition.MinOrderedAndCondition:
			endJumps = append(endJumps, in.JPcb.Stub8(&f.Text)) // Keep b if unordered, else
			endJumps = append(endJumps, jumpInv.Stub8(&f.Text)) // keep b if cond, else

		default:
			endJumps = append(endJumps, jumpInv.Stub8(&f.Text)) // Keep b if not cond, else
		}

		linker.UpdateNearBranches(f.Text.Bytes(), movJumps)

		asm.Move(f, targetReg, a) // take a.

		linker.UpdateNearBranches(f.Text.Bytes(), endJumps)
	}

	return operand.Reg(a.Type, targetReg)
}

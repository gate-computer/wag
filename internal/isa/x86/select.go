// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/x86/in"
	"github.com/tsavola/wag/wa"
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
		insns := conditionInsns[cond]

		switch a.Storage {
		default: // stack, immediate, or register
			aReg, _ := getScratchReg(f, a)
			insns.CmovccOpcode().RegReg(&f.Text, a.Type, targetReg, aReg)
			f.Regs.Free(a.Type, aReg)
		}

	case wa.Float:
		var moveItJumps []int32
		var endJumps []int32

		cond = condition.Inverted[cond]
		notCondJump := conditionInsns[cond].JccOpcodeCb()

		switch {
		case cond >= condition.MinUnorderedOrCondition:
			in.JPcb.Stub8(&f.Text) // move it if unordered
			moveItJumps = append(moveItJumps, f.Text.Addr)

			notCondJump.Stub8(&f.Text) // break if not cond
			endJumps = append(endJumps, f.Text.Addr)

		case cond >= condition.MinOrderedAndCondition:
			in.JPcb.Stub8(&f.Text) // break if unordered
			endJumps = append(endJumps, f.Text.Addr)

			notCondJump.Stub8(&f.Text) // break if not cond
			endJumps = append(endJumps, f.Text.Addr)

		default:
			notCondJump.Stub8(&f.Text) // break if not cond
			endJumps = append(endJumps, f.Text.Addr)
		}

		linker.UpdateNearBranches(f.Text.Bytes(), moveItJumps)

		asm.Move(f, targetReg, a)

		linker.UpdateNearBranches(f.Text.Bytes(), endJumps)
	}

	return operand.Reg(a.Type, targetReg)
}

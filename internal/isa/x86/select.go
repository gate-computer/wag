// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/x86/in"
	"github.com/tsavola/wag/wa"
)

// Select may allocate registers, use RegResult and update condition flags.
// The cond operand may be the condition flags.
func (MacroAssembler) Select(f *gen.Func, a, b, condOperand operand.O) operand.O {
	var cond condition.C

	switch condOperand.Storage {
	case storage.Stack:
		in.POPo.RegScratch(&f.Text)
		f.StackValueConsumed()
		in.TEST.RegReg(&f.Text, wa.I32, RegScratch, RegScratch)
		cond = condition.Ne

	case storage.Imm:
		if condOperand.ImmValue() != 0 {
			dropStableValue(f, b)
			return a
		} else {
			dropStableValue(f, a)
			return b
		}

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
		var moveIt link.L
		var end link.L

		cond = condition.Inverted[cond]
		notCondJump := conditionInsns[cond].JccOpcodeCb()

		switch {
		case cond >= condition.MinUnorderedOrCondition:
			in.JPcb.Stub8(&f.Text) // move it if unordered
			moveIt.AddSite(f.Text.Addr)

			notCondJump.Stub8(&f.Text) // break if not cond
			end.AddSite(f.Text.Addr)

		case cond >= condition.MinOrderedAndCondition:
			in.JPcb.Stub8(&f.Text) // break if unordered
			end.AddSite(f.Text.Addr)

			notCondJump.Stub8(&f.Text) // break if not cond
			end.AddSite(f.Text.Addr)

		default:
			notCondJump.Stub8(&f.Text) // break if not cond
			end.AddSite(f.Text.Addr)
		}

		moveIt.Addr = f.Text.Addr
		isa.UpdateNearBranches(f.Text.Bytes(), &moveIt)

		asm.Move(f, targetReg, a)

		end.Addr = f.Text.Addr
		isa.UpdateNearBranches(f.Text.Bytes(), &end)
	}

	return operand.Reg(a.Type, targetReg)
}

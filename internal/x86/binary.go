// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/opers"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
	"github.com/tsavola/wag/types"
)

func (mach X86) BinaryOp(code gen.RegCoder, oper uint16, a, b values.Operand) values.Operand {
	switch {
	case (oper & opers.BinaryShift) != 0:
		return mach.binaryShiftOp(code, uint8(oper), a, b)

	case (oper & opers.BinaryDivmul) != 0:
		return mach.binaryDivmulOp(code, uint8(oper), a, b)

	case (oper & (opers.BinaryCompare | opers.BinaryFloat)) == opers.BinaryCompare:
		return mach.binaryIntCompareOp(code, uint8(oper), a, b)

	case (oper & opers.BinaryFloat) == 0:
		return mach.binaryIntOp(code, uint8(oper), a, b)

	case (oper & opers.BinaryMinmax) != 0:
		return mach.binaryFloatMinmaxOp(code, uint8(oper), a, b)

	case (oper & opers.BinaryCompare) != 0:
		return mach.binaryFloatCompareOp(code, uint8(oper), a, b)

	default:
		return mach.binaryFloatOp(code, uint8(oper), a, b)
	}
}

var binaryIntInsns = []binaryInsn{
	opers.IndexIntAdd: Add,
	opers.IndexIntSub: Sub,
	opers.IndexIntAnd: And,
	opers.IndexIntOr:  Or,
	opers.IndexIntXor: Xor,
}

func (mach X86) binaryIntOp(code gen.RegCoder, index uint8, a, b values.Operand) (result values.Operand) {
	if a.Storage == values.Imm && a.ImmValue() == 0 && index == opers.IndexIntSub {
		targetReg, _ := mach.opMaybeResultReg(code, b, false)
		Neg.opReg(code, a.Type, targetReg)
		return values.TempRegOperand(a.Type, targetReg, true)
	}

	switch b.Storage {
	case values.Imm:
		value := b.ImmValue()

		switch {
		case index == opers.IndexIntAdd && value == 1: // assume that we won't see sub -1
			reg, _ := mach.opMaybeResultReg(code, a, false)
			Inc.opReg(code, a.Type, reg)
			return values.TempRegOperand(a.Type, reg, true)

		case index == opers.IndexIntSub && value == 1: // assume that we won't see add -1
			reg, _ := mach.opMaybeResultReg(code, a, false)
			Dec.opReg(code, a.Type, reg)
			return values.TempRegOperand(a.Type, reg, true)

		case value < -0x80000000 || value >= 0x80000000:
			// TODO: merge this with the next outer case
			sourceReg, _, own := mach.opBorrowMaybeScratchReg(code, b, true)
			b = values.RegOperand(own, a.Type, sourceReg)
		}

	case values.Stack, values.ConditionFlags:
		sourceReg, _, own := mach.opBorrowMaybeScratchReg(code, b, true)
		b = values.RegOperand(own, a.Type, sourceReg)
	}

	insn := binaryIntInsns[index]
	targetReg, _ := mach.opMaybeResultReg(code, a, false)
	result = values.TempRegOperand(a.Type, targetReg, true)

	if b.Storage == values.VarMem {
		insn.opFromStack(code, a.Type, targetReg, b.VarMemOffset())
		return
	}

	var sourceReg regs.R

	if b.Storage.IsReg() {
		sourceReg = b.Reg()
	} else {
		if b.Storage == values.Imm {
			if value := b.ImmValue(); value >= -0x80000000 && value < 0x80000000 {
				insn.opImm(code, a.Type, targetReg, int32(b.ImmValue()))
				return
			}
		}
		sourceReg = regScratch
		mach.OpMove(code, sourceReg, b, false)
	}

	insn.opFromReg(code, a.Type, targetReg, sourceReg)
	code.Consumed(b)
	return
}

func (mach X86) binaryIntCompareOp(code gen.RegCoder, cond uint8, a, b values.Operand) (result values.Operand) {
	result = values.ConditionFlagsOperand(values.Condition(cond))

	targetReg, _, own := mach.opBorrowMaybeResultReg(code, a, false)
	if own {
		defer code.FreeReg(a.Type, targetReg)
	}

	if b.Storage == values.VarMem {
		Cmp.opFromStack(code, a.Type, targetReg, b.VarMemOffset())
		return
	}

	var sourceReg regs.R

	if b.Storage.IsReg() {
		sourceReg = b.Reg()
	} else {
		if b.Storage == values.Imm {
			if value := b.ImmValue(); value >= -0x80000000 && value < 0x80000000 {
				Cmp.opImm(code, a.Type, targetReg, int32(value))
				return
			}
		}
		sourceReg = regScratch
		mach.OpMove(code, sourceReg, b, false)
	}

	Cmp.opFromReg(code, a.Type, targetReg, sourceReg)
	code.Consumed(b)
	return
}

var binaryDivmulInsns = []struct {
	insnRexM
	shiftImm shiftImmInsn
}{
	opers.IndexDivmulDivS: {Idiv, NoShiftImmInsn},
	opers.IndexDivmulDivU: {Div, ShrImm},
	opers.IndexDivmulRemS: {Idiv, NoShiftImmInsn},
	opers.IndexDivmulRemU: {Div, NoShiftImmInsn}, // TODO: use AND for 2^n divisors
	opers.IndexDivmulMul:  {Mul, ShlImm},
}

func (mach X86) binaryDivmulOp(code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	insn := binaryDivmulInsns[index]
	t := a.Type

	if b.Storage == values.Imm {
		value := b.ImmValue()

		switch {
		case insn.shiftImm.defined() && value > 0 && isPowerOfTwo(uint64(value)):
			reg, _ := mach.opMaybeResultReg(code, a, false)
			insn.shiftImm.op(code, t, reg, log2(uint64(value)))
			return values.TempRegOperand(t, reg, true)
		}
	}

	division := (index & opers.DivmulMul) == 0
	checkZero := true
	checkOverflow := true

	if b.Storage.IsReg() {
		if b.Reg() == regResult {
			newReg := regScratch

			if division {
				var ok bool

				// can't use scratch reg as divisor since it contains the dividend high bits
				newReg, ok = code.TryAllocReg(t)
				if !ok {
					// borrow a register which we don't need in this function
					MovMMX.opFromReg(code, types.I64, regScratchMMX, regTextBase)
					defer MovMMX.opToReg(code, types.I64, regTextBase, regScratchMMX)

					newReg = regTextBase
				}
			}

			Mov.opFromReg(code, t, newReg, regResult)
			b = values.RegOperand(true, t, newReg)
		}
	} else {
		if division && b.Storage == values.Imm {
			value := b.ImmValue()
			if value != 0 {
				checkZero = false
			}
			if value != -1 {
				checkOverflow = false
			}
		}

		reg, ok := code.TryAllocReg(t)
		if !ok {
			// borrow a register which we don't need in this function
			MovMMX.opFromReg(code, types.I64, regScratchMMX, regTextBase)
			defer MovMMX.opToReg(code, types.I64, regTextBase, regScratchMMX)

			reg = regTextBase
		}

		mach.OpMove(code, reg, b, true)
		b = values.RegOperand(true, t, reg)
	}

	mach.OpMove(code, regResult, a, false)

	remainder := (index & opers.DivmulRem) != 0

	var doNot links.L

	if division {
		if checkZero {
			mach.opCheckDivideByZero(code, t, b.Reg())
		}

		if a.Storage == values.Imm {
			value := a.ImmValue()
			if t.Size() == types.Size32 {
				if value != -0x80000000 {
					checkOverflow = false
				}
			} else {
				if value != -0x8000000000000000 {
					checkOverflow = false
				}
			}
		}

		signed := (index & opers.DivmulSign) != 0

		if signed && checkOverflow {
			var do links.L

			if remainder {
				Xor.opFromReg(code, types.I32, regScratch, regScratch) // moved to result at the end

				Cmp.opImm(code, t, b.Reg(), -1)
				Je.rel8.opStub(code)
				doNot.AddSite(code.Len())
			} else {
				switch t.Size() {
				case types.Size32:
					Cmp.opImm(code, t, regResult, -0x80000000)

				case types.Size64:
					MovImm64.op(code, t, regScratch, -0x8000000000000000)
					Cmp.opFromReg(code, t, regResult, regScratch)

				default:
					panic(a)
				}

				Jne.rel8.opStub(code)
				do.AddSite(code.Len())

				Cmp.opImm(code, t, b.Reg(), -1)
				Jne.rel8.opStub(code)
				do.AddSite(code.Len())

				code.OpTrapCall(traps.IntegerOverflow)
			}

			do.Addr = code.Len()
			mach.updateBranches8(code, &do)
		}

		if signed {
			// sign-extend dividend low bits to high bits
			CdqCqo.op(code, t)
		} else {
			// zero-extend dividend high bits
			Xor.opFromReg(code, types.I32, regScratch, regScratch)
		}
	}

	insn.opReg(code, t, b.Reg())
	code.Consumed(b)

	doNot.Addr = code.Len()
	mach.updateBranches8(code, &doNot)

	if remainder {
		Mov.opFromReg(code, t, regResult, regScratch)
	}

	return values.TempRegOperand(t, regResult, true)
}

func (mach X86) opCheckDivideByZero(code gen.RegCoder, t types.T, reg regs.R) {
	var end links.L

	Test.opFromReg(code, t, reg, reg)
	Jne.rel8.opStub(code)
	end.AddSite(code.Len())

	code.OpTrapCall(traps.IntegerDivideByZero)

	end.Addr = code.Len()
	mach.updateBranches8(code, &end)
}

var binaryShiftInsns = []struct {
	insnRexM
	imm shiftImmInsn
}{
	opers.IndexShiftRotl: {Rol, RolImm},
	opers.IndexShiftRotr: {Ror, RorImm},
	opers.IndexShiftShl:  {Shl, ShlImm},
	opers.IndexShiftShrS: {Sar, SarImm},
	opers.IndexShiftShrU: {Shr, ShrImm},
}

func (mach X86) binaryShiftOp(code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	insn := binaryShiftInsns[index]

	var targetReg regs.R

	switch b.Storage {
	case values.Imm:
		targetReg, _ = mach.opMaybeResultReg(code, a, true)
		insn.imm.op(code, b.Type, targetReg, uint8(b.ImmValue()))

	default:
		if b.Storage.IsReg() && b.Reg() == regShiftCount {
			targetReg, _ = mach.opMaybeResultReg(code, a, false)
			defer code.Discard(b)
		} else {
			if code.RegAllocated(types.I32, regShiftCount) {
				targetReg, _ = mach.opMaybeResultReg(code, a, true)
				if targetReg == regShiftCount {
					Mov.opFromReg(code, a.Type, regResult, regShiftCount)
					targetReg = regResult

					defer code.FreeReg(types.I32, regShiftCount)
				} else {
					// unknown operand in regShiftCount
					Mov.opFromReg(code, types.I64, regScratch, regShiftCount)
					defer Mov.opFromReg(code, types.I64, regShiftCount, regScratch)
				}
			} else {
				code.AllocSpecificReg(types.I32, regShiftCount)
				defer code.FreeReg(types.I32, regShiftCount)

				targetReg, _ = mach.opMaybeResultReg(code, a, true)
			}

			b.Type = types.I32 // TODO: 8-bit mov
			mach.OpMove(code, regShiftCount, b, false)
		}

		insn.opReg(code, a.Type, targetReg)
	}

	return values.TempRegOperand(a.Type, targetReg, true)
}

var binaryFloatInsns = []insnPrefix{
	opers.IndexFloatAdd: AddsSSE,
	opers.IndexFloatSub: SubsSSE,
	opers.IndexFloatDiv: DivsSSE,
	opers.IndexFloatMul: MulsSSE,
}

// TODO: support memory source operands

func (mach X86) binaryFloatOp(code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	targetReg, _ := mach.opMaybeResultReg(code, a, false)

	sourceReg, _, own := mach.opBorrowMaybeScratchReg(code, b, false)
	if own {
		defer code.FreeReg(b.Type, sourceReg)
	}

	binaryFloatInsns[index].opFromReg(code, a.Type, targetReg, sourceReg)
	return values.TempRegOperand(a.Type, targetReg, false)
}

type binaryFloatMinmax struct {
	commonInsn insnPrefix
	zeroInsn   insnPrefix
}

var binaryFloatMinmaxInsns = []binaryFloatMinmax{
	opers.IndexMinmaxMin: {MinsSSE, OrpSSE},
	opers.IndexMinmaxMax: {MaxsSSE, AndpSSE},
}

func (mach X86) binaryFloatMinmaxOp(code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	targetReg, _ := mach.opMaybeResultReg(code, a, false)

	sourceReg, _, own := mach.opBorrowMaybeScratchReg(code, b, false)
	if own {
		defer code.FreeReg(b.Type, sourceReg)
	}

	var common links.L
	var end links.L

	UcomisSSE.opFromReg(code, a.Type, targetReg, sourceReg)
	Jne.rel8.opStub(code)
	common.AddSite(code.Len())

	binaryFloatMinmaxInsns[index].zeroInsn.opFromReg(code, a.Type, targetReg, sourceReg)
	JmpRel.rel8.opStub(code)
	end.AddSite(code.Len())

	common.Addr = code.Len()
	mach.updateBranches8(code, &common)

	binaryFloatMinmaxInsns[index].commonInsn.opFromReg(code, a.Type, targetReg, sourceReg)

	end.Addr = code.Len()
	mach.updateBranches8(code, &end)

	return values.TempRegOperand(a.Type, targetReg, false)
}

func (mach X86) binaryFloatCompareOp(code gen.RegCoder, cond uint8, a, b values.Operand) values.Operand {
	aReg, _, own := mach.opBorrowMaybeResultReg(code, a, true)
	if own {
		defer code.FreeReg(a.Type, aReg)
	}

	bReg, _, own := mach.opBorrowMaybeScratchReg(code, b, false)
	if own {
		defer code.FreeReg(b.Type, bReg)
	}

	UcomisSSE.opFromReg(code, a.Type, aReg, bReg)
	return values.ConditionFlagsOperand(values.Condition(cond))
}

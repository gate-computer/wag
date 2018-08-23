// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/opers"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/trap"
)

func (ISA) BinaryOp(code gen.RegCoder, oper uint16, a, b values.Operand) values.Operand {
	if (oper & opers.BinaryFloat) == 0 {
		switch {
		case (oper & opers.BinaryCompare) != 0:
			return binaryIntCompareOp(code, uint8(oper), a, b)

		case (oper & opers.BinaryIntShift) != 0:
			return binaryIntShiftOp(code, uint8(oper), a, b)

		case (oper & opers.BinaryIntDivmul) != 0:
			return binaryIntDivmulOp(code, uint8(oper), a, b)

		default:
			return commonBinaryIntOp(code, uint8(oper), a, b)
		}
	} else {
		switch {
		case (oper & opers.BinaryCompare) != 0:
			return binaryFloatCompareOp(code, uint8(oper), a, b)

		case (oper & opers.BinaryFloatMinmax) != 0:
			return binaryFloatMinmaxOp(code, uint8(oper), a, b)

		case (oper & opers.BinaryFloatCopysign) != 0:
			return binaryFloatCopysignOp(code, a, b)

		default:
			return commonBinaryFloatOp(code, uint8(oper), a, b)
		}
	}
}

var commonBinaryIntInsns = []binaryInsn{
	opers.IndexIntAdd: add,
	opers.IndexIntSub: sub,
	opers.IndexIntAnd: and,
	opers.IndexIntOr:  or,
	opers.IndexIntXor: xor,
}

func commonBinaryIntOp(code gen.RegCoder, index uint8, a, b values.Operand) (result values.Operand) {
	if index == opers.IndexIntSub && a.Storage == values.Imm && a.ImmValue() == 0 {
		return inplaceIntOp(code, neg, b)
	}

	switch b.Storage {
	case values.Imm:
		switch {
		case b.ImmValue() == 1:
			switch index {
			case opers.IndexIntAdd:
				return inplaceIntOp(code, inc, a)

			case opers.IndexIntSub:
				return inplaceIntOp(code, dec, a)
			}

		case b.ImmValue() < -0x80000000 || b.ImmValue() >= 0x80000000:
			b = opBorrowMaybeScratchRegOperand(code, b, true)
		}

	case values.VarReference, values.Stack, values.ConditionFlags:
		b = opBorrowMaybeScratchRegOperand(code, b, true)
	}

	insn := commonBinaryIntInsns[index]

	targetReg, _ := opMaybeResultReg(code, a, false)
	result = values.TempRegOperand(a.Type, targetReg, true)

	switch {
	case b.Storage.IsReg():
		insn.opFromReg(code, a.Type, targetReg, b.Reg())
		code.Consumed(b)
		return

	case b.Storage == values.VarMem:
		insn.opFromStack(code, a.Type, targetReg, b.VarMemOffset())
		return

	case b.Storage == values.Imm: // large values moved to registers earlier
		insn.opImm(code, a.Type, targetReg, int32(b.ImmValue()))
		return

	default:
		panic("unexpected storage type of second operand of common binary int op")
	}
}

func binaryIntCompareOp(code gen.RegCoder, cond uint8, a, b values.Operand) (result values.Operand) {
	targetReg, _, own := opBorrowMaybeResultReg(code, a, false)
	if own {
		defer code.FreeReg(a.Type, targetReg)
	}

	result = values.ConditionFlagsOperand(values.Condition(cond))

	switch {
	case b.Storage.IsReg():
		cmp.opFromReg(code, a.Type, targetReg, b.Reg())
		code.Consumed(b)
		return

	case b.Storage == values.VarMem:
		cmp.opFromStack(code, a.Type, targetReg, b.VarMemOffset())
		return

	case b.Storage == values.Imm && b.ImmValue() >= -0x80000000 && b.ImmValue() < 0x80000000:
		cmp.opImm(code, a.Type, targetReg, int32(b.ImmValue()))
		return

	default:
		opMove(code, RegScratch, b, false)
		cmp.opFromReg(code, a.Type, targetReg, RegScratch)
		return
	}
}

var binaryDivmulInsns = []struct {
	insnRexM
	shiftImm shiftImmInsn
}{
	opers.IndexDivmulDivS: {idiv, noShiftImmInsn},
	opers.IndexDivmulDivU: {div, shrImm},
	opers.IndexDivmulRemS: {idiv, noShiftImmInsn},
	opers.IndexDivmulRemU: {div, noShiftImmInsn}, // TODO: use AND for 2^n divisors
	opers.IndexDivmulMul:  {mul, shlImm},
}

func binaryIntDivmulOp(code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	insn := binaryDivmulInsns[index]
	t := a.Type

	if b.Storage == values.Imm {
		value := b.ImmValue()

		switch {
		case insn.shiftImm.defined() && value > 0 && isPowerOfTwo(uint64(value)):
			reg, _ := opMaybeResultReg(code, a, false)
			insn.shiftImm.op(code, t, reg, log2(uint64(value)))
			return values.TempRegOperand(t, reg, true)
		}
	}

	division := (index & opers.DivmulMul) == 0
	checkZero := true
	checkOverflow := true

	if b.Storage.IsReg() {
		if b.Reg() == RegResult {
			newReg := RegScratch

			if division {
				var ok bool

				// can't use scratch reg as divisor since it contains the dividend high bits
				newReg, ok = code.TryAllocReg(t)
				if !ok {
					// borrow a register which we don't need in this function
					movMMX.opFromReg(code, abi.I64, RegScratchMMX, RegTextBase)
					defer movMMX.opToReg(code, abi.I64, RegTextBase, RegScratchMMX)

					newReg = RegTextBase
				}
			}

			mov.opFromReg(code, t, newReg, RegResult)
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
			movMMX.opFromReg(code, abi.I64, RegScratchMMX, RegTextBase)
			defer movMMX.opToReg(code, abi.I64, RegTextBase, RegScratchMMX)

			reg = RegTextBase
		}

		opMove(code, reg, b, true)
		b = values.RegOperand(true, t, reg)
	}

	opMove(code, RegResult, a, false)

	remainder := (index & opers.DivmulRem) != 0

	var doNot links.L

	if division {
		if checkZero {
			opCheckDivideByZero(code, t, b.Reg())
		}

		if a.Storage == values.Imm {
			value := a.ImmValue()
			if t.Size() == abi.Size32 {
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
				xor.opFromReg(code, abi.I32, RegScratch, RegScratch) // moved to result at the end

				cmp.opImm(code, t, b.Reg(), -1)
				je.rel8.opStub(code)
				doNot.AddSite(code.Pos())
			} else {
				switch t.Size() {
				case abi.Size32:
					cmp.opImm(code, t, RegResult, -0x80000000)

				case abi.Size64:
					cmp.opFromAddr(code, t, RegResult, 0, NoIndex, code.RODataAddr()+gen.ROMask80Addr64)

				default:
					panic(a)
				}

				jne.rel8.opStub(code)
				do.AddSite(code.Pos())

				cmp.opImm(code, t, b.Reg(), -1)
				jne.rel8.opStub(code)
				do.AddSite(code.Pos())

				code.OpTrapCall(trap.IntegerOverflow)
			}

			do.Addr = code.Pos()
			updateLocalBranches(code, &do)
		}

		if signed {
			// sign-extend dividend low bits to high bits
			cdqCqo.op(code, t)
		} else {
			// zero-extend dividend high bits
			xor.opFromReg(code, abi.I32, RegScratch, RegScratch)
		}
	}

	insn.opReg(code, t, b.Reg())
	code.Consumed(b)

	doNot.Addr = code.Pos()
	updateLocalBranches(code, &doNot)

	if remainder {
		mov.opFromReg(code, t, RegResult, RegScratch)
	}

	return values.TempRegOperand(t, RegResult, true)
}

func opCheckDivideByZero(code gen.Coder, t abi.Type, reg regs.R) {
	var end links.L

	test.opFromReg(code, t, reg, reg)
	jne.rel8.opStub(code)
	end.AddSite(code.Pos())

	code.OpTrapCall(trap.IntegerDivideByZero)

	end.Addr = code.Pos()
	updateLocalBranches(code, &end)
}

var binaryShiftInsns = []struct {
	reg insnRexM
	imm shiftImmInsn
}{
	opers.IndexShiftRotl: {rol, rolImm},
	opers.IndexShiftRotr: {ror, rorImm},
	opers.IndexShiftShl:  {shl, shlImm},
	opers.IndexShiftShrS: {sar, sarImm},
	opers.IndexShiftShrU: {shr, shrImm},
}

func binaryIntShiftOp(code gen.RegCoder, index uint8, a, b values.Operand) (result values.Operand) {
	insn := binaryShiftInsns[index]

	switch {
	case b.Storage == values.Imm:
		reg, _ := opMaybeResultReg(code, a, true)
		insn.imm.op(code, b.Type, reg, uint8(b.ImmValue()))
		result = values.TempRegOperand(a.Type, reg, true)

	case b.Storage.IsReg() && b.Reg() == RegShiftCount:
		reg, _ := opMaybeResultReg(code, a, false)
		insn.reg.opReg(code, a.Type, reg)
		code.Discard(b)
		result = values.TempRegOperand(a.Type, reg, true)

	case code.RegAllocated(abi.I32, RegShiftCount):
		reg, _ := opMaybeResultReg(code, a, true)
		if reg == RegShiftCount {
			mov.opFromReg(code, a.Type, RegResult, RegShiftCount)
			result = subtleShiftOp(code, insn.reg, a.Type, RegResult, b)
			code.FreeReg(abi.I32, RegShiftCount)
		} else {
			// unknown operand in RegShiftCount
			mov.opFromReg(code, abi.I64, RegScratch, RegShiftCount) // save
			result = subtleShiftOp(code, insn.reg, a.Type, reg, b)
			mov.opFromReg(code, abi.I64, RegShiftCount, RegScratch) // restore
		}

	default:
		code.AllocSpecificReg(abi.I32, RegShiftCount)
		reg, _ := opMaybeResultReg(code, a, true)
		result = subtleShiftOp(code, insn.reg, a.Type, reg, b)
		code.FreeReg(abi.I32, RegShiftCount)
	}

	return
}

// subtleShiftOp trashes RegShiftCount.
func subtleShiftOp(code gen.Coder, insn insnRexM, t abi.Type, reg regs.R, count values.Operand) values.Operand {
	count.Type = abi.I32                      // TODO: 8-bit mov
	opMove(code, RegShiftCount, count, false) //
	insn.opReg(code, t, reg)
	return values.TempRegOperand(t, reg, true)
}

var commonBinaryFloatInsns = []insnPrefix{
	opers.IndexFloatAdd: addsSSE,
	opers.IndexFloatSub: subsSSE,
	opers.IndexFloatDiv: divsSSE,
	opers.IndexFloatMul: mulsSSE,
}

// TODO: support memory source operands

func commonBinaryFloatOp(code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	targetReg, _ := opMaybeResultReg(code, a, false)

	sourceReg, _, own := opBorrowMaybeScratchReg(code, b, false)
	if own {
		defer code.FreeReg(b.Type, sourceReg)
	}

	commonBinaryFloatInsns[index].opFromReg(code, a.Type, targetReg, sourceReg)
	return values.TempRegOperand(a.Type, targetReg, false)
}

var binaryFloatMinmaxInsns = []struct {
	commonInsn insnPrefix
	zeroInsn   insnPrefix
}{
	opers.IndexMinmaxMin: {minsSSE, orpSSE},
	opers.IndexMinmaxMax: {maxsSSE, andpSSE},
}

func binaryFloatMinmaxOp(code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	targetReg, _ := opMaybeResultReg(code, a, false)

	sourceReg, _, own := opBorrowMaybeScratchReg(code, b, false)
	if own {
		defer code.FreeReg(b.Type, sourceReg)
	}

	var common links.L
	var end links.L

	ucomisSSE.opFromReg(code, a.Type, targetReg, sourceReg)
	jne.rel8.opStub(code)
	common.AddSite(code.Pos())

	binaryFloatMinmaxInsns[index].zeroInsn.opFromReg(code, a.Type, targetReg, sourceReg)
	jmpRel.rel8.opStub(code)
	end.AddSite(code.Pos())

	common.Addr = code.Pos()
	updateLocalBranches(code, &common)

	binaryFloatMinmaxInsns[index].commonInsn.opFromReg(code, a.Type, targetReg, sourceReg)

	end.Addr = code.Pos()
	updateLocalBranches(code, &end)

	return values.TempRegOperand(a.Type, targetReg, false)
}

func binaryFloatCompareOp(code gen.RegCoder, cond uint8, a, b values.Operand) values.Operand {
	aReg, _, own := opBorrowMaybeResultReg(code, a, true)
	if own {
		defer code.FreeReg(a.Type, aReg)
	}

	bReg, _, own := opBorrowMaybeScratchReg(code, b, false)
	if own {
		defer code.FreeReg(b.Type, bReg)
	}

	ucomisSSE.opFromReg(code, a.Type, aReg, bReg)
	return values.ConditionFlagsOperand(values.Condition(cond))
}

func binaryFloatCopysignOp(code gen.RegCoder, a, b values.Operand) values.Operand {
	targetReg, _ := opMaybeResultReg(code, a, false)

	sourceReg, _, own := opBorrowMaybeScratchReg(code, b, false)
	if own {
		defer code.FreeReg(b.Type, sourceReg)
	}

	var done links.L

	signMaskAddr := gen.MaskAddr(code.RODataAddr(), gen.Mask80Base, a.Type)

	movSSE.opToReg(code, a.Type, RegScratch, sourceReg) // int <- float
	and.opFromAddr(code, a.Type, RegScratch, 0, NoIndex, signMaskAddr)
	movSSE.opToReg(code, a.Type, RegResult, targetReg) // int <- float
	and.opFromAddr(code, a.Type, RegResult, 0, NoIndex, signMaskAddr)
	cmp.opFromReg(code, a.Type, RegResult, RegScratch)
	je.rel8.opStub(code)
	done.AddSite(code.Pos())

	opNegFloatReg(code, a.Type, targetReg)

	done.Addr = code.Pos()
	updateLocalBranches(code, &done)

	return values.TempRegOperand(a.Type, targetReg, false)
}

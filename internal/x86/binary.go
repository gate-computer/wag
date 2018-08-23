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

func (ISA) BinaryOp(text gen.Buffer, code gen.RegCoder, oper uint16, a, b values.Operand) values.Operand {
	if (oper & opers.BinaryFloat) == 0 {
		switch {
		case (oper & opers.BinaryCompare) != 0:
			return binaryIntCompareOp(text, code, uint8(oper), a, b)

		case (oper & opers.BinaryIntShift) != 0:
			return binaryIntShiftOp(text, code, uint8(oper), a, b)

		case (oper & opers.BinaryIntDivmul) != 0:
			return binaryIntDivmulOp(text, code, uint8(oper), a, b)

		default:
			return commonBinaryIntOp(text, code, uint8(oper), a, b)
		}
	} else {
		switch {
		case (oper & opers.BinaryCompare) != 0:
			return binaryFloatCompareOp(text, code, uint8(oper), a, b)

		case (oper & opers.BinaryFloatMinmax) != 0:
			return binaryFloatMinmaxOp(text, code, uint8(oper), a, b)

		case (oper & opers.BinaryFloatCopysign) != 0:
			return binaryFloatCopysignOp(text, code, a, b)

		default:
			return commonBinaryFloatOp(text, code, uint8(oper), a, b)
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

func commonBinaryIntOp(text gen.Buffer, code gen.RegCoder, index uint8, a, b values.Operand) (result values.Operand) {
	if index == opers.IndexIntSub && a.Storage == values.Imm && a.ImmValue() == 0 {
		return inplaceIntOp(text, code, neg, b)
	}

	switch b.Storage {
	case values.Imm:
		switch {
		case b.ImmValue() == 1:
			switch index {
			case opers.IndexIntAdd:
				return inplaceIntOp(text, code, inc, a)

			case opers.IndexIntSub:
				return inplaceIntOp(text, code, dec, a)
			}

		case b.ImmValue() < -0x80000000 || b.ImmValue() >= 0x80000000:
			b = opBorrowMaybeScratchRegOperand(text, code, b, true)
		}

	case values.VarReference, values.Stack, values.ConditionFlags:
		b = opBorrowMaybeScratchRegOperand(text, code, b, true)
	}

	insn := commonBinaryIntInsns[index]

	targetReg, _ := opMaybeResultReg(text, code, a, false)
	result = values.TempRegOperand(a.Type, targetReg, true)

	switch {
	case b.Storage.IsReg():
		insn.opFromReg(text, a.Type, targetReg, b.Reg())
		code.Consumed(b)
		return

	case b.Storage == values.VarMem:
		insn.opFromStack(text, a.Type, targetReg, b.VarMemOffset())
		return

	case b.Storage == values.Imm: // large values moved to registers earlier
		insn.opImm(text, a.Type, targetReg, int32(b.ImmValue()))
		return

	default:
		panic("unexpected storage type of second operand of common binary int op")
	}
}

func binaryIntCompareOp(text gen.Buffer, code gen.RegCoder, cond uint8, a, b values.Operand) (result values.Operand) {
	targetReg, _, own := opBorrowMaybeResultReg(text, code, a, false)
	if own {
		defer code.FreeReg(a.Type, targetReg)
	}

	result = values.ConditionFlagsOperand(values.Condition(cond))

	switch {
	case b.Storage.IsReg():
		cmp.opFromReg(text, a.Type, targetReg, b.Reg())
		code.Consumed(b)
		return

	case b.Storage == values.VarMem:
		cmp.opFromStack(text, a.Type, targetReg, b.VarMemOffset())
		return

	case b.Storage == values.Imm && b.ImmValue() >= -0x80000000 && b.ImmValue() < 0x80000000:
		cmp.opImm(text, a.Type, targetReg, int32(b.ImmValue()))
		return

	default:
		opMove(text, code, RegScratch, b, false)
		cmp.opFromReg(text, a.Type, targetReg, RegScratch)
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

func binaryIntDivmulOp(text gen.Buffer, code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	insn := binaryDivmulInsns[index]
	t := a.Type

	if b.Storage == values.Imm {
		value := b.ImmValue()

		switch {
		case insn.shiftImm.defined() && value > 0 && isPowerOfTwo(uint64(value)):
			reg, _ := opMaybeResultReg(text, code, a, false)
			insn.shiftImm.op(text, t, reg, log2(uint64(value)))
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
					movMMX.opFromReg(text, abi.I64, RegScratchMMX, RegTextBase)
					defer movMMX.opToReg(text, abi.I64, RegTextBase, RegScratchMMX)

					newReg = RegTextBase
				}
			}

			mov.opFromReg(text, t, newReg, RegResult)
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
			movMMX.opFromReg(text, abi.I64, RegScratchMMX, RegTextBase)
			defer movMMX.opToReg(text, abi.I64, RegTextBase, RegScratchMMX)

			reg = RegTextBase
		}

		opMove(text, code, reg, b, true)
		b = values.RegOperand(true, t, reg)
	}

	opMove(text, code, RegResult, a, false)

	remainder := (index & opers.DivmulRem) != 0

	var doNot links.L

	if division {
		if checkZero {
			opCheckDivideByZero(text, code, t, b.Reg())
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
				xor.opFromReg(text, abi.I32, RegScratch, RegScratch) // moved to result at the end

				cmp.opImm(text, t, b.Reg(), -1)
				je.rel8.opStub(text)
				doNot.AddSite(text.Pos())
			} else {
				switch t.Size() {
				case abi.Size32:
					cmp.opImm(text, t, RegResult, -0x80000000)

				case abi.Size64:
					cmp.opFromAddr(text, t, RegResult, 0, NoIndex, code.RODataAddr()+gen.ROMask80Addr64)

				default:
					panic(a)
				}

				jne.rel8.opStub(text)
				do.AddSite(text.Pos())

				cmp.opImm(text, t, b.Reg(), -1)
				jne.rel8.opStub(text)
				do.AddSite(text.Pos())

				code.OpTrapCall(trap.IntegerOverflow)
			}

			do.Addr = text.Pos()
			updateLocalBranches(text, &do)
		}

		if signed {
			// sign-extend dividend low bits to high bits
			cdqCqo.op(text, t)
		} else {
			// zero-extend dividend high bits
			xor.opFromReg(text, abi.I32, RegScratch, RegScratch)
		}
	}

	insn.opReg(text, t, b.Reg())
	code.Consumed(b)

	doNot.Addr = text.Pos()
	updateLocalBranches(text, &doNot)

	if remainder {
		mov.opFromReg(text, t, RegResult, RegScratch)
	}

	return values.TempRegOperand(t, RegResult, true)
}

func opCheckDivideByZero(text gen.Buffer, code gen.Coder, t abi.Type, reg regs.R) {
	var end links.L

	test.opFromReg(text, t, reg, reg)
	jne.rel8.opStub(text)
	end.AddSite(text.Pos())

	code.OpTrapCall(trap.IntegerDivideByZero)

	end.Addr = text.Pos()
	updateLocalBranches(text, &end)
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

func binaryIntShiftOp(text gen.Buffer, code gen.RegCoder, index uint8, a, b values.Operand) (result values.Operand) {
	insn := binaryShiftInsns[index]

	switch {
	case b.Storage == values.Imm:
		reg, _ := opMaybeResultReg(text, code, a, true)
		insn.imm.op(text, b.Type, reg, uint8(b.ImmValue()))
		result = values.TempRegOperand(a.Type, reg, true)

	case b.Storage.IsReg() && b.Reg() == RegShiftCount:
		reg, _ := opMaybeResultReg(text, code, a, false)
		insn.reg.opReg(text, a.Type, reg)
		code.Discard(b)
		result = values.TempRegOperand(a.Type, reg, true)

	case code.RegAllocated(abi.I32, RegShiftCount):
		reg, _ := opMaybeResultReg(text, code, a, true)
		if reg == RegShiftCount {
			mov.opFromReg(text, a.Type, RegResult, RegShiftCount)
			result = subtleShiftOp(text, code, insn.reg, a.Type, RegResult, b)
			code.FreeReg(abi.I32, RegShiftCount)
		} else {
			// unknown operand in RegShiftCount
			mov.opFromReg(text, abi.I64, RegScratch, RegShiftCount) // save
			result = subtleShiftOp(text, code, insn.reg, a.Type, reg, b)
			mov.opFromReg(text, abi.I64, RegShiftCount, RegScratch) // restore
		}

	default:
		code.AllocSpecificReg(abi.I32, RegShiftCount)
		reg, _ := opMaybeResultReg(text, code, a, true)
		result = subtleShiftOp(text, code, insn.reg, a.Type, reg, b)
		code.FreeReg(abi.I32, RegShiftCount)
	}

	return
}

// subtleShiftOp trashes RegShiftCount.
func subtleShiftOp(text gen.Buffer, code gen.Coder, insn insnRexM, t abi.Type, reg regs.R, count values.Operand) values.Operand {
	count.Type = abi.I32                            // TODO: 8-bit mov
	opMove(text, code, RegShiftCount, count, false) //
	insn.opReg(text, t, reg)
	return values.TempRegOperand(t, reg, true)
}

var commonBinaryFloatInsns = []insnPrefix{
	opers.IndexFloatAdd: addsSSE,
	opers.IndexFloatSub: subsSSE,
	opers.IndexFloatDiv: divsSSE,
	opers.IndexFloatMul: mulsSSE,
}

// TODO: support memory source operands

func commonBinaryFloatOp(text gen.Buffer, code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	targetReg, _ := opMaybeResultReg(text, code, a, false)

	sourceReg, _, own := opBorrowMaybeScratchReg(text, code, b, false)
	if own {
		defer code.FreeReg(b.Type, sourceReg)
	}

	commonBinaryFloatInsns[index].opFromReg(text, a.Type, targetReg, sourceReg)
	return values.TempRegOperand(a.Type, targetReg, false)
}

var binaryFloatMinmaxInsns = []struct {
	commonInsn insnPrefix
	zeroInsn   insnPrefix
}{
	opers.IndexMinmaxMin: {minsSSE, orpSSE},
	opers.IndexMinmaxMax: {maxsSSE, andpSSE},
}

func binaryFloatMinmaxOp(text gen.Buffer, code gen.RegCoder, index uint8, a, b values.Operand) values.Operand {
	targetReg, _ := opMaybeResultReg(text, code, a, false)

	sourceReg, _, own := opBorrowMaybeScratchReg(text, code, b, false)
	if own {
		defer code.FreeReg(b.Type, sourceReg)
	}

	var common links.L
	var end links.L

	ucomisSSE.opFromReg(text, a.Type, targetReg, sourceReg)
	jne.rel8.opStub(text)
	common.AddSite(text.Pos())

	binaryFloatMinmaxInsns[index].zeroInsn.opFromReg(text, a.Type, targetReg, sourceReg)
	jmpRel.rel8.opStub(text)
	end.AddSite(text.Pos())

	common.Addr = text.Pos()
	updateLocalBranches(text, &common)

	binaryFloatMinmaxInsns[index].commonInsn.opFromReg(text, a.Type, targetReg, sourceReg)

	end.Addr = text.Pos()
	updateLocalBranches(text, &end)

	return values.TempRegOperand(a.Type, targetReg, false)
}

func binaryFloatCompareOp(text gen.Buffer, code gen.RegCoder, cond uint8, a, b values.Operand) values.Operand {
	aReg, _, own := opBorrowMaybeResultReg(text, code, a, true)
	if own {
		defer code.FreeReg(a.Type, aReg)
	}

	bReg, _, own := opBorrowMaybeScratchReg(text, code, b, false)
	if own {
		defer code.FreeReg(b.Type, bReg)
	}

	ucomisSSE.opFromReg(text, a.Type, aReg, bReg)
	return values.ConditionFlagsOperand(values.Condition(cond))
}

func binaryFloatCopysignOp(text gen.Buffer, code gen.RegCoder, a, b values.Operand) values.Operand {
	targetReg, _ := opMaybeResultReg(text, code, a, false)

	sourceReg, _, own := opBorrowMaybeScratchReg(text, code, b, false)
	if own {
		defer code.FreeReg(b.Type, sourceReg)
	}

	var done links.L

	signMaskAddr := gen.MaskAddr(code.RODataAddr(), gen.Mask80Base, a.Type)

	movSSE.opToReg(text, a.Type, RegScratch, sourceReg) // int <- float
	and.opFromAddr(text, a.Type, RegScratch, 0, NoIndex, signMaskAddr)
	movSSE.opToReg(text, a.Type, RegResult, targetReg) // int <- float
	and.opFromAddr(text, a.Type, RegResult, 0, NoIndex, signMaskAddr)
	cmp.opFromReg(text, a.Type, RegResult, RegScratch)
	je.rel8.opStub(text)
	done.AddSite(text.Pos())

	opNegFloatReg(text, code, a.Type, targetReg)

	done.Addr = text.Pos()
	updateLocalBranches(text, &done)

	return values.TempRegOperand(a.Type, targetReg, false)
}

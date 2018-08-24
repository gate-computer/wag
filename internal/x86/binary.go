// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/prop"
	"github.com/tsavola/wag/internal/gen/val"
	"github.com/tsavola/wag/internal/link"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/rodata"
	"github.com/tsavola/wag/trap"
)

func (ISA) BinaryOp(f *gen.Func, props uint16, a, b val.Operand) val.Operand {
	if (props & prop.BinaryFloat) == 0 {
		switch {
		case (props & prop.BinaryCompare) != 0:
			return binaryIntCompareOp(f, uint8(props), a, b)

		case (props & prop.BinaryIntShift) != 0:
			return binaryIntShiftOp(f, uint8(props), a, b)

		case (props & prop.BinaryIntDivmul) != 0:
			return binaryIntDivmulOp(f, uint8(props), a, b)

		default:
			return commonBinaryIntOp(f, uint8(props), a, b)
		}
	} else {
		switch {
		case (props & prop.BinaryCompare) != 0:
			return binaryFloatCompareOp(f, uint8(props), a, b)

		case (props & prop.BinaryFloatMinmax) != 0:
			return binaryFloatMinmaxOp(f, uint8(props), a, b)

		case (props & prop.BinaryFloatCopysign) != 0:
			return binaryFloatCopysignOp(f, a, b)

		default:
			return commonBinaryFloatOp(f, uint8(props), a, b)
		}
	}
}

var commonBinaryIntInsns = []binaryInsn{
	prop.IndexIntAdd: add,
	prop.IndexIntSub: sub,
	prop.IndexIntAnd: and,
	prop.IndexIntOr:  or,
	prop.IndexIntXor: xor,
}

func commonBinaryIntOp(f *gen.Func, index uint8, a, b val.Operand) (result val.Operand) {
	if index == prop.IndexIntSub && a.Storage == val.Imm && a.ImmValue() == 0 {
		return inplaceIntOp(f, neg, b)
	}

	switch b.Storage {
	case val.Imm:
		switch {
		case b.ImmValue() == 1:
			switch index {
			case prop.IndexIntAdd:
				return inplaceIntOp(f, inc, a)

			case prop.IndexIntSub:
				return inplaceIntOp(f, dec, a)
			}

		case b.ImmValue() < -0x80000000 || b.ImmValue() >= 0x80000000:
			b = opBorrowMaybeScratchRegOperand(f, b, true)
		}

	case val.VarReference, val.Stack, val.ConditionFlags:
		b = opBorrowMaybeScratchRegOperand(f, b, true)
	}

	insn := commonBinaryIntInsns[index]

	targetReg, _ := opMaybeResultReg(f, a, false)
	result = val.TempRegOperand(a.Type, targetReg, true)

	switch {
	case b.Storage.IsReg():
		insn.opFromReg(&f.Text, a.Type, targetReg, b.Reg())
		if b.Storage == val.TempReg {
			f.Regs.Free(b.Type, b.Reg())
		}
		return

	case b.Storage == val.VarMem:
		insn.opFromStack(&f.Text, a.Type, targetReg, b.VarMemOffset())
		return

	case b.Storage == val.Imm: // large values moved to registers earlier
		insn.opImm(&f.Text, a.Type, targetReg, int32(b.ImmValue()))
		return

	default:
		panic("unexpected storage type of second operand of common binary int op")
	}
}

func binaryIntCompareOp(f *gen.Func, cond uint8, a, b val.Operand) (result val.Operand) {
	targetReg, _, own := opBorrowMaybeResultReg(f, a, false)
	if own {
		defer f.Regs.Free(a.Type, targetReg)
	}

	result = val.ConditionFlagsOperand(val.Condition(cond))

	switch {
	case b.Storage.IsReg():
		cmp.opFromReg(&f.Text, a.Type, targetReg, b.Reg())
		if b.Storage == val.TempReg {
			f.Regs.Free(b.Type, b.Reg())
		}
		return

	case b.Storage == val.VarMem:
		cmp.opFromStack(&f.Text, a.Type, targetReg, b.VarMemOffset())
		return

	case b.Storage == val.Imm && b.ImmValue() >= -0x80000000 && b.ImmValue() < 0x80000000:
		cmp.opImm(&f.Text, a.Type, targetReg, int32(b.ImmValue()))
		return

	default:
		opMove(f, RegScratch, b, false)
		cmp.opFromReg(&f.Text, a.Type, targetReg, RegScratch)
		return
	}
}

var binaryDivmulInsns = []struct {
	insnRexM
	shiftImm shiftImmInsn
}{
	prop.IndexDivmulDivS: {idiv, noShiftImmInsn},
	prop.IndexDivmulDivU: {div, shrImm},
	prop.IndexDivmulRemS: {idiv, noShiftImmInsn},
	prop.IndexDivmulRemU: {div, noShiftImmInsn}, // TODO: use AND for 2^n divisors
	prop.IndexDivmulMul:  {mul, shlImm},
}

func binaryIntDivmulOp(f *gen.Func, index uint8, a, b val.Operand) val.Operand {
	insn := binaryDivmulInsns[index]
	t := a.Type

	if b.Storage == val.Imm {
		value := b.ImmValue()

		switch {
		case insn.shiftImm.defined() && value > 0 && isPowerOfTwo(uint64(value)):
			reg, _ := opMaybeResultReg(f, a, false)
			insn.shiftImm.op(&f.Text, t, reg, log2(uint64(value)))
			return val.TempRegOperand(t, reg, true)
		}
	}

	division := (index & prop.DivmulMul) == 0
	checkZero := true
	checkOverflow := true

	if b.Storage.IsReg() {
		if b.Reg() == RegResult {
			newReg := RegScratch

			if division {
				var ok bool

				// can't use scratch reg as divisor since it contains the dividend high bits
				newReg, ok = f.Regs.Alloc(t)
				if !ok {
					// borrow a register which we don't need in this function
					movMMX.opFromReg(&f.Text, abi.I64, RegScratchMMX, RegTextBase)
					defer movMMX.opToReg(&f.Text, abi.I64, RegTextBase, RegScratchMMX)

					newReg = RegTextBase
				}
			}

			mov.opFromReg(&f.Text, t, newReg, RegResult)
			b = val.RegOperand(true, t, newReg)
		}
	} else {
		if division && b.Storage == val.Imm {
			value := b.ImmValue()
			if value != 0 {
				checkZero = false
			}
			if value != -1 {
				checkOverflow = false
			}
		}

		reg, ok := f.Regs.Alloc(t)
		if !ok {
			// borrow a register which we don't need in this function
			movMMX.opFromReg(&f.Text, abi.I64, RegScratchMMX, RegTextBase)
			defer movMMX.opToReg(&f.Text, abi.I64, RegTextBase, RegScratchMMX)

			reg = RegTextBase
		}

		opMove(f, reg, b, true)
		b = val.RegOperand(true, t, reg)
	}

	opMove(f, RegResult, a, false)

	remainder := (index & prop.DivmulRem) != 0

	var doNot link.L

	if division {
		if checkZero {
			opCheckDivideByZero(f, t, b.Reg())
		}

		if a.Storage == val.Imm {
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

		signed := (index & prop.DivmulSign) != 0

		if signed && checkOverflow {
			var do link.L

			if remainder {
				xor.opFromReg(&f.Text, abi.I32, RegScratch, RegScratch) // moved to result at the end

				cmp.opImm(&f.Text, t, b.Reg(), -1)
				je.rel8.opStub(&f.Text)
				doNot.AddSite(f.Text.Addr)
			} else {
				switch t.Size() {
				case abi.Size32:
					cmp.opImm(&f.Text, t, RegResult, -0x80000000)

				case abi.Size64:
					cmp.opFromAddr(&f.Text, t, RegResult, 0, NoIndex, f.RODataAddr+rodata.Mask80Addr64)

				default:
					panic(a)
				}

				jne.rel8.opStub(&f.Text)
				do.AddSite(f.Text.Addr)

				cmp.opImm(&f.Text, t, b.Reg(), -1)
				jne.rel8.opStub(&f.Text)
				do.AddSite(f.Text.Addr)

				opTrapCall(f, trap.IntegerOverflow)
			}

			do.Addr = f.Text.Addr
			updateLocalBranches(f.M, &do)
		}

		if signed {
			// sign-extend dividend low bits to high bits
			cdqCqo.op(&f.Text, t)
		} else {
			// zero-extend dividend high bits
			xor.opFromReg(&f.Text, abi.I32, RegScratch, RegScratch)
		}
	}

	insn.opReg(&f.Text, t, b.Reg())
	if b.Storage == val.TempReg {
		f.Regs.Free(b.Type, b.Reg())
	}

	doNot.Addr = f.Text.Addr
	updateLocalBranches(f.M, &doNot)

	if remainder {
		mov.opFromReg(&f.Text, t, RegResult, RegScratch)
	}

	return val.TempRegOperand(t, RegResult, true)
}

func opCheckDivideByZero(f *gen.Func, t abi.Type, reg regs.R) {
	var end link.L

	test.opFromReg(&f.Text, t, reg, reg)
	jne.rel8.opStub(&f.Text)
	end.AddSite(f.Text.Addr)

	opTrapCall(f, trap.IntegerDivideByZero)

	end.Addr = f.Text.Addr
	updateLocalBranches(f.M, &end)
}

var binaryShiftInsns = []struct {
	reg insnRexM
	imm shiftImmInsn
}{
	prop.IndexShiftRotl: {rol, rolImm},
	prop.IndexShiftRotr: {ror, rorImm},
	prop.IndexShiftShl:  {shl, shlImm},
	prop.IndexShiftShrS: {sar, sarImm},
	prop.IndexShiftShrU: {shr, shrImm},
}

func binaryIntShiftOp(f *gen.Func, index uint8, a, b val.Operand) (result val.Operand) {
	insn := binaryShiftInsns[index]

	switch {
	case b.Storage == val.Imm:
		reg, _ := opMaybeResultReg(f, a, true)
		insn.imm.op(&f.Text, b.Type, reg, uint8(b.ImmValue()))
		result = val.TempRegOperand(a.Type, reg, true)

	case b.Storage.IsReg() && b.Reg() == RegShiftCount:
		reg, _ := opMaybeResultReg(f, a, false)
		insn.reg.opReg(&f.Text, a.Type, reg)
		if b.Storage == val.TempReg {
			f.Regs.Free(abi.I32, RegShiftCount)
		}
		result = val.TempRegOperand(a.Type, reg, true)

	case f.Regs.Allocated(abi.I32, RegShiftCount):
		reg, _ := opMaybeResultReg(f, a, true)
		if reg == RegShiftCount {
			mov.opFromReg(&f.Text, a.Type, RegResult, RegShiftCount)
			result = subtleShiftOp(f, insn.reg, a.Type, RegResult, b)
			f.Regs.Free(abi.I32, RegShiftCount)
		} else {
			// unknown operand in RegShiftCount
			mov.opFromReg(&f.Text, abi.I64, RegScratch, RegShiftCount) // save
			result = subtleShiftOp(f, insn.reg, a.Type, reg, b)
			mov.opFromReg(&f.Text, abi.I64, RegShiftCount, RegScratch) // restore
		}

	default:
		f.Regs.AllocSpecific(abi.I32, RegShiftCount)
		reg, _ := opMaybeResultReg(f, a, true)
		result = subtleShiftOp(f, insn.reg, a.Type, reg, b)
		f.Regs.Free(abi.I32, RegShiftCount)
	}

	return
}

// subtleShiftOp trashes RegShiftCount.
func subtleShiftOp(f *gen.Func, insn insnRexM, t abi.Type, reg regs.R, count val.Operand) val.Operand {
	count.Type = abi.I32                   // TODO: 8-bit mov
	opMove(f, RegShiftCount, count, false) //
	insn.opReg(&f.Text, t, reg)
	return val.TempRegOperand(t, reg, true)
}

var commonBinaryFloatInsns = []insnPrefix{
	prop.IndexFloatAdd: addsSSE,
	prop.IndexFloatSub: subsSSE,
	prop.IndexFloatDiv: divsSSE,
	prop.IndexFloatMul: mulsSSE,
}

// TODO: support memory source operands

func commonBinaryFloatOp(f *gen.Func, index uint8, a, b val.Operand) val.Operand {
	targetReg, _ := opMaybeResultReg(f, a, false)

	sourceReg, _, own := opBorrowMaybeScratchReg(f, b, false)
	if own {
		defer f.Regs.Free(b.Type, sourceReg)
	}

	commonBinaryFloatInsns[index].opFromReg(&f.Text, a.Type, targetReg, sourceReg)
	return val.TempRegOperand(a.Type, targetReg, false)
}

var binaryFloatMinmaxInsns = []struct {
	commonInsn insnPrefix
	zeroInsn   insnPrefix
}{
	prop.IndexMinmaxMin: {minsSSE, orpSSE},
	prop.IndexMinmaxMax: {maxsSSE, andpSSE},
}

func binaryFloatMinmaxOp(f *gen.Func, index uint8, a, b val.Operand) val.Operand {
	targetReg, _ := opMaybeResultReg(f, a, false)

	sourceReg, _, own := opBorrowMaybeScratchReg(f, b, false)
	if own {
		defer f.Regs.Free(b.Type, sourceReg)
	}

	var common link.L
	var end link.L

	ucomisSSE.opFromReg(&f.Text, a.Type, targetReg, sourceReg)
	jne.rel8.opStub(&f.Text)
	common.AddSite(f.Text.Addr)

	binaryFloatMinmaxInsns[index].zeroInsn.opFromReg(&f.Text, a.Type, targetReg, sourceReg)
	jmpRel.rel8.opStub(&f.Text)
	end.AddSite(f.Text.Addr)

	common.Addr = f.Text.Addr
	updateLocalBranches(f.M, &common)

	binaryFloatMinmaxInsns[index].commonInsn.opFromReg(&f.Text, a.Type, targetReg, sourceReg)

	end.Addr = f.Text.Addr
	updateLocalBranches(f.M, &end)

	return val.TempRegOperand(a.Type, targetReg, false)
}

func binaryFloatCompareOp(f *gen.Func, cond uint8, a, b val.Operand) val.Operand {
	aReg, _, own := opBorrowMaybeResultReg(f, a, true)
	if own {
		defer f.Regs.Free(a.Type, aReg)
	}

	bReg, _, own := opBorrowMaybeScratchReg(f, b, false)
	if own {
		defer f.Regs.Free(b.Type, bReg)
	}

	ucomisSSE.opFromReg(&f.Text, a.Type, aReg, bReg)
	return val.ConditionFlagsOperand(val.Condition(cond))
}

func binaryFloatCopysignOp(f *gen.Func, a, b val.Operand) val.Operand {
	targetReg, _ := opMaybeResultReg(f, a, false)

	sourceReg, _, own := opBorrowMaybeScratchReg(f, b, false)
	if own {
		defer f.Regs.Free(b.Type, sourceReg)
	}

	var done link.L

	signMaskAddr := rodata.MaskAddr(f.RODataAddr, rodata.Mask80Base, a.Type)

	movSSE.opToReg(&f.Text, a.Type, RegScratch, sourceReg) // int <- float
	and.opFromAddr(&f.Text, a.Type, RegScratch, 0, NoIndex, signMaskAddr)
	movSSE.opToReg(&f.Text, a.Type, RegResult, targetReg) // int <- float
	and.opFromAddr(&f.Text, a.Type, RegResult, 0, NoIndex, signMaskAddr)
	cmp.opFromReg(&f.Text, a.Type, RegResult, RegScratch)
	je.rel8.opStub(&f.Text)
	done.AddSite(f.Text.Addr)

	opNegFloatReg(f.M, a.Type, targetReg)

	done.Addr = f.Text.Addr
	updateLocalBranches(f.M, &done)

	return val.TempRegOperand(a.Type, targetReg, false)
}

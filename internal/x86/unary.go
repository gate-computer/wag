// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/opers"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/types"
)

func (mach X86) UnaryOp(code gen.RegCoder, oper uint16, x values.Operand) values.Operand {
	if (oper & opers.UnaryFloat) == 0 {
		return mach.unaryIntOp(code, oper, x)
	} else {
		return mach.unaryFloatOp(code, oper, x)
	}
}

func (mach X86) unaryIntOp(code gen.RegCoder, oper uint16, x values.Operand) values.Operand {
	switch index := uint8(oper); index {
	case opers.IndexIntEqz:
		return mach.opIntEqz(code, x)

	default:
		return mach.commonUnaryIntOp(code, index, x)
	}
}

func (mach X86) opIntEqz(code gen.RegCoder, x values.Operand) values.Operand {
	reg, _, own := mach.opBorrowMaybeScratchReg(code, x, false)
	if own {
		defer code.FreeReg(x.Type, reg)
	}

	test.opFromReg(code, x.Type, reg, reg)
	return values.ConditionFlagsOperand(values.Eq)
}

func (mach X86) commonUnaryIntOp(code gen.RegCoder, index uint8, x values.Operand) (result values.Operand) {
	var ok bool
	var targetReg regs.R

	sourceReg, _, own := mach.opBorrowMaybeScratchReg(code, x, false)
	if own {
		targetReg = sourceReg
	} else {
		targetReg, ok = code.TryAllocReg(x.Type)
		if !ok {
			targetReg = regResult
		}
	}

	result = values.TempRegOperand(x.Type, targetReg, true)

	switch index {
	case opers.IndexIntClz:
		bsr.opFromReg(code, x.Type, regScratch, sourceReg)
		movImm.opImm(code, x.Type, targetReg, -1)
		cmove.opFromReg(code, x.Type, regScratch, targetReg)
		movImm.opImm(code, x.Type, targetReg, (int32(x.Type.Size())<<3)-1)
		sub.opFromReg(code, x.Type, targetReg, regScratch)
		return

	case opers.IndexIntCtz:
		bsf.opFromReg(code, x.Type, targetReg, sourceReg)
		movImm.opImm(code, x.Type, regScratch, int32(x.Type.Size())<<3)
		cmove.opFromReg(code, x.Type, targetReg, regScratch)
		return

	case opers.IndexIntPopcnt:
		popcnt.opFromReg(code, x.Type, targetReg, sourceReg)
		return
	}

	panic("unknown unary int op")
}

func (mach X86) unaryFloatOp(code gen.RegCoder, oper uint16, x values.Operand) (result values.Operand) {
	// TODO: support memory source operands

	reg, _ := mach.opMaybeResultReg(code, x, false)
	result = values.TempRegOperand(x.Type, reg, false)

	if (oper & opers.UnaryRound) != 0 {
		roundMode := uint8(oper)
		roundsSSE.opReg(code, x.Type, reg, reg, int8(roundMode))
		return
	} else {
		switch index := uint8(oper); index {
		case opers.IndexFloatAbs:
			mach.opAbsFloatReg(code, x.Type, reg)
			return

		case opers.IndexFloatNeg:
			mach.opNegFloatReg(code, x.Type, reg)
			return

		case opers.IndexFloatSqrt:
			sqrtsSSE.opFromReg(code, x.Type, reg, reg)
			return
		}
	}

	panic("unknown unary float op")
}

// opAbsFloatReg in-place.
func (mach X86) opAbsFloatReg(code gen.RegCoder, t types.T, reg regs.R) {
	absMask := ^(uint64(1) << (uint(t.Size())*8 - 1)) // only high bit cleared
	movImm64.op(code, t, regScratch, int64(absMask))  // integer scratch register
	movSSE.opFromReg(code, t, regScratch, regScratch) // float scratch register
	andpSSE.opFromReg(code, t, reg, regScratch)
}

// opNegFloatReg in-place.
func (mach X86) opNegFloatReg(code gen.RegCoder, t types.T, reg regs.R) {
	signMask := int64(-1) << (uint(t.Size())*8 - 1)   // only high bit set
	movImm64.op(code, t, regScratch, signMask)        // integer scratch register
	movSSE.opFromReg(code, t, regScratch, regScratch) // float scratch register
	xorpSSE.opFromReg(code, t, reg, regScratch)
}

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/opers"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
)

func (ISA) UnaryOp(text *gen.Text, code gen.RegCoder, oper uint16, x values.Operand) values.Operand {
	if (oper & opers.UnaryFloat) == 0 {
		return unaryIntOp(text, code, oper, x)
	} else {
		return unaryFloatOp(text, code, oper, x)
	}
}

func unaryIntOp(text *gen.Text, code gen.RegCoder, oper uint16, x values.Operand) values.Operand {
	switch index := uint8(oper); index {
	case opers.IndexIntEqz:
		return opIntEqz(text, code, x)

	default:
		return commonUnaryIntOp(text, code, index, x)
	}
}

func opIntEqz(text *gen.Text, code gen.Coder, x values.Operand) values.Operand {
	reg, _, own := opBorrowMaybeScratchReg(text, code, x, false)
	if own {
		defer code.FreeReg(x.Type, reg)
	}

	test.opFromReg(text, x.Type, reg, reg)
	return values.ConditionFlagsOperand(values.Eq)
}

func commonUnaryIntOp(text *gen.Text, code gen.RegCoder, index uint8, x values.Operand) (result values.Operand) {
	var ok bool
	var targetReg regs.R

	sourceReg, _, own := opBorrowMaybeScratchReg(text, code, x, false)
	if own {
		targetReg = sourceReg
	} else {
		targetReg, ok = code.TryAllocReg(x.Type)
		if !ok {
			targetReg = RegResult
		}
	}

	result = values.TempRegOperand(x.Type, targetReg, true)

	switch index {
	case opers.IndexIntClz:
		bsr.opFromReg(text, x.Type, RegScratch, sourceReg)
		movImm.opImm(text, x.Type, targetReg, -1)
		cmove.opFromReg(text, x.Type, RegScratch, targetReg)
		movImm.opImm(text, x.Type, targetReg, (int32(x.Type.Size())<<3)-1)
		sub.opFromReg(text, x.Type, targetReg, RegScratch)
		return

	case opers.IndexIntCtz:
		bsf.opFromReg(text, x.Type, targetReg, sourceReg)
		movImm.opImm(text, x.Type, RegScratch, int32(x.Type.Size())<<3)
		cmove.opFromReg(text, x.Type, targetReg, RegScratch)
		return

	case opers.IndexIntPopcnt:
		popcnt.opFromReg(text, x.Type, targetReg, sourceReg)
		return
	}

	panic("unknown unary int op")
}

func unaryFloatOp(text *gen.Text, code gen.RegCoder, oper uint16, x values.Operand) (result values.Operand) {
	// TODO: support memory source operands

	reg, _ := opMaybeResultReg(text, code, x, false)
	result = values.TempRegOperand(x.Type, reg, false)

	if (oper & opers.UnaryRound) != 0 {
		roundMode := uint8(oper)
		roundsSSE.opReg(text, x.Type, reg, reg, int8(roundMode))
		return
	} else {
		switch index := uint8(oper); index {
		case opers.IndexFloatAbs:
			opAbsFloatReg(text, code, x.Type, reg)
			return

		case opers.IndexFloatNeg:
			opNegFloatReg(text, code, x.Type, reg)
			return

		case opers.IndexFloatSqrt:
			sqrtsSSE.opFromReg(text, x.Type, reg, reg)
			return
		}
	}

	panic("unknown unary float op")
}

// opAbsFloatReg in-place.
func opAbsFloatReg(text *gen.Text, code gen.Coder, t abi.Type, reg regs.R) {
	absMaskAddr := gen.MaskAddr(code.RODataAddr(), gen.Mask7fBase, t)
	andpSSE.opFromAddr(text, t, reg, 0, NoIndex, absMaskAddr)
}

// opNegFloatReg in-place.
func opNegFloatReg(text *gen.Text, code gen.Coder, t abi.Type, reg regs.R) {
	signMaskAddr := gen.MaskAddr(code.RODataAddr(), gen.Mask80Base, t)
	xorpSSE.opFromAddr(text, t, reg, 0, NoIndex, signMaskAddr)
}

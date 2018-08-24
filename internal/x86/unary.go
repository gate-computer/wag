// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/mod"
	"github.com/tsavola/wag/internal/opers"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
)

func (ISA) UnaryOp(f *gen.Func, oper uint16, x values.Operand) values.Operand {
	if (oper & opers.UnaryFloat) == 0 {
		return unaryIntOp(f, oper, x)
	} else {
		return unaryFloatOp(f, oper, x)
	}
}

func unaryIntOp(f *gen.Func, oper uint16, x values.Operand) values.Operand {
	switch index := uint8(oper); index {
	case opers.IndexIntEqz:
		return opIntEqz(f, x)

	default:
		return commonUnaryIntOp(f, index, x)
	}
}

func opIntEqz(f *gen.Func, x values.Operand) values.Operand {
	reg, _, own := opBorrowMaybeScratchReg(f, x, false)
	if own {
		defer f.Regs.Free(x.Type, reg)
	}

	test.opFromReg(&f.Text, x.Type, reg, reg)
	return values.ConditionFlagsOperand(values.Eq)
}

func commonUnaryIntOp(f *gen.Func, index uint8, x values.Operand) (result values.Operand) {
	var ok bool
	var targetReg regs.R

	sourceReg, _, own := opBorrowMaybeScratchReg(f, x, false)
	if own {
		targetReg = sourceReg
	} else {
		targetReg, ok = f.Regs.Alloc(x.Type)
		if !ok {
			targetReg = RegResult
		}
	}

	result = values.TempRegOperand(x.Type, targetReg, true)

	switch index {
	case opers.IndexIntClz:
		bsr.opFromReg(&f.Text, x.Type, RegScratch, sourceReg)
		movImm.opImm(&f.Text, x.Type, targetReg, -1)
		cmove.opFromReg(&f.Text, x.Type, RegScratch, targetReg)
		movImm.opImm(&f.Text, x.Type, targetReg, (int32(x.Type.Size())<<3)-1)
		sub.opFromReg(&f.Text, x.Type, targetReg, RegScratch)
		return

	case opers.IndexIntCtz:
		bsf.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
		movImm.opImm(&f.Text, x.Type, RegScratch, int32(x.Type.Size())<<3)
		cmove.opFromReg(&f.Text, x.Type, targetReg, RegScratch)
		return

	case opers.IndexIntPopcnt:
		popcnt.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
		return
	}

	panic("unknown unary int op")
}

func unaryFloatOp(f *gen.Func, oper uint16, x values.Operand) (result values.Operand) {
	// TODO: support memory source operands

	reg, _ := opMaybeResultReg(f, x, false)
	result = values.TempRegOperand(x.Type, reg, false)

	if (oper & opers.UnaryRound) != 0 {
		roundMode := uint8(oper)
		roundsSSE.opReg(&f.Text, x.Type, reg, reg, int8(roundMode))
		return
	} else {
		switch index := uint8(oper); index {
		case opers.IndexFloatAbs:
			opAbsFloatReg(f.M, x.Type, reg)
			return

		case opers.IndexFloatNeg:
			opNegFloatReg(f.M, x.Type, reg)
			return

		case opers.IndexFloatSqrt:
			sqrtsSSE.opFromReg(&f.Text, x.Type, reg, reg)
			return
		}
	}

	panic("unknown unary float op")
}

// opAbsFloatReg in-place.
func opAbsFloatReg(m *mod.M, t abi.Type, reg regs.R) {
	absMaskAddr := gen.MaskAddr(m.RODataAddr, gen.Mask7fBase, t)
	andpSSE.opFromAddr(&m.Text, t, reg, 0, NoIndex, absMaskAddr)
}

// opNegFloatReg in-place.
func opNegFloatReg(m *mod.M, t abi.Type, reg regs.R) {
	signMaskAddr := gen.MaskAddr(m.RODataAddr, gen.Mask80Base, t)
	xorpSSE.opFromAddr(&m.Text, t, reg, 0, NoIndex, signMaskAddr)
}

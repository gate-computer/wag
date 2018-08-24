// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/prop"
	"github.com/tsavola/wag/internal/gen/val"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/rodata"
)

func (ISA) UnaryOp(f *gen.Func, props uint16, x val.Operand) val.Operand {
	if (props & prop.UnaryFloat) == 0 {
		return unaryIntOp(f, props, x)
	} else {
		return unaryFloatOp(f, props, x)
	}
}

func unaryIntOp(f *gen.Func, props uint16, x val.Operand) val.Operand {
	switch index := uint8(props); index {
	case prop.IndexIntEqz:
		return opIntEqz(f, x)

	default:
		return commonUnaryIntOp(f, index, x)
	}
}

func opIntEqz(f *gen.Func, x val.Operand) val.Operand {
	reg, _, own := opBorrowMaybeScratchReg(f, x, false)
	if own {
		defer f.Regs.Free(x.Type, reg)
	}

	test.opFromReg(&f.Text, x.Type, reg, reg)
	return val.ConditionFlagsOperand(val.Eq)
}

func commonUnaryIntOp(f *gen.Func, index uint8, x val.Operand) (result val.Operand) {
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

	result = val.TempRegOperand(x.Type, targetReg, true)

	switch index {
	case prop.IndexIntClz:
		bsr.opFromReg(&f.Text, x.Type, RegScratch, sourceReg)
		movImm.opImm(&f.Text, x.Type, targetReg, -1)
		cmove.opFromReg(&f.Text, x.Type, RegScratch, targetReg)
		movImm.opImm(&f.Text, x.Type, targetReg, (int32(x.Type.Size())<<3)-1)
		sub.opFromReg(&f.Text, x.Type, targetReg, RegScratch)
		return

	case prop.IndexIntCtz:
		bsf.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
		movImm.opImm(&f.Text, x.Type, RegScratch, int32(x.Type.Size())<<3)
		cmove.opFromReg(&f.Text, x.Type, targetReg, RegScratch)
		return

	case prop.IndexIntPopcnt:
		popcnt.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
		return
	}

	panic("unknown unary int op")
}

func unaryFloatOp(f *gen.Func, props uint16, x val.Operand) (result val.Operand) {
	// TODO: support memory source operands

	reg, _ := opMaybeResultReg(f, x, false)
	result = val.TempRegOperand(x.Type, reg, false)

	if (props & prop.UnaryRound) != 0 {
		roundMode := uint8(props)
		roundsSSE.opReg(&f.Text, x.Type, reg, reg, int8(roundMode))
		return
	} else {
		switch index := uint8(props); index {
		case prop.IndexFloatAbs:
			opAbsFloatReg(f.M, x.Type, reg)
			return

		case prop.IndexFloatNeg:
			opNegFloatReg(f.M, x.Type, reg)
			return

		case prop.IndexFloatSqrt:
			sqrtsSSE.opFromReg(&f.Text, x.Type, reg, reg)
			return
		}
	}

	panic("unknown unary float op")
}

// opAbsFloatReg in-place.
func opAbsFloatReg(m *module.M, t abi.Type, reg regs.R) {
	absMaskAddr := rodata.MaskAddr(m.RODataAddr, rodata.Mask7fBase, t)
	andpSSE.opFromAddr(&m.Text, t, reg, 0, NoIndex, absMaskAddr)
}

// opNegFloatReg in-place.
func opNegFloatReg(m *module.M, t abi.Type, reg regs.R) {
	signMaskAddr := rodata.MaskAddr(m.RODataAddr, rodata.Mask80Base, t)
	xorpSSE.opFromAddr(&m.Text, t, reg, 0, NoIndex, signMaskAddr)
}

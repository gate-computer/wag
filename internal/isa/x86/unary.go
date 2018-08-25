// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/gen/val"
	"github.com/tsavola/wag/internal/isa/prop"
	"github.com/tsavola/wag/internal/module"
)

func (ISA) UnaryOp(f *gen.Func, props uint16, x val.Operand) val.Operand {
	switch props & 7 {
	case prop.IntEqz:
		r, _, own := opBorrowMaybeScratchReg(f, x, false)
		test.opFromReg(&f.Text, x.Type, r, r)
		if own {
			f.Regs.Free(x.Type, r)
		}
		return val.ConditionFlagsOperand(val.Eq)

	case prop.IntClz:
		sourceReg, targetReg, result := commonUnaryIntOpPrologue(f, x)
		bsr.opFromReg(&f.Text, x.Type, RegScratch, sourceReg)
		movImm.opImm(&f.Text, x.Type, targetReg, -1)
		cmove.opFromReg(&f.Text, x.Type, RegScratch, targetReg)
		movImm.opImm(&f.Text, x.Type, targetReg, (int32(x.Type.Size())<<3)-1)
		sub.opFromReg(&f.Text, x.Type, targetReg, RegScratch)
		return result

	case prop.IntCtz:
		sourceReg, targetReg, result := commonUnaryIntOpPrologue(f, x)
		bsf.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
		movImm.opImm(&f.Text, x.Type, RegScratch, int32(x.Type.Size())<<3)
		cmove.opFromReg(&f.Text, x.Type, targetReg, RegScratch)
		return result

	case prop.IntPopcnt:
		sourceReg, targetReg, result := commonUnaryIntOpPrologue(f, x)
		popcnt.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
		return result

	case prop.FloatAbs:
		r, result := commonUnaryFloatOpPrologue(f, x)
		opAbsFloatReg(f.M, x.Type, r)
		return result

	case prop.FloatNeg:
		r, result := commonUnaryFloatOpPrologue(f, x)
		opNegFloatReg(f.M, x.Type, r)
		return result

	case prop.FloatRoundOp:
		r, result := commonUnaryFloatOpPrologue(f, x)
		roundMode := int8(props >> 3)
		roundsSSE.opReg(&f.Text, x.Type, r, r, roundMode)
		return result

	case prop.FloatSqrt:
		r, result := commonUnaryFloatOpPrologue(f, x)
		sqrtsSSE.opFromReg(&f.Text, x.Type, r, r)
		return result
	}

	panic("unknown unary op")
}

func commonUnaryIntOpPrologue(f *gen.Func, x val.Operand) (sourceReg, targetReg reg.R, result val.Operand) {
	var ok bool

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
	return
}

func commonUnaryFloatOpPrologue(f *gen.Func, x val.Operand) (r reg.R, result val.Operand) {
	// TODO: support memory source operands

	r, _ = opMaybeResultReg(f, x, false)
	result = val.TempRegOperand(x.Type, r, false)
	return
}

// opAbsFloatReg in-place.
func opAbsFloatReg(m *module.M, t abi.Type, r reg.R) {
	absMaskAddr := rodata.MaskAddr(m.RODataAddr, rodata.Mask7fBase, t)
	andpSSE.opFromAddr(&m.Text, t, r, 0, NoIndex, absMaskAddr)
}

// opNegFloatReg in-place.
func opNegFloatReg(m *module.M, t abi.Type, r reg.R) {
	signMaskAddr := rodata.MaskAddr(m.RODataAddr, rodata.Mask80Base, t)
	xorpSSE.opFromAddr(&m.Text, t, r, 0, NoIndex, signMaskAddr)
}

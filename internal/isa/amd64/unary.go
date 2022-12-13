// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || wagamd64) && !wagarm64

package amd64

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/rodata"
	"gate.computer/wag/internal/isa/amd64/in"
	"gate.computer/wag/internal/isa/prop"
	"gate.computer/wag/wa"
)

func (MacroAssembler) Unary(f *gen.Func, props uint64, x operand.O) operand.O {
	switch props & prop.MaskUnary {
	case prop.UnaryIntEqz:
		r, _ := getScratchReg(f, x)
		in.TEST.RegReg(&f.Text, x.Type, r, r)
		f.Regs.Free(x.Type, r)
		return operand.Flags(condition.Eq)

	case prop.UnaryIntClz:
		r, _ := allocResultReg(f, x)
		if haveLZCNT {
			in.LZCNT.RegReg(&f.Text, x.Type, r, r)
		} else {
			in.BSR.RegReg(&f.Text, x.Type, RegScratch, r)
			in.MOVi.RegImm32(&f.Text, x.Type, r, -1)
			in.CMOVE.RegReg(&f.Text, x.Type, RegScratch, r)
			in.MOVi.RegImm32(&f.Text, x.Type, r, (int32(x.Size())<<3)-1)
			in.SUB.RegReg(&f.Text, x.Type, r, RegScratch)
		}
		return operand.Reg(x.Type, r)

	case prop.UnaryIntCtz:
		r, _ := allocResultReg(f, x)
		if haveTZCNT {
			in.TZCNT.RegReg(&f.Text, x.Type, r, r)
		} else {
			in.BSF.RegReg(&f.Text, x.Type, r, r)
			in.MOVi.RegImm32(&f.Text, x.Type, RegScratch, int32(x.Size())<<3)
			in.CMOVE.RegReg(&f.Text, x.Type, r, RegScratch)
		}
		return operand.Reg(x.Type, r)

	case prop.UnaryIntPopcnt:
		var r reg.R
		if havePOPCNT {
			r, _ = allocResultReg(f, x)
			in.POPCNT.RegReg(&f.Text, x.Type, r, r)
		} else {
			r = popcnt(f, x)
		}
		return operand.Reg(x.Type, r)

	case prop.UnaryFloatAbs:
		r, _ := allocResultReg(f, x)
		absFloatReg(&f.Prog, x.Type, r)
		return operand.Reg(x.Type, r)

	case prop.UnaryFloatNeg:
		r, _ := allocResultReg(f, x)
		negFloatReg(&f.Prog, x.Type, r)
		return operand.Reg(x.Type, r)

	case prop.UnaryFloatRound:
		r, _ := allocResultReg(f, x)
		roundMode := int8(props >> 8)
		in.ROUNDSx.RegRegImm8(&f.Text, x.Type, r, r, roundMode)
		return operand.Reg(x.Type, r)

	case prop.UnaryFloatSqrt:
		r, _ := allocResultReg(f, x)
		in.SQRTSx.RegReg(&f.Text, x.Type, r, r)
		return operand.Reg(x.Type, r)
	}

	panic(props)
}

// absFloatReg in-place.
func absFloatReg(p *gen.Prog, t wa.Type, r reg.R) {
	absMaskAddr := rodata.MaskAddr(rodata.Mask7fBase, t)
	in.ANDPx.RegMemDisp(&p.Text, t, r, in.BaseText, absMaskAddr)
}

// negFloatReg in-place.
func negFloatReg(p *gen.Prog, t wa.Type, r reg.R) {
	signMaskAddr := rodata.MaskAddr(rodata.Mask80Base, t)
	in.XORPx.RegMemDisp(&p.Text, t, r, in.BaseText, signMaskAddr)
}

// Population count algorithm:
//
//	func popcnt(x uint) (count int) {
//	    for count = 0; x != 0; count++ {
//	        x &= x - 1
//	    }
//	    return
//	}
func popcnt(f *gen.Func, x operand.O) (count reg.R) {
	count = f.Regs.AllocResult(x.Type)
	pop, _ := getScratchReg(f, x)
	temp := RegZero // cleared again at the end

	in.XOR.RegReg(&f.Text, wa.I32, count, count)

	in.TEST.RegReg(&f.Text, x.Type, pop, pop)
	skipJump := in.JEcb.Stub8(&f.Text)

	loopAddr := f.Text.Addr
	in.INC.Reg(&f.Text, wa.I32, count)
	in.MOV.RegReg(&f.Text, x.Type, temp, pop)
	in.DEC.Reg(&f.Text, x.Type, temp)
	in.AND.RegReg(&f.Text, x.Type, pop, temp)
	in.JNEcb.Addr8(&f.Text, loopAddr)

	linker.UpdateNearBranch(f.Text.Bytes(), skipJump)

	in.XOR.RegReg(&f.Text, wa.I32, RegZero, RegZero) // temp reg
	f.Regs.Free(x.Type, pop)
	return
}

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || wagamd64) && !wagarm64

package amd64

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/rodata"
	"gate.computer/wag/internal/isa/amd64/in"
	"gate.computer/wag/internal/isa/prop"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
)

func (MacroAssembler) Convert(f *gen.Func, props uint64, resultType wa.Type, source operand.O) operand.O {
	switch props & prop.MaskConversion {
	case prop.ConversionMote:
		r, _ := allocResultReg(f, source)
		in.CVTS2Sx.RegReg(&f.Text, source.Type, r, r)
		return operand.Reg(resultType, r)

	case prop.ConversionTruncS:
		sourceReg, _ := allocResultReg(f, source)
		resultReg := f.Regs.AllocResult(wa.I64)
		truncateSigned(f, resultType, resultReg, source.Type, sourceReg, false)
		f.Regs.Free(source.Type, sourceReg)
		return operand.Reg(resultType, resultReg)

	case prop.ConversionTruncU:
		sourceReg, _ := allocResultReg(f, source)
		resultReg := f.Regs.AllocResult(wa.I64)
		if resultType == wa.I32 {
			truncateUnsignedI32(f, resultReg, source.Type, sourceReg, false)
		} else {
			truncateUnsignedI64(f, resultReg, source.Type, sourceReg)
		}
		f.Regs.Free(source.Type, sourceReg)
		return operand.Reg(resultType, resultReg)

	case prop.ConversionConvertS:
		sourceReg, _ := getScratchReg(f, source)
		resultReg := f.Regs.AllocResult(resultType)
		in.CVTSI2Sx.TypeRegReg(&f.Text, resultType, source.Type, resultReg, sourceReg)
		f.Regs.Free(source.Type, sourceReg)
		return operand.Reg(resultType, resultReg)

	case prop.ConversionConvertU:
		sourceReg, zeroExtended := getScratchReg(f, source)
		resultReg := f.Regs.AllocResult(resultType)
		if source.Type == wa.I32 {
			if !zeroExtended {
				in.MOV.RegReg(&f.Text, wa.I32, sourceReg, sourceReg)
			}
			in.CVTSI2Sx.TypeRegReg(&f.Text, resultType, wa.I64, resultReg, sourceReg)
		} else {
			convertUnsignedI64ToFloat(f, resultType, resultReg, sourceReg)
		}
		f.Regs.Free(source.Type, sourceReg)
		return operand.Reg(resultType, resultReg)

	case prop.ConversionReinterpret:
		sourceReg, _ := getScratchReg(f, source)
		resultReg := f.Regs.AllocResult(resultType)
		if source.Type.Category() == wa.Int {
			in.MOVx.RegReg(&f.Text, source.Type, resultReg, sourceReg)
		} else {
			in.MOVxmr.RegReg(&f.Text, source.Type, sourceReg, resultReg)
		}
		f.Regs.Free(source.Type, sourceReg)
		return operand.Reg(resultType, resultReg)
	}

	panic(props)
}

func (MacroAssembler) TruncSat(f *gen.Func, props uint64, resultType wa.Type, source operand.O) operand.O {
	sourceReg, _ := allocResultReg(f, source)
	resultReg := f.Regs.AllocResult(wa.I64)

	if props == prop.TruncS {
		truncateSigned(f, resultType, resultReg, source.Type, sourceReg, true)
	} else if resultType == wa.I32 {
		truncateUnsignedI32(f, resultReg, source.Type, sourceReg, true)
	} else {
		truncateUnsignedI64Sat(f, resultReg, source.Type, sourceReg)
	}

	f.Regs.Free(source.Type, sourceReg)
	return operand.Reg(resultType, resultReg)
}

// Algorithm (non-saturating version):
//
//	target_i = Convert(source_f)
//	if target_i == MinInt {
//	    if &source_f != &RegResult_f {
//	        RegResult_f = source_f
//	    }
//	    TrapTruncOverflow()
//	}
func truncateSigned(f *gen.Func, targetType wa.Type, target reg.R, sourceType wa.Type, source reg.R, saturate bool) {
	in.CVTTSx2SI.TypeRegReg(&f.Text, sourceType, targetType, target, source)

	// Target is the smallest negative integer if source is invalid; see if
	// target-1 underflows.
	in.CMPi.RegImm8(&f.Text, targetType, target, 1)
	jumpUnlessMagicValue := in.JNOcb.Stub8(&f.Text)

	if saturate {
		in.MOVx.RegReg(&f.Text, sourceType, RegScratch, RegZero)
		in.UCOMISx.RegReg(&f.Text, sourceType, source, RegScratch)
		jumpIfNaN := in.JPcb.Stub8(&f.Text)
		jumpIfBelow := in.JBcb.Stub8(&f.Text)
		in.MOV64i.RegImm64(&f.Text, target, (1<<(targetType.Size()*8-1) - 1)) // Max value.
		jumpIfAbove := in.JAcb.Stub8(&f.Text)

		linker.UpdateNearBranch(f.Text.Bytes(), jumpIfNaN)
		in.MOV.RegReg(&f.Text, targetType, target, RegZero)

		linker.UpdateNearBranch(f.Text.Bytes(), jumpIfAbove)
		linker.UpdateNearBranch(f.Text.Bytes(), jumpIfBelow)
	} else {
		if source != RegResult {
			// Trap handler expects conversion input value in result register.
			in.MOVAPx.RegReg(&f.Text, sourceType, RegResult, source)
		}
		in.CALLcd.Addr32(&f.Text, f.TrapLinkTruncOverflow[int(sourceType>>2)&2|int(targetType>>3)].Addr)
		f.MapCallAddr(f.Text.Addr)
	}

	linker.UpdateNearBranch(f.Text.Bytes(), jumpUnlessMagicValue)
}

// Algorithm (non-saturating version):
//
//	target_i = ConvertToI64(source_f)
//	if target_i < 0 || target_i > MaxUint32 {
//	    Trap()
//	}
func truncateUnsignedI32(f *gen.Func, target reg.R, sourceType wa.Type, source reg.R, saturate bool) {
	in.CVTTSx2SI.TypeRegReg(&f.Text, sourceType, wa.I64, target, source)

	// Some high bits are set if the target is negative or the magic value.
	in.MOV.RegReg(&f.Text, wa.I64, RegScratch, target)
	in.SHRi.RegImm8(&f.Text, wa.I64, RegScratch, 32)
	jumpIfZero := in.JEcb.Stub8(&f.Text)

	if saturate {
		in.MOVx.RegReg(&f.Text, sourceType, RegScratch, RegZero)
		in.UCOMISx.RegReg(&f.Text, sourceType, source, RegScratch)
		jumpIfNaN := in.JPcb.Stub8(&f.Text)
		jumpIfBelow := in.JBcb.Stub8(&f.Text)

		in.MOVi.RegImm32(&f.Text, wa.I32, target, -1) // Max value.
		jumpDone := in.JMPcb.Stub8(&f.Text)

		linker.UpdateNearBranch(f.Text.Bytes(), jumpIfBelow)
		linker.UpdateNearBranch(f.Text.Bytes(), jumpIfNaN)
		in.MOV.RegReg(&f.Text, wa.I32, target, RegZero)

		linker.UpdateNearBranch(f.Text.Bytes(), jumpDone)
	} else {
		asm.Trap(f, trap.IntegerOverflow)
	}

	linker.UpdateNearBranch(f.Text.Bytes(), jumpIfZero)
}

// Algorithm:
//
//	if source_f < ConvertToFloat(MaxInt64+1) {
//	    target_i = ConvertToI64(source_f)
//	    if target_i < 0 {
//	        Trap()
//	    }
//	} else {
//	    target_i = ConvertToI64(source_f - ConvertToFloat(MaxInt64+1))
//	    if target_i < 0 {
//	        Trap()
//	    }
//	    target_i = target_i ^ (MaxInt64+1)
//	}
func truncateUnsignedI64(f *gen.Func, target reg.R, sourceType wa.Type, source reg.R) {
	intRangeAsFloat := rodata.MaskAddr(rodata.MaskTruncBase, sourceType)

	// if source_f < ConvertToFloat(MaxInt64+1)
	in.UCOMISx.RegMemDisp(&f.Text, sourceType, source, in.BaseText, intRangeAsFloat)
	jumpIfAboveOrEqual := in.JAEcb.Stub8(&f.Text)

	// if source_f < ConvertToFloat(MaxInt64+1)
	// target_i = ConvertToI64(source_f)
	// if target_i < 0
	in.CVTTSx2SI.TypeRegReg(&f.Text, sourceType, wa.I64, target, source)
	in.TEST.RegReg(&f.Text, wa.I64, target, target)
	jumpIfNonNegative := in.JGEcb.Stub8(&f.Text)

	// Trap()
	trapAddr := f.Text.Addr
	asm.Trap(f, trap.IntegerOverflow)

	// else
	linker.UpdateNearBranch(f.Text.Bytes(), jumpIfAboveOrEqual)

	// target_i = ConvertToI64(source_f - ConvertToFloat(MaxInt64+1))
	// if target_i < 0
	in.SUBSx.RegMemDisp(&f.Text, sourceType, source, in.BaseText, intRangeAsFloat)
	in.CVTTSx2SI.TypeRegReg(&f.Text, sourceType, wa.I64, target, source)
	in.TEST.RegReg(&f.Text, wa.I64, target, target)

	// Trap()
	in.JLcb.Addr8(&f.Text, trapAddr)

	// target_i = target_i ^ (MaxInt64+1)
	in.MOV.RegMemDisp(&f.Text, wa.I64, RegScratch, in.BaseText, rodata.Mask80Addr64)
	in.XOR.RegReg(&f.Text, wa.I64, target, RegScratch)

	// endif
	linker.UpdateNearBranch(f.Text.Bytes(), jumpIfNonNegative)
}

// Algorithm:
//
//	target_i = 0
//	if !(IsNaN(source_f) || source_f < 0) {
//	    if source_f < ConvertToFloat(MaxInt64+1) {
//	        target_i = ConvertToI64(source_f)
//	    } else {
//	        target_i = MaxUint64
//	        scratch_f = source_f - ConvertToFloat(MaxInt64+1)
//	        if scratch_f < ConvertToFloat(MaxInt64+1) {
//	            target_i = ConvertToI64(scratch_f)
//	            target_i = target_i ^ (MaxInt64+1)
//	        }
//	    }
//	}
func truncateUnsignedI64Sat(f *gen.Func, target reg.R, sourceType wa.Type, source reg.R) {
	intRangeAsFloat := rodata.MaskAddr(rodata.MaskTruncBase, sourceType)

	// target_i = 0
	in.MOV.RegReg(&f.Text, wa.I64, target, RegZero)

	// if !(IsNaN(source_f) || source_f < 0)
	in.MOVx.RegReg(&f.Text, sourceType, RegScratch, RegZero)
	in.UCOMISx.RegReg(&f.Text, sourceType, source, RegScratch)
	jumpIfNaN := in.JPcb.Stub8(&f.Text)
	jumpIfLE := in.JBEcb.Stub8(&f.Text)

	// if source_f < ConvertToFloat(MaxInt64+1)
	in.UCOMISx.RegMemDisp(&f.Text, sourceType, source, in.BaseText, intRangeAsFloat)
	jumpToElse := in.JAEcb.Stub8(&f.Text)

	// target_i = ConvertToI64(source_f)
	in.CVTTSx2SI.TypeRegReg(&f.Text, sourceType, wa.I64, target, source)
	jumpToEnd := in.JMPcb.Stub8(&f.Text)

	// else
	linker.UpdateNearBranch(f.Text.Bytes(), jumpToElse)

	// target_i = MaxUint64
	in.DEC.Reg(&f.Text, wa.I64, target)

	// scratch_f = source_f - ConvertToFloat(MaxInt64+1)
	in.MOVAPx.RegReg(&f.Text, sourceType, RegScratch, source)
	in.SUBSx.RegMemDisp(&f.Text, sourceType, RegScratch, in.BaseText, intRangeAsFloat)

	// if scratch_f < ConvertToFloat(MaxInt64+1)
	in.UCOMISx.RegMemDisp(&f.Text, sourceType, RegScratch, in.BaseText, intRangeAsFloat)
	jumpIfGE := in.JAEcb.Stub8(&f.Text)

	// target_i = ConvertToI64(scratch_f)
	in.CVTTSx2SI.TypeRegReg(&f.Text, sourceType, wa.I64, target, RegScratch)

	// target_i = target_i ^ (MaxInt64+1)
	in.MOV.RegMemDisp(&f.Text, wa.I64, RegScratch, in.BaseText, rodata.Mask80Addr64)
	in.XOR.RegReg(&f.Text, wa.I64, target, RegScratch)

	// endif
	linker.UpdateNearBranch(f.Text.Bytes(), jumpIfGE)
	linker.UpdateNearBranch(f.Text.Bytes(), jumpToEnd)
	linker.UpdateNearBranch(f.Text.Bytes(), jumpIfLE)
	linker.UpdateNearBranch(f.Text.Bytes(), jumpIfNaN)
}

func convertUnsignedI64ToFloat(f *gen.Func, targetType wa.Type, target, source reg.R) {
	// This algorithm is copied from code generated by gcc and clang:

	in.TEST.RegReg(&f.Text, wa.I64, source, source)
	hugeJump := in.JScb.Stub8(&f.Text)

	// max. 63-bit value
	in.CVTSI2Sx.TypeRegReg(&f.Text, targetType, wa.I64, target, source)

	doneJump := in.JMPcb.Stub8(&f.Text)

	linker.UpdateNearBranch(f.Text.Bytes(), hugeJump)

	// 64-bit value
	in.MOV.RegReg(&f.Text, wa.I64, RegScratch, source)
	in.ANDi.RegImm8(&f.Text, wa.I64, RegScratch, 1)
	in.SHRi.RegImm8(&f.Text, wa.I64, source, 1)
	in.OR.RegReg(&f.Text, wa.I64, source, RegScratch)
	in.CVTSI2Sx.TypeRegReg(&f.Text, targetType, wa.I64, target, source)
	in.ADDSx.RegReg(&f.Text, targetType, target, target)

	linker.UpdateNearBranch(f.Text.Bytes(), doneJump)
}

func (MacroAssembler) Extend(f *gen.Func, props uint32, resultType wa.Type, source operand.O) operand.O {
	r, zeroExtended := allocResultReg(f, source)

	switch props {
	case prop.ExtensionMOVSX8:
		in.MOVSX8.RegReg(&f.Text, resultType, r, r)

	case prop.ExtensionMOVSX16:
		in.MOVSX16.RegReg(&f.Text, resultType, r, r)

	case prop.ExtensionMOVSXD:
		in.MOVSXD.RegReg(&f.Text, resultType, r, r)

	default:
		if !zeroExtended {
			in.MOV.RegReg(&f.Text, wa.I32, r, r)
		}
	}

	return operand.Reg(resultType, r)
}

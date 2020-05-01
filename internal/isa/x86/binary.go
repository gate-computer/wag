// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/prop"
	"github.com/tsavola/wag/internal/isa/x86/in"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

func (MacroAssembler) Binary(f *gen.Func, props uint16, a, b operand.O) operand.O {
	return ops[props&prop.BinaryMask](f, uint8(props>>8), a, b)
}

var ops = [prop.BinaryMask + 1]func(*gen.Func, uint8, operand.O, operand.O) operand.O{
	prop.BinaryIntALAdd:      binaryIntALAdd,
	prop.BinaryIntALSub:      binaryIntALSub,
	prop.BinaryIntAL:         binaryIntAL,
	prop.BinaryIntCmp:        binaryIntCmp,
	prop.BinaryIntMul:        binaryIntMul,
	prop.BinaryIntDivU:       binaryIntDivU,
	prop.BinaryIntDivS:       binaryIntDivS,
	prop.BinaryIntRemU:       binaryIntRemU,
	prop.BinaryIntRemS:       binaryIntRemS,
	prop.BinaryIntShift:      binaryIntShift,
	prop.BinaryFloatCommon:   binaryFloatCommon,
	prop.BinaryFloatMinmax:   binaryFloatMinmax,
	prop.BinaryFloatCmp:      binaryFloatCmp,
	prop.BinaryFloatCopysign: binaryFloatCopysign,
}

func binaryIntALAdd(f *gen.Func, index uint8, a, b operand.O) operand.O {
	switch {
	case b.Storage == storage.Imm && b.ImmValue() == 1:
		return opInplaceInt(f, in.INC, a)

	default:
		return binaryIntAL(f, index, a, b)
	}
}

func binaryIntALSub(f *gen.Func, index uint8, a, b operand.O) operand.O {
	switch {
	case b.Storage == storage.Imm && b.ImmValue() == 1:
		return opInplaceInt(f, in.DEC, a)

	case a.Storage == storage.Imm && a.ImmValue() == 0:
		r, _ := allocResultReg(f, b)
		in.NEG.Reg(&f.Text, b.Type, r)
		return operand.Reg(b.Type, r)

	default:
		return binaryIntAL(f, index, a, b)
	}
}

func binaryIntAL(f *gen.Func, index uint8, a, b operand.O) operand.O {
	insn := in.ALInsn(index)

	switch b.Storage {
	case storage.Imm:
		if value := b.ImmValue(); uint64(value+0x80000000) > 0xffffffff {
			in.MOV64i.RegImm64(&f.Text, RegScratch, value)
			b.SetReg(RegScratch)
		}

	case storage.Stack:
		in.POPo.RegScratch(&f.Text)
		f.StackValueConsumed()
		b.SetReg(RegScratch)
	}

	targetReg, _ := allocResultReg(f, a)

	switch b.Storage {
	case storage.Imm: // large values moved to registers earlier
		insn.OpcodeI().RegImm(&f.Text, a.Type, targetReg, int32(b.ImmValue()))

	default: // Reg
		insn.Opcode().RegReg(&f.Text, a.Type, targetReg, b.Reg())
		f.Regs.Free(b.Type, b.Reg())
	}

	return operand.Reg(a.Type, targetReg)
}

func binaryIntCmp(f *gen.Func, cond uint8, a, b operand.O) operand.O {
	if b.Storage == storage.Stack {
		// Since b is in stack, a must also be.  We must pop b before a.
		in.POPo.RegScratch(&f.Text)
		f.StackValueConsumed()
		in.POPo.RegScratch(&f.Text)
		f.StackValueConsumed()
		in.CMP.RegReg(&f.Text, a.Type, RegResult, RegScratch)
	} else {
		// We know b isn't in stack, so we can reverse access order.
		asm.Move(f, RegResult, a)

		switch {
		case b.Storage == storage.Imm && uint64(b.ImmValue()+0x80000000) <= 0xffffffff:
			in.CMPi.RegImm(&f.Text, a.Type, RegResult, int32(b.ImmValue()))

		case b.Storage == storage.Reg:
			in.CMP.RegReg(&f.Text, a.Type, RegResult, b.Reg())
			f.Regs.Free(b.Type, b.Reg())

		default: // stack or large immediate
			asm.Move(f, RegScratch, b)
			in.CMP.RegReg(&f.Text, a.Type, RegResult, RegScratch)
		}
	}

	return operand.Flags(condition.C(cond))
}

func binaryIntMul(f *gen.Func, _ uint8, a, b operand.O) operand.O {
	targetReg, _ := allocResultReg(f, a)

	var sourceReg reg.R

	if b.Storage == storage.Imm {
		value := b.ImmValue()

		if uint64(value+0x80000000) <= 0xffffffff {
			in.IMULi.RegRegImm(&f.Text, a.Type, targetReg, targetReg, int32(value))
			return operand.Reg(a.Type, targetReg)
		}

		in.MOV64i.RegImm64(&f.Text, RegScratch, value)
		sourceReg = RegScratch
	} else {
		sourceReg, _ = getScratchReg(f, b)
	}

	in.IMUL.RegReg(&f.Text, a.Type, targetReg, sourceReg)
	f.Regs.Free(b.Type, sourceReg)

	return operand.Reg(a.Type, targetReg)
}

func binaryIntDivU(f *gen.Func, _ uint8, a, b operand.O) operand.O {
	divisorReg := opPrepareDiv(f, a, b)

	// RegDividendHigh is RegZero.
	in.DIV.Reg(&f.Text, b.Type, divisorReg)
	f.Regs.Free(b.Type, divisorReg)

	in.XOR.RegReg(&f.Text, wa.I32, RegZero, RegZero)
	return operand.Reg(a.Type, RegResult)
}

func binaryIntRemU(f *gen.Func, _ uint8, a, b operand.O) operand.O {
	divisorReg := opPrepareDiv(f, a, b)

	// RegDividendHigh is RegZero.
	in.DIV.Reg(&f.Text, b.Type, divisorReg)
	f.Regs.Free(b.Type, divisorReg)

	resultReg := f.Regs.AllocResult(a.Type)
	in.MOV.RegReg(&f.Text, a.Type, resultReg, RegDividendHigh) // Remainder

	in.XOR.RegReg(&f.Text, wa.I32, RegZero, RegZero)
	return operand.Reg(a.Type, resultReg)
}

func binaryIntDivS(f *gen.Func, _ uint8, a, b operand.O) operand.O {
	divisorReg := opPrepareDiv(f, a, b)

	if a.Type == wa.I32 {
		in.CMPi.RegImm32(&f.Text, a.Type, RegDividendLow, -0x80000000)
	} else {
		in.CMP.RegMemDisp(&f.Text, a.Type, RegDividendLow, in.BaseText, rodata.Mask80Addr64)
	}
	skip1 := in.JNEcb.Stub8(&f.Text)

	in.CMPi.RegImm8(&f.Text, b.Type, divisorReg, -1)
	skip2 := in.JNEcb.Stub8(&f.Text)

	asm.Trap(f, trap.IntegerOverflow)

	text := f.Text.Bytes()
	linker.UpdateNearBranch(text, skip1)
	linker.UpdateNearBranch(text, skip2)

	in.CDQ.Type(&f.Text, a.Type) // Sign-extend dividend low bits to high bits.
	in.IDIV.Reg(&f.Text, b.Type, divisorReg)
	f.Regs.Free(b.Type, divisorReg)

	in.XOR.RegReg(&f.Text, wa.I32, RegZero, RegZero)
	return operand.Reg(a.Type, RegResult)
}

func binaryIntRemS(f *gen.Func, _ uint8, a, b operand.O) operand.O {
	divisorReg := opPrepareDiv(f, a, b)

	// RegDividendHigh (remainer) is RegZero, so correct result is already in
	// place if the division is skipped.
	in.CMPi.RegImm8(&f.Text, b.Type, divisorReg, -1)
	skip := in.JEcb.Stub8(&f.Text)

	in.CDQ.Type(&f.Text, a.Type) // Sign-extend dividend low bits to high bits.
	in.IDIV.Reg(&f.Text, b.Type, divisorReg)

	linker.UpdateNearBranch(f.Text.Bytes(), skip)

	f.Regs.Free(b.Type, divisorReg)

	resultReg := f.Regs.AllocResult(a.Type)
	in.MOV.RegReg(&f.Text, a.Type, resultReg, RegDividendHigh) // Remainder

	in.XOR.RegReg(&f.Text, wa.I32, RegZero, RegZero)
	return operand.Reg(a.Type, resultReg)
}

func opPrepareDiv(f *gen.Func, a, b operand.O) (divisorReg reg.R) {
	if b.Storage == storage.Reg {
		if b.Reg() == RegDividendLow {
			in.MOV.RegReg(&f.Text, b.Type, RegScratch, RegDividendLow)
			divisorReg = RegScratch
		} else {
			divisorReg = b.Reg()
		}
	} else {
		asm.Move(f, RegScratch, b)
		divisorReg = RegScratch
	}

	in.TEST.RegReg(&f.Text, b.Type, divisorReg, divisorReg)
	in.JNEcb.Rel8(&f.Text, in.CALLcd.Size()) // Skip next instruction.
	asm.Trap(f, trap.IntegerDivideByZero)

	asm.Move(f, RegDividendLow, a)
	return
}

func binaryIntShift(f *gen.Func, index uint8, a, b operand.O) operand.O {
	insn := in.ShiftInsn(index)
	r, _ := allocResultReg(f, a)

	if b.Storage == storage.Imm {
		insn.OpcodeI().RegImm8(&f.Text, a.Type, r, b.ImmValue8())
	} else {
		b.Type = wa.I32
		asm.Move(f, RegCount, b)
		insn.Opcode().Reg(&f.Text, a.Type, r)
	}

	return operand.Reg(a.Type, r)
}

func binaryFloatCommon(f *gen.Func, index uint8, a, b operand.O) operand.O {
	opcode := in.RMscalar(index)
	targetReg, _ := allocResultReg(f, a)
	sourceReg, _ := getScratchReg(f, b)

	opcode.RegReg(&f.Text, a.Type, targetReg, sourceReg)

	f.Regs.Free(b.Type, sourceReg)
	return operand.Reg(a.Type, targetReg)
}

var binaryFloatMinmaxOpcodes = [2]struct {
	common in.RMscalar
	zero   in.RMpacked
}{
	prop.IndexMinmaxMin: {in.MINSx, in.ORPx},
	prop.IndexMinmaxMax: {in.MAXSx, in.ANDPx},
}

func binaryFloatMinmax(f *gen.Func, index uint8, a, b operand.O) operand.O {
	opcodes := binaryFloatMinmaxOpcodes[index]
	targetReg, _ := allocResultReg(f, a)
	sourceReg, _ := getScratchReg(f, b)

	in.UCOMISx.RegReg(&f.Text, a.Type, targetReg, sourceReg)
	commonJump := in.JNEcb.Stub8(&f.Text)

	opcodes.zero.RegReg(&f.Text, a.Type, targetReg, sourceReg)
	endJump := in.JMPcb.Stub8(&f.Text)

	linker.UpdateNearBranch(f.Text.Bytes(), commonJump)

	opcodes.common.RegReg(&f.Text, a.Type, targetReg, sourceReg)

	linker.UpdateNearBranch(f.Text.Bytes(), endJump)

	f.Regs.Free(b.Type, sourceReg)
	return operand.Reg(a.Type, targetReg)
}

func binaryFloatCmp(f *gen.Func, cond uint8, a, b operand.O) operand.O {
	aReg, _ := allocResultReg(f, a)
	bReg, _ := getScratchReg(f, b)

	in.UCOMISx.RegReg(&f.Text, a.Type, aReg, bReg)

	f.Regs.Free2(a.Type, aReg, bReg)
	return operand.Flags(condition.C(cond))
}

func binaryFloatCopysign(f *gen.Func, _ uint8, a, b operand.O) operand.O {
	targetReg, _ := allocResultReg(f, a)
	sourceReg, _ := getScratchReg(f, b)

	signMaskAddr := rodata.MaskAddr(rodata.Mask80Base, a.Type)

	in.MOVxmr.RegReg(&f.Text, a.Type, sourceReg, RegScratch) // int <- float
	in.AND.RegMemDisp(&f.Text, a.Type, RegScratch, in.BaseText, signMaskAddr)
	in.MOVxmr.RegReg(&f.Text, a.Type, targetReg, RegResult) // int <- float
	in.AND.RegMemDisp(&f.Text, a.Type, RegResult, in.BaseText, signMaskAddr)
	in.CMP.RegReg(&f.Text, a.Type, RegResult, RegScratch)
	doneJump := in.JEcb.Stub8(&f.Text)

	negFloatReg(&f.Prog, a.Type, targetReg)

	linker.UpdateNearBranch(f.Text.Bytes(), doneJump)

	f.Regs.Free(b.Type, sourceReg)
	return operand.Reg(a.Type, targetReg)
}

// opInplaceInt allocates registers.
func opInplaceInt(f *gen.Func, insn in.M, x operand.O) operand.O {
	r, _ := allocResultReg(f, x)
	insn.Reg(&f.Text, x.Type, r)
	return operand.Reg(x.Type, r)
}

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
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/isa/amd64/in"
	"gate.computer/wag/internal/isa/prop"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
)

func (MacroAssembler) Binary(f *gen.Func, props uint64, a, b operand.O) operand.O {
	switch props & prop.MaskBinary {
	case prop.BinaryIntALSub:
		if a.Storage == storage.Imm && a.ImmValue() == 0 {
			r, _ := allocResultReg(f, b)
			in.NEG.Reg(&f.Text, b.Type, r)
			return operand.Reg(b.Type, r)
		}

		fallthrough

	case prop.BinaryIntALAddsub:
		if b.Storage == storage.Imm && b.ImmValue() == 1 {
			r, _ := allocResultReg(f, a)
			in.M(props>>16).Reg(&f.Text, a.Type, r)
			return operand.Reg(a.Type, r)
		}

		fallthrough

	case prop.BinaryIntAL:
		insn := in.ALInsn(props >> 8)

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
		case storage.Imm: // Large values moved to registers earlier.
			insn.OpcodeI().RegImm(&f.Text, a.Type, targetReg, int32(b.ImmValue()))

		default: // Register
			insn.Opcode().RegReg(&f.Text, a.Type, targetReg, b.Reg())
			f.Regs.Free(b.Type, b.Reg())
		}

		return operand.Reg(a.Type, targetReg)

	case prop.BinaryIntCmp:
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

			default: // Stack or large immediate.
				asm.Move(f, RegScratch, b)
				in.CMP.RegReg(&f.Text, a.Type, RegResult, RegScratch)
			}
		}

		return operand.Flags(condition.C(props >> 8))

	case prop.BinaryIntMul:
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

	case prop.BinaryIntDivU:
		divisorReg := opPrepareDiv(f, a, b)

		// RegDividendHigh is RegZero.
		in.DIV.Reg(&f.Text, b.Type, divisorReg)
		f.Regs.Free(b.Type, divisorReg)

		in.XOR.RegReg(&f.Text, wa.I32, RegZero, RegZero)
		return operand.Reg(a.Type, RegResult)

	case prop.BinaryIntDivS:
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

	case prop.BinaryIntRemU:
		divisorReg := opPrepareDiv(f, a, b)

		// RegDividendHigh is RegZero.
		in.DIV.Reg(&f.Text, b.Type, divisorReg)
		f.Regs.Free(b.Type, divisorReg)

		resultReg := f.Regs.AllocResult(a.Type)
		in.MOV.RegReg(&f.Text, a.Type, resultReg, RegDividendHigh) // Remainder

		in.XOR.RegReg(&f.Text, wa.I32, RegZero, RegZero)
		return operand.Reg(a.Type, resultReg)

	case prop.BinaryIntRemS:
		divisorReg := opPrepareDiv(f, a, b)

		// RegDividendHigh (remainer) is RegZero, so correct result is already
		// in place if the division is skipped.
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

	case prop.BinaryIntShift:
		insn := in.ShiftInsn(props >> 8)
		r, _ := allocResultReg(f, a)

		if b.Storage == storage.Imm {
			insn.OpcodeI().RegImm8(&f.Text, a.Type, r, b.ImmValue8())
		} else {
			b.Type = wa.I32
			asm.Move(f, RegCount, b)
			insn.Opcode().Reg(&f.Text, a.Type, r)
		}

		return operand.Reg(a.Type, r)

	case prop.BinaryFloatCommon:
		targetReg, _ := allocResultReg(f, a)
		sourceReg, _ := getScratchReg(f, b)

		in.RMscalar(props>>8).RegReg(&f.Text, a.Type, targetReg, sourceReg)

		f.Regs.Free(b.Type, sourceReg)
		return operand.Reg(a.Type, targetReg)

	case prop.BinaryFloatMinmax:
		// TODO: Intel says that this behavior can be accomplished "using a
		//       sequence of instructions, such as, a comparison followed by
		//       AND, ANDN and OR."

		targetReg, _ := allocResultReg(f, a)
		sourceReg, _ := getScratchReg(f, b)

		var endJumps [2]int32

		in.UCOMISx.RegReg(&f.Text, a.Type, targetReg, targetReg)
		endJumps[0] = in.JPcb.Stub8(&f.Text)
		in.UCOMISx.RegReg(&f.Text, a.Type, sourceReg, sourceReg)
		takeSourceJump := in.JPcb.Stub8(&f.Text)
		in.RMscalar(props>>8).RegReg(&f.Text, a.Type, targetReg, sourceReg)
		endJumps[1] = in.JMPcb.Stub8(&f.Text)

		linker.UpdateNearBranch(f.Text.Bytes(), takeSourceJump)

		in.MOVAPx.RegReg(&f.Text, a.Type, targetReg, sourceReg)

		linker.UpdateNearBranches(f.Text.Bytes(), endJumps[:])

		f.Regs.Free(b.Type, sourceReg)
		return operand.Reg(a.Type, targetReg)

	case prop.BinaryFloatCmp:
		aReg, _ := allocResultReg(f, a)
		bReg, _ := getScratchReg(f, b)

		in.UCOMISx.RegReg(&f.Text, a.Type, aReg, bReg)

		f.Regs.Free2(a.Type, aReg, bReg)
		return operand.Flags(condition.C(props >> 8))

	case prop.BinaryFloatCopysign:
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

	panic(props)
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

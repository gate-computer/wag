// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/prop"
	"github.com/tsavola/wag/internal/isa/x86/in"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

// Binary may allocate registers, use RegResult and update condition flags.
func (MacroAssembler) Binary(f *gen.Func, props uint16, a, b operand.O) operand.O {
	switch uint8(props) {
	case prop.BinaryIntAL:
		return binaryIntAL(f, uint8(props>>8), a, b)

	case prop.BinaryIntCmp:
		return binaryIntCmp(f, uint8(props>>8), a, b)

	case prop.BinaryIntDivmul:
		return binaryIntDivmul(f, uint8(props>>8), a, b)

	case prop.BinaryIntShift:
		return binaryIntShift(f, uint8(props>>8), a, b)

	case prop.BinaryFloatCommon:
		return binaryFloatCommon(f, uint8(props>>8), a, b)

	case prop.BinaryFloatMinmax:
		return binaryFloatMinmax(f, uint8(props>>8), a, b)

	case prop.BinaryFloatCmp:
		return binaryFloatCmp(f, uint8(props>>8), a, b)

	default:
		return binaryFloatCopysign(f, a, b)
	}
}

func binaryIntAL(f *gen.Func, index uint8, a, b operand.O) operand.O {
	insn := in.ALInsn(index)

	if insn == in.InsnSub && a.Storage == storage.Imm && a.ImmValue() == 0 {
		return opNegInt(f, b)
	}

	switch b.Storage {
	case storage.Imm:
		switch value := b.ImmValue(); {
		case value == 1:
			switch insn {
			case in.InsnAdd:
				return opInplaceInt(f, in.INC, a)

			case in.InsnSub:
				return opInplaceInt(f, in.DEC, a)
			}

		case uint64(value+0x80000000) > 0xffffffff:
			in.MOV64i.RegImm64(&f.Text, RegScratch, value)
			b.SetReg(RegScratch, true)
		}

	case storage.Stack:
		in.POPo.RegScratch(&f.Text)
		f.StackValueConsumed()
		b.SetReg(RegScratch, false)
	}

	targetReg, _ := allocResultReg(f, a)

	switch b.Storage {
	case storage.Imm: // large values moved to registers earlier
		insn.OpcodeI().RegImm(&f.Text, a.Type, targetReg, int32(b.ImmValue()))

	default: // Reg
		insn.Opcode().RegReg(&f.Text, a.Type, targetReg, b.Reg())
		f.Regs.Free(b.Type, b.Reg())
	}

	return operand.Reg(a.Type, targetReg, true)
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

func binaryIntDivmul(f *gen.Func, index uint8, a, b operand.O) operand.O {
	var (
		insn      = in.DivmulInsn(index) & prop.DivmulInsnMask
		remainder = (index & prop.DivmulRemFlag) != 0
		division  = insn != in.InsnMul
	)

	checkZero := true
	checkOverflow := true

	if b.Storage == storage.Reg {
		if b.Reg() == RegDividendLow {
			in.MOV.RegReg(&f.Text, b.Type, RegScratch, RegDividendLow)
			b.SetReg(RegScratch, true)
		}
	} else {
		if division && b.Storage == storage.Imm {
			value := b.ImmValue()
			if value != 0 {
				checkZero = false
			}
			if value != -1 {
				checkOverflow = false
			}
		}

		zeroExt := asm.Move(f, RegScratch, b)
		b.SetReg(RegScratch, zeroExt)
	}

	asm.Move(f, RegDividendLow, a)

	var doNot link.L

	if division {
		if checkZero {
			opCheckDivideByZero(f, b.Type, b.Reg())
		}

		if a.Storage == storage.Imm {
			value := a.ImmValue()
			if a.Type == wa.I32 {
				if value != -0x80000000 {
					checkOverflow = false
				}
			} else {
				if value != -0x8000000000000000 {
					checkOverflow = false
				}
			}
		}

		signed := (insn == in.InsnDivS)

		if signed && checkOverflow {
			var do link.L

			if remainder {
				in.CMPi.RegImm8(&f.Text, b.Type, b.Reg(), -1)
				in.JEcb.Stub8(&f.Text)
				doNot.AddSite(f.Text.Addr)
			} else {
				if a.Type == wa.I32 {
					in.CMPi.RegImm32(&f.Text, a.Type, RegDividendLow, -0x80000000)
				} else {
					in.CMP.RegMemDisp(&f.Text, a.Type, RegDividendLow, in.BaseZero, f.RODataAddr+rodata.Mask80Addr64)
				}

				in.JNEcb.Stub8(&f.Text)
				do.AddSite(f.Text.Addr)

				in.CMPi.RegImm8(&f.Text, b.Type, b.Reg(), -1)
				in.JNEcb.Stub8(&f.Text)
				do.AddSite(f.Text.Addr)

				asm.Trap(f, trap.IntegerOverflow)
			}

			do.Addr = f.Text.Addr
			isa.UpdateNearBranches(f.Text.Bytes(), &do)
		}

		if signed {
			// Sign-extend dividend low bits to high bits
			in.CDQ.Type(&f.Text, a.Type)
		} else {
			// RegDividendHigh is zero by default
		}
	}

	insn.Opcode().Reg(&f.Text, b.Type, b.Reg())
	f.Regs.Free(b.Type, b.Reg())

	doNot.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &doNot)

	if remainder {
		in.MOV.RegReg(&f.Text, a.Type, RegResult, RegDividendHigh)
	}

	in.XOR.RegReg(&f.Text, wa.I32, RegZero, RegZero)

	return operand.Reg(a.Type, RegResult, true)
}

func opCheckDivideByZero(f *gen.Func, t wa.Type, r reg.R) {
	var end link.L

	in.TEST.RegReg(&f.Text, t, r, r)
	in.JNEcb.Stub8(&f.Text)
	end.AddSite(f.Text.Addr)

	asm.Trap(f, trap.IntegerDivideByZero)

	end.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &end)
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

	return operand.Reg(a.Type, r, true)
}

func binaryFloatCommon(f *gen.Func, index uint8, a, b operand.O) operand.O {
	opcode := in.RMscalar(index)
	targetReg, _ := allocResultReg(f, a)
	sourceReg, _ := getScratchReg(f, b)

	opcode.RegReg(&f.Text, a.Type, targetReg, sourceReg)

	f.Regs.Free(b.Type, sourceReg)
	return operand.Reg(a.Type, targetReg, false)
}

var binaryFloatMinmaxOpcodes = [2]struct {
	common in.RMscalar
	zero   in.RMpacked
}{
	prop.IndexMinmaxMin: {in.MINSSD, in.ORPSD},
	prop.IndexMinmaxMax: {in.MAXSSD, in.ANDPSD},
}

func binaryFloatMinmax(f *gen.Func, index uint8, a, b operand.O) operand.O {
	opcodes := binaryFloatMinmaxOpcodes[index]
	targetReg, _ := allocResultReg(f, a)
	sourceReg, _ := getScratchReg(f, b)

	var common link.L
	var end link.L

	in.UCOMISSD.RegReg(&f.Text, a.Type, targetReg, sourceReg)
	in.JNEcb.Stub8(&f.Text)
	common.AddSite(f.Text.Addr)

	opcodes.zero.RegReg(&f.Text, a.Type, targetReg, sourceReg)
	in.JMPcb.Stub8(&f.Text)
	end.AddSite(f.Text.Addr)

	common.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &common)

	opcodes.common.RegReg(&f.Text, a.Type, targetReg, sourceReg)

	end.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &end)

	f.Regs.Free(b.Type, sourceReg)
	return operand.Reg(a.Type, targetReg, false)
}

func binaryFloatCmp(f *gen.Func, cond uint8, a, b operand.O) operand.O {
	aReg, _ := allocResultReg(f, a)
	bReg, _ := getScratchReg(f, b)

	in.UCOMISSD.RegReg(&f.Text, a.Type, aReg, bReg)

	f.Regs.Free(b.Type, bReg)
	f.Regs.Free(a.Type, aReg)
	return operand.Flags(condition.C(cond))
}

func binaryFloatCopysign(f *gen.Func, a, b operand.O) operand.O {
	targetReg, _ := allocResultReg(f, a)
	sourceReg, _ := getScratchReg(f, b)

	var done link.L

	signMaskAddr := rodata.MaskAddr(f.RODataAddr, rodata.Mask80Base, a.Type)

	in.MOVDQmr.RegReg(&f.Text, a.Type, sourceReg, RegScratch) // int <- float
	in.AND.RegMemDisp(&f.Text, a.Type, RegScratch, in.BaseZero, signMaskAddr)
	in.MOVDQmr.RegReg(&f.Text, a.Type, targetReg, RegResult) // int <- float
	in.AND.RegMemDisp(&f.Text, a.Type, RegResult, in.BaseZero, signMaskAddr)
	in.CMP.RegReg(&f.Text, a.Type, RegResult, RegScratch)
	in.JEcb.Stub8(&f.Text)
	done.AddSite(f.Text.Addr)

	negFloatReg(f.Prog, a.Type, targetReg)

	done.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &done)

	f.Regs.Free(b.Type, sourceReg)
	return operand.Reg(a.Type, targetReg, false)
}

// opNegInt allocates registers.
func opNegInt(f *gen.Func, x operand.O) operand.O {
	r, _ := allocResultReg(f, x)
	in.NEG.Reg(&f.Text, x.Type, r)
	return operand.Reg(x.Type, r, true)
}

// opInplaceInt allocates registers.
func opInplaceInt(f *gen.Func, insn in.M, x operand.O) operand.O {
	r, _ := allocResultReg(f, x)
	insn.Reg(&f.Text, x.Type, r)
	return operand.Reg(x.Type, r, true)
}

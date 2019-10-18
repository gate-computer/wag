// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/internal/isa/prop"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

func (MacroAssembler) Binary(f *gen.Func, props uint16, a, b operand.O) (result operand.O) {
	return binaryOps[props&prop.MaskBinary](f, props, a, b)
}

var binaryOps = [prop.MaskBinary + 1]func(*gen.Func, uint16, operand.O, operand.O) operand.O{
	prop.BinaryIntCmp:        binaryIntCmp,
	prop.BinaryIntAddsub:     binaryIntAddsub,
	prop.BinaryIntMul:        binaryIntMul,
	prop.BinaryIntDivU:       binaryIntDivU,
	prop.BinaryIntDivS:       binaryIntDivS,
	prop.BinaryIntRem:        binaryIntRem,
	prop.BinaryIntLogic:      binaryIntLogic,
	prop.BinaryIntShift:      binaryIntShift,
	prop.BinaryIntRotl:       binaryIntRotl,
	prop.BinaryFloatCmp:      binaryFloatCmp,
	prop.BinaryFloat:         binaryFloat,
	prop.BinaryFloatCopysign: binaryFloatCopysign,
}

func binaryIntCmp(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)
	o.insn(in.SUBSe.RdRnI3ExtRm(RegDiscard, aReg, 0, in.UXTX, bReg, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free2(a.Type, aReg, bReg)
	return operand.Flags(condition.C(props >> 8))
}

func binaryIntAddsub(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	insn := in.Addsub(props >> 8).OpcodeRegExt()

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)
	o.insn(insn.RdRnI3ExtRm(aReg, aReg, 0, in.SizeZeroExt(a.Size()), bReg, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

func binaryIntMul(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)
	o.insn(in.MADD.RdRnRaRm(aReg, aReg, RegZero, bReg, a.Size())) // RegZero + aReg * bReg
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

func binaryIntDivU(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)

	o.insn(in.CBNZ.RtI19(bReg, 2, a.Size())) // Skip next instruction.
	o.trap(f, trap.IntegerDivideByZero)

	o.insn(in.UDIV.RdRnRm(aReg, aReg, bReg, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

func binaryIntDivS(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)

	o.insn(in.CBNZ.RtI19(bReg, 2, a.Size())) // Skip next instruction.
	o.trap(f, trap.IntegerDivideByZero)

	o.insn(in.ADDSi.RdRnI12S2(RegDiscard, bReg, 1, 0, a.Size()))
	o.insn(in.Bc.CondI19(in.NE, 5)) // Skip until div instruction.
	o.moveImm0x80(RegScratch2, a.Size())
	o.insn(in.SUBSs.RdRnI6RmS2(RegDiscard, RegScratch2, 0, aReg, in.LSL, a.Size()))
	o.insn(in.Bc.CondI19(in.NE, 2)) // Skip next instruction.
	o.trap(f, trap.IntegerOverflow)

	o.insn(in.SDIV.RdRnRm(aReg, aReg, bReg, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

func binaryIntRem(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)

	o.insn(in.CBNZ.RtI19(bReg, 2, a.Size())) // Skip next instruction.
	o.trap(f, trap.IntegerDivideByZero)

	div := in.DataProcessing2(props >> 8).OpcodeReg()
	o.insn(div.RdRnRm(RegScratch2, aReg, bReg, a.Size()))
	o.insn(in.MSUB.RdRnRaRm(aReg, RegScratch2, aReg, bReg, a.Size())) // aReg - RegScratch2 * bReg
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

func binaryIntLogic(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	insn := in.Logic(props >> 8).OpcodeReg()

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)
	o.insn(insn.RdRnI6RmS2(aReg, aReg, 0, bReg, 0, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

func binaryIntShift(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	insn := in.DataProcessing2(props >> 8).OpcodeReg()

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)
	o.insn(insn.RdRnRm(aReg, aReg, bReg, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

func binaryIntRotl(f *gen.Func, _ uint16, a, b operand.O) operand.O {
	var o outbuf

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)

	o.insn(in.SUBs.RdRnI6RmS2(bReg, RegZero, 0, bReg, in.LSL, a.Size()))
	o.insn(in.RORV.RdRnRm(aReg, aReg, bReg, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

func binaryFloatCmp(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)
	o.insn(in.FCMP.RnRm(aReg, bReg, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free2(a.Type, aReg, bReg)
	return operand.Flags(condition.C(props >> 8))
}

func binaryFloat(f *gen.Func, props uint16, a, b operand.O) operand.O {
	var o outbuf

	insn := in.BinaryFloat(props >> 8).OpcodeReg()

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)
	o.insn(insn.RdRnRm(aReg, aReg, bReg, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

func binaryFloatCopysign(f *gen.Func, _ uint16, a, b operand.O) operand.O {
	var o outbuf

	bReg := o.getScratchReg(f, b)
	aReg := o.allocResultReg(f, a)

	o.insn(in.FMOVtog.RdRn(RegScratch, bReg, b.Size(), b.Size()))
	o.moveImm0x80(RegScratch2, a.Size())
	o.insn(in.ANDs.RdRnI6RmS2(RegScratch, RegScratch, 0, RegScratch2, 0, wa.Size64)) // TODO: ANDi?
	o.insn(in.FMOVtog.RdRn(RegResult, aReg, a.Size(), a.Size()))
	o.insn(in.ANDs.RdRnI6RmS2(RegResult, RegResult, 0, RegScratch2, 0, wa.Size64)) // TODO: ANDi?
	o.insn(in.SUBSs.RdRnI6RmS2(RegDiscard, RegResult, 0, RegScratch, in.LSL, wa.Size64))
	o.insn(in.Bc.CondI19(in.EQ, 2)) // Skip next instruction.
	o.insn(in.FNEG.RdRn(aReg, aReg, a.Size()))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(b.Type, bReg)
	return operand.Reg(a.Type, aReg)
}

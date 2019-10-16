// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/internal/isa/prop"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

func (MacroAssembler) Binary(f *gen.Func, props uint16, a, b operand.O) operand.O {
	bReg, _ := getScratchReg(f, b)
	aReg, _ := allocResultReg(f, a)

	switch uint8(props) {
	case prop.BinaryIntCmp:
		f.Text.PutUint32(in.SUBSe.RdRnI3ExtRm(RegDiscard, aReg, 0, in.UXTX, bReg, a.Type))
		f.Regs.Free2(a.Type, aReg, bReg)
		return operand.Flags(condition.C(props >> 8))

	case prop.BinaryIntAddsub:
		insn := in.Addsub(props >> 8).OpcodeRegExt()
		f.Text.PutUint32(insn.RdRnI3ExtRm(aReg, aReg, 0, in.SizeZeroExt(a.Type), bReg, a.Type))
		f.Regs.Free(b.Type, bReg)
		return operand.Reg(a.Type, aReg)

	case prop.BinaryIntMul:
		f.Text.PutUint32(in.MADD.RdRnRaRm(aReg, aReg, RegZero, bReg, a.Type)) // RegZero + aReg * bReg
		f.Regs.Free(b.Type, bReg)
		return operand.Reg(a.Type, aReg)

	case prop.BinaryIntDiv:
		return binaryIntDiv(f, props, aReg, bReg, a.Type)

	case prop.BinaryIntRem:
		return binaryIntRem(f, props, aReg, bReg, a.Type)

	case prop.BinaryIntLogic:
		insn := in.Logic(props >> 8).OpcodeReg()
		f.Text.PutUint32(insn.RdRnI6RmS2(aReg, aReg, 0, bReg, 0, a.Type))
		f.Regs.Free(b.Type, bReg)
		return operand.Reg(a.Type, aReg)

	case prop.BinaryIntShift:
		insn := in.DataProcessing2(props >> 8).OpcodeReg()
		f.Text.PutUint32(insn.RdRnRm(aReg, aReg, bReg, a.Type))
		f.Regs.Free(b.Type, bReg)
		return operand.Reg(a.Type, aReg)

	case prop.BinaryIntRotl:
		var o output

		o.uint32(in.SUBs.RdRnI6RmS2(bReg, RegZero, 0, bReg, in.LSL, b.Type))
		o.uint32(in.RORV.RdRnRm(aReg, aReg, bReg, a.Type))
		o.copy(f.Text.Extend(o.size()))

		f.Regs.Free(b.Type, bReg)

		return operand.Reg(a.Type, aReg)

	default:
		return TODO(props, a, b).(operand.O)
	}
}

func binaryIntDiv(f *gen.Func, props uint16, aReg, bReg reg.R, t wa.Type) operand.O {
	var o output

	o.uint32(in.CBNZ.RtI19(bReg, 2, t)) // Skip next instruction.
	putTrapInsn(&o, f, trap.IntegerDivideByZero)

	div := in.UDIV

	if props&prop.BinaryIntDivSigned != 0 {
		o.uint32(in.ADDSi.RdRnI12S2(RegDiscard, bReg, 1, 0, t))
		o.uint32(in.Bc.CondI19(in.NE, 5)) // Skip until div instruction.
		o.uint32(in.LDUR.RtRnI9(RegScratch2, RegTextBase, uint32(rodata.MaskAddr(rodata.Mask80Base, t)), t))
		o.uint32(in.SUBSs.RdRnI6RmS2(RegDiscard, RegScratch2, 0, aReg, in.LSL, t))
		o.uint32(in.Bc.CondI19(in.NE, 2)) // Skip next instruction.
		putTrapInsn(&o, f, trap.IntegerOverflow)

		div = in.SDIV
	}

	o.uint32(div.RdRnRm(aReg, aReg, bReg, t))
	o.copy(f.Text.Extend(o.size()))

	f.Regs.Free(t, bReg)

	return operand.Reg(t, aReg)
}

func binaryIntRem(f *gen.Func, props uint16, aReg, bReg reg.R, t wa.Type) operand.O {
	var o output

	o.uint32(in.CBNZ.RtI19(bReg, 2, t)) // Skip next instruction.
	putTrapInsn(&o, f, trap.IntegerDivideByZero)

	div := in.DataProcessing2(props >> 8).OpcodeReg()
	o.uint32(div.RdRnRm(RegScratch2, aReg, bReg, t))
	o.uint32(in.MSUB.RdRnRaRm(aReg, RegScratch2, aReg, bReg, t)) // aReg - RegScratch2 * bReg
	o.copy(f.Text.Extend(o.size()))

	f.Regs.Free(t, bReg)

	return operand.Reg(t, aReg)
}

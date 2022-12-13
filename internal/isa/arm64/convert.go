// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64
// +build arm64 wagarm64
// +build !wagamd64

package arm64

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/isa/arm64/in"
	"gate.computer/wag/internal/isa/prop"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
)

func (MacroAssembler) Convert(f *gen.Func, props uint64, resultType wa.Type, source operand.O) operand.O {
	var o outbuf

	switch props & prop.MaskConversion {
	case prop.ConversionExtend:
		insn := in.Bitfield(props >> 8).Opcode()

		r := o.allocResultReg(f, source)
		o.insn(insn.RdRnI6sI6r(r, r, 31, 0, wa.Size64))
		o.copy(f.Text.Extend(o.size))

		return operand.Reg(resultType, r)

	case prop.ConversionMote:
		return convertFloat(f, props, resultType, source)

	case prop.ConversionFloatToInt:
		insn := in.Conversion(props >> 8).Opcode()

		resultReg := f.Regs.AllocResult(wa.I64)
		sourceReg := o.getScratchReg(f, source)
		o.insn(in.MSR_FPSR.Rt(RegZero))
		o.insn(insn.RdRn(resultReg, sourceReg, source.Size(), resultType.Size()))
		o.insn(in.MRS_FPSR.Rt(RegScratch))
		o.insn(in.TBZ.RtI14Bit(RegScratch, 2, 0)) // Skip next instruction if valid operation.
		o.trap(f, trap.IntegerOverflow)
		o.copy(f.Text.Extend(o.size))

		f.Regs.Free(wa.F64, sourceReg)
		return operand.Reg(resultType, resultReg)

	case prop.ConversionIntToFloat:
		insn := in.Conversion(props >> 8).Opcode()

		resultReg := f.Regs.AllocResult(wa.F64)
		sourceReg := o.getScratchReg(f, source)
		o.insn(insn.RdRn(resultReg, sourceReg, resultType.Size(), source.Size()))
		o.copy(f.Text.Extend(o.size))

		f.Regs.Free(wa.I64, sourceReg)
		return operand.Reg(resultType, resultReg)
	}

	panic(props)
}

func convertFloat(f *gen.Func, props uint64, resultType wa.Type, source operand.O) operand.O {
	var o outbuf

	insn := in.UnaryFloat(props >> 8).Opcode()

	r := o.allocResultReg(f, source)
	o.insn(insn.RdRn(r, r, source.Size()))
	o.copy(f.Text.Extend(o.size))

	return operand.Reg(resultType, r)
}

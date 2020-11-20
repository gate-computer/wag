// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/isa/arm/in"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
)

func (MacroAssembler) Load(f *gen.Func, props uint16, index operand.O, resultType wa.Type, align, offset uint32) operand.O {
	var o outbuf

	r := f.Regs.AllocResult(resultType)
	o.access(f, in.Memory(props), r, index, offset)
	o.copy(f.Text.Extend(o.size))

	return operand.Reg(resultType, r)
}

func (MacroAssembler) Store(f *gen.Func, props uint16, index, x operand.O, align, offset uint32) {
	var o outbuf

	r := RegZero
	if !(x.Storage == storage.Imm && x.ImmValue() == 0) {
		r = RegResult
		o.move(f, r, x)
	}

	o.access(f, in.Memory(props), r, index, offset)
	o.copy(f.Text.Extend(o.size))
}

func (o *outbuf) access(f *gen.Func, op in.Memory, dataReg reg.R, index operand.O, offset uint32) {
	if offset >= 0x80000000 {
		f.ValueBecameUnreachable(index)
		asm.Trap(f, trap.MemoryAccessOutOfBounds)
		return
	}

	switch index.Storage {
	case storage.Imm:
		value := uint64(index.ImmValue())
		addr := value + uint64(offset)
		if value >= 0x80000000 || addr >= 0x80000000 {
			asm.Trap(f, trap.MemoryAccessOutOfBounds)
			return
		}

		switch {
		case addr <= 255:
			o.insn(op.OpcodeUnscaled().RtRnI9(dataReg, RegMemoryBase, uint32(addr)))

		default:
			o.moveUintImm32(RegScratch, uint32(addr))
			o.insn(op.OpcodeReg().RtRnSOptionRm(dataReg, RegMemoryBase, in.Unscaled, in.UXTW, RegScratch))
		}

	default:
		r := o.getScratchReg(f, index)

		if offset < 1<<24 {
			imm := uint64(offset)
			if imm != 0 {
				o.insn(in.ADDi.RdRnI12S2(r, r, in.Uint12(imm), 0, wa.Size32))
			}
			imm >>= 12
			if imm != 0 {
				o.insn(in.ADDi.RdRnI12S2(r, r, in.Uint12(imm), 1, wa.Size32))
			}
		} else {
			o.moveUintImm32(RegScratch2, offset)
			o.insn(in.ADDs.RdRnI6RmS2(r, r, 0, RegScratch2, 0, wa.Size32))
		}

		// UXTW masks index register unconditionally.
		o.insn(op.OpcodeReg().RtRnSOptionRm(dataReg, RegMemoryBase, in.Unscaled, in.UXTW, r))

		f.Regs.Free(wa.I32, r)
	}

	f.MapTrapAddr(o.addr(&f.Text)) // Address of instruction pointer during SIGSEGV handling.
}

func (MacroAssembler) CurrentMemory(f *gen.Func) int32 {
	var o outbuf

	o.insn(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(gen.VectorOffsetCurrentMemory), wa.I64))
	o.insn(in.BLR.Rn(RegScratch))
	o.copy(f.Text.Extend(o.size))

	return f.Text.Addr
}

func (MacroAssembler) GrowMemory(f *gen.Func) int32 {
	var o outbuf

	o.insn(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(gen.VectorOffsetGrowMemory), wa.I64))
	o.insn(in.BLR.Rn(RegScratch))
	o.copy(f.Text.Extend(o.size))

	return f.Text.Addr
}

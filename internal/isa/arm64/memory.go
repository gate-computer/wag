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
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/isa/arm64/in"
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

	// Wrapping index to 32 bits avoids speculation beyond memory mapping.

	switch index.Storage {
	case storage.Imm:
		o.moveUintImm32(RegScratch, uint32(index.ImmValue()))

	case storage.Stack:
		o.insn(in.PopReg(RegScratch, wa.I32))
		f.StackValueConsumed()

	case storage.Reg:
		r := index.Reg()
		o.insn(in.ORRs.RdRnI6RmS2(RegScratch, RegZero, 0, r, 0, wa.Size32))
		f.Regs.Free(index.Type, r)

	case storage.Flags:
		o.setBool(RegScratch, index.FlagsCond())
	}

	o.moveUintImm32(RegScratch2, offset)
	o.insn(in.ADDs.RdRnI6RmS2(RegScratch, RegScratch, 0, RegScratch2, 0, wa.Size64))
	o.insn(op.OpcodeReg().RtRnSOptionRm(dataReg, RegMemoryBase, in.Unscaled, in.UXTX, RegScratch))

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

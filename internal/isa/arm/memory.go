// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

func (MacroAssembler) Load(f *gen.Func, props uint16, index operand.O, resultType wa.Type, align, offset uint32) operand.O {
	r := f.Regs.AllocResult(resultType)
	access(f, in.Memory(props), r, index, offset)
	return operand.Reg(resultType, r)
}

func (MacroAssembler) Store(f *gen.Func, props uint16, index, x operand.O, align, offset uint32) {
	var r reg.R

	switch {
	case x.Storage == storage.Imm && x.ImmValue() == 0:
		r = RegZero

	default:
		r, _ = allocResultReg(f, x)
		f.Regs.Free(x.Type, r)
	}

	access(f, in.Memory(props), r, index, offset)
}

func access(f *gen.Func, op in.Memory, dataReg reg.R, index operand.O, offset uint32) {
	if offset >= 0x80000000 {
		f.ValueBecameUnreachable(index)
		asm.Trap(f, trap.MemoryAccessOutOfBounds)
		return
	}

	var o output

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
			o.uint32(op.OpcodeUnscaled().RtRnI9(dataReg, RegMemoryBase, uint32(addr)))

		default:
			moveUintImm32(&o, RegScratch, uint32(addr))
			o.uint32(op.OpcodeReg().RtRnSOptionRm(dataReg, RegMemoryBase, in.Unscaled, in.UXTW, RegScratch))
		}

	default:
		r, _ := getScratchReg(f, index)

		var i uint32
		for imm := uint64(offset); imm != 0; imm >>= 12 {
			o.uint32(in.ADDi.RdRnI12S2(r, r, in.Uint12(imm), i, wa.I32))
			i++
		}

		// UXTW masks index register unconditionally.
		o.uint32(op.OpcodeReg().RtRnSOptionRm(dataReg, RegMemoryBase, in.Unscaled, in.UXTW, r))

		f.Regs.Free(wa.I32, r)
	}

	o.copy(f.Text.Extend(o.size()))
}

func (MacroAssembler) CurrentMemory(f *gen.Func) int32 {
	var o output

	o.uint32(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(gen.VectorOffsetCurrentMemory), wa.I64))
	o.uint32(in.BLR.Rn(RegScratch))
	o.copy(f.Text.Extend(o.size()))

	return f.Text.Addr
}

func (MacroAssembler) GrowMemory(f *gen.Func) int32 {
	var o output

	o.uint32(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(gen.VectorOffsetGrowMemory), wa.I64))
	o.uint32(in.BLR.Rn(RegScratch))
	o.copy(f.Text.Extend(o.size()))

	return f.Text.Addr
}

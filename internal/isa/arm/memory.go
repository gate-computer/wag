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
	op := in.Memory(props)
	base, disp9 := checkAccess(f, op.SizeReach(), index, offset)

	r := f.Regs.AllocResult(resultType)
	f.Text.PutUint32(op.OpcodeUnscaled().RtRnI9(r, base, disp9))
	return operand.Reg(resultType, r) // TODO: is it?
}

func (MacroAssembler) Store(f *gen.Func, props uint16, index, x operand.O, align, offset uint32) {
	op := in.Memory(props)
	base, disp9 := checkAccess(f, op.SizeReach(), index, offset)

	var value reg.R
	if x.Storage == storage.Imm && x.ImmValue() == 0 {
		value = RegZero
	} else {
		value, _ = allocResultReg(f, x)
		f.Regs.Free(x.Type, value)
	}

	f.Text.PutUint32(op.OpcodeUnscaled().RtRnI9(value, base, disp9))
}

// checkAccess returns RegMemoryBase or RegScratch as base.
func checkAccess(f *gen.Func, sizeReach uint64, index operand.O, offset uint32) (base reg.R, disp9 uint32) {
	reachOffset := uint64(offset) + sizeReach

	if reachOffset >= 0x80000000 {
		f.ValueBecameUnreachable(index)
		return invalidAccess(f)
	}

	if index.Storage == storage.Imm {
		value := uint64(index.ImmValue())

		if value >= 0x80000000 {
			return invalidAccess(f)
		}

		addr := value + uint64(offset)
		reachAddr := addr + sizeReach

		if reachAddr >= 0x80000000 {
			return invalidAccess(f)
		}

		if reachAddr < uint64(f.Module.MemoryLimitValues.Initial) {
			// Call site is not mapped, so this optimization is part of
			// portable ABI.
			if addr <= 255 {
				base = RegMemoryBase
				disp9 = uint32(addr)
			} else {
				panic(addr)
			}
			return
		}

		panic(reachAddr)
	} else {
		r, _ := getScratchReg(f, index)
		f.Text.PutUint32(in.ADDe.RdRnI3ExtRm(RegScratch, RegMemoryBase, 0, in.UXTW, r, wa.I64))
		f.Regs.Free(wa.I32, r)

		var i uint32
		for imm := reachOffset; imm != 0; imm >>= 12 {
			f.Text.PutUint32(in.ADDi.RdRnI12S2(RegScratch, RegScratch, in.Uint12(imm), i, wa.I64))
			i++
		}
	}

	base = RegScratch
	disp9 = in.Int9(-int32(sizeReach))
	return
}

func invalidAccess(f *gen.Func) (base reg.R, disp9 uint32) {
	asm.Trap(f, trap.MemoryAccessOutOfBounds)

	f.Text.PutUint32(in.MOVZ.RdI16Hw(RegScratch, 0, 0, wa.I64))
	base = RegScratch
	disp9 = 0
	return
}

func (MacroAssembler) CurrentMemory(f *gen.Func) int32 {
	TODO()
	return f.Text.Addr
}

func (MacroAssembler) GrowMemory(f *gen.Func) int32 {
	TODO()
	return f.Text.Addr
}

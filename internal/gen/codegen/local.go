// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/wa"
	"gate.computer/wag/wa/opcode"
	"import.name/pan"
)

func loadLocalIndex(f *gen.Func, load *loader.L, op opcode.Opcode) uint32 {
	index := load.Varuint32()
	if index >= uint32(len(f.LocalTypes)) {
		pan.Panic(module.Errorf("%s index out of bounds: %d", op, index))
	}
	return index
}

func loadLocalIndexType(f *gen.Func, load *loader.L, op opcode.Opcode) (int, wa.Type) {
	index := loadLocalIndex(f, load, op)
	t := f.LocalTypes[index]
	return int(index), t
}

func genGetLocal(f *gen.Func, load *loader.L, op opcode.Opcode) {
	index, t := loadLocalIndexType(f, load, op)
	r, _ := opAllocReg(f, t)
	asm.LoadStack(&f.Prog, t, r, f.LocalOffset(index))
	pushOperand(f, operand.Reg(t, r))
}

func genSetLocal(f *gen.Func, load *loader.L, op opcode.Opcode) {
	index, t := loadLocalIndexType(f, load, op)
	value := popOperand(f, t)
	asm.StoreStack(f, f.LocalOffset(index), value)
}

func genTeeLocal(f *gen.Func, load *loader.L, op opcode.Opcode) {
	index, t := loadLocalIndexType(f, load, op)
	value := popOperand(f, t)

	switch value.Storage {
	default:
		r, _ := opAllocReg(f, t)
		asm.Move(f, r, value)
		value.SetReg(r)
		fallthrough

	case storage.Reg:
		asm.StoreStackReg(&f.Prog, t, f.LocalOffset(index), value.Reg())

	case storage.Imm:
		asm.StoreStackImm(&f.Prog, t, f.LocalOffset(index), value.ImmValue())
	}

	pushOperand(f, value)
}

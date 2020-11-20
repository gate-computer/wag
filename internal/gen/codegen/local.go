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
)

func readLocalIndex(f *gen.Func, load loader.L, op opcode.Opcode) (index int, t wa.Type) {
	i := load.Varuint32()
	if i >= uint32(len(f.LocalTypes)) {
		panic(module.Errorf("%s index out of bounds: %d", op, i))
	}

	index = int(i)
	t = f.LocalTypes[index]
	return
}

func genGetLocal(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	index, t := readLocalIndex(f, load, op)
	r, _ := opAllocReg(f, t)
	asm.LoadStack(&f.Prog, t, r, f.LocalOffset(index))
	pushOperand(f, operand.Reg(t, r))
	return
}

func genSetLocal(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	index, t := readLocalIndex(f, load, op)
	value := popOperand(f, t)
	asm.StoreStack(f, f.LocalOffset(index), value)
	return
}

func genTeeLocal(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	index, t := readLocalIndex(f, load, op)
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
	return
}

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/wa"
)

func readLocalIndex(f *gen.Func, load loader.L, op Opcode) (index int, t wa.Type) {
	i := load.Varuint32()
	if i >= uint32(len(f.LocalTypes)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, i))
	}

	index = int(i)
	t = f.LocalTypes[index]
	return
}

func genGetLocal(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	index, t := readLocalIndex(f, load, op)
	r := opAllocReg(f, t)
	asm.LoadStack(f.Prog, t, r, f.LocalOffset(index))
	pushOperand(f, operand.Reg(t, r, true))
	return
}

func genSetLocal(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	index, t := readLocalIndex(f, load, op)
	value := popOperand(f, t)
	asm.StoreStack(f, f.LocalOffset(index), value)
	return
}

func genTeeLocal(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	index, t := readLocalIndex(f, load, op)
	value := popOperand(f, t)

	switch value.Storage {
	case storage.Imm:
		asm.StoreStackImm(f.Prog, t, f.LocalOffset(index), value.ImmValue())

	default:
		r := opAllocReg(f, t)
		asm.Move(f, r, value)
		value.SetReg(r, false) // zeroExt information not needed
		fallthrough

	case storage.Reg:
		asm.StoreStackReg(f.Prog, t, f.LocalOffset(index), value.Reg())
	}

	pushOperand(f, value)
	return
}

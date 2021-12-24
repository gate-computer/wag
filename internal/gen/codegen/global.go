// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/wa/opcode"
)

func globalOffset(f *gen.Func, index uint32) int32 {
	return (int32(index) - int32(len(f.Module.Globals))) * obj.Word
}

func genGetGlobal(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	globalIndex := load.Varuint32()
	if globalIndex >= uint32(len(f.Module.Globals)) {
		check(module.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := f.Module.Globals[globalIndex]
	r, _ := opAllocReg(f, global.Type)
	asm.LoadGlobal(&f.Prog, global.Type, r, globalOffset(f, globalIndex))
	pushOperand(f, operand.Reg(global.Type, r))
	return
}

func genSetGlobal(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	globalIndex := load.Varuint32()
	if globalIndex >= uint32(len(f.Module.Globals)) {
		check(module.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := f.Module.Globals[globalIndex]
	if !global.Mutable {
		check(module.Errorf("%s: global %d is immutable", op, globalIndex))
	}

	x := popOperand(f, global.Type)
	asm.StoreGlobal(f, globalOffset(f, globalIndex), x)
	return
}

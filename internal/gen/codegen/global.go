// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/opcode"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/obj"
)

func globalOffset(f *gen.Func, index uint32) int32 {
	return (int32(index) - int32(len(f.Module.Globals))) * obj.Word
}

func genGetGlobal(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	globalIndex := load.Varuint32()
	if globalIndex >= uint32(len(f.Module.Globals)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := f.Module.Globals[globalIndex]
	r := opAllocReg(f, global.Type)
	zeroExt := asm.LoadGlobal(&f.Prog, global.Type, r, globalOffset(f, globalIndex))
	pushOperand(f, operand.Reg(global.Type, r, zeroExt))
	return
}

func genSetGlobal(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	globalIndex := load.Varuint32()
	if globalIndex >= uint32(len(f.Module.Globals)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := f.Module.Globals[globalIndex]
	if !global.Mutable {
		panic(fmt.Errorf("%s: global %d is immutable", op, globalIndex))
	}

	x := popOperand(f, global.Type)
	asm.StoreGlobal(f, globalOffset(f, globalIndex), x)
	return
}

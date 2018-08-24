// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/obj"
)

func offsetOfGlobal(f *gen.Func, index uint32) int32 {
	return (int32(index) - int32(len(f.Globals))) * obj.Word
}

func genGetGlobal(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	globalIndex := load.Varuint32()
	if globalIndex >= uint32(len(f.Globals)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := f.Globals[globalIndex]
	offset := offsetOfGlobal(f, globalIndex)

	opStabilizeOperandStack(f)
	result := isa.OpGetGlobal(f, global.Type, offset)
	pushOperand(f, result)
	return
}

func genSetGlobal(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	globalIndex := load.Varuint32()
	if globalIndex >= uint32(len(f.Globals)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := f.Globals[globalIndex]
	if !global.Mutable {
		panic(fmt.Errorf("%s: global %d is immutable", op, globalIndex))
	}

	offset := offsetOfGlobal(f, globalIndex)

	x := opMaterializeOperand(f, popOperand(f))
	if x.Type != global.Type {
		panic(fmt.Errorf("%s operand type is %s, but type of global %d is %s", op, x.Type, globalIndex, global.Type))
	}

	isa.OpSetGlobal(f, offset, x)
	return
}

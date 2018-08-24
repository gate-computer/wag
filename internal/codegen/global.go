// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/internal/loader"
)

func genGetGlobal(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	globalIndex := load.Varuint32()
	if globalIndex >= uint32(len(f.Globals)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := f.Globals[globalIndex]
	offset := offsetOfGlobal(f.Module, globalIndex)

	opStabilizeOperandStack(f)
	result := isa.OpGetGlobal(f.Module, f, global.Type, offset)
	pushOperand(f, result)
	return
}

func genSetGlobal(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	globalIndex := load.Varuint32()
	if globalIndex >= uint32(len(f.Globals)) {
		panic(fmt.Errorf("%s index out of bounds: %d", op, globalIndex))
	}

	global := f.Globals[globalIndex]
	if !global.Mutable {
		panic(fmt.Errorf("%s: global %d is immutable", op, globalIndex))
	}

	offset := offsetOfGlobal(f.Module, globalIndex)

	x := opMaterializeOperand(f, popOperand(f))
	if x.Type != global.Type {
		panic(fmt.Errorf("%s operand type is %s, but type of global %d is %s", op, x.Type, globalIndex, global.Type))
	}

	isa.OpSetGlobal(f.Module, f, offset, x)
	return
}

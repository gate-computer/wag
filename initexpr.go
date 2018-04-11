// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wag

import (
	"fmt"

	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/types"
)

func readInitExpr(load loader.L, m *Module) (valueBits uint64, t types.T) {
	op := opcode(load.Byte())

	switch op {
	case opcodeI32Const:
		valueBits = uint64(int64(load.Varint32()))
		t = types.I32

	case opcodeI64Const:
		valueBits = uint64(load.Varint64())
		t = types.I64

	case opcodeF32Const:
		valueBits = uint64(load.Uint32())
		t = types.F32

	case opcodeF64Const:
		valueBits = load.Uint64()
		t = types.F64

	case opcodeGetGlobal:
		i := load.Varuint32()
		if i >= uint32(m.NumImportGlobals) {
			panic(fmt.Errorf("import global index out of bounds in initializer expression: %d", i))
		}
		g := m.Globals[i]
		valueBits = g.Init
		t = g.Type

	default:
		panic(fmt.Errorf("unsupported operation in initializer expression: %s", op))
	}

	if op := opcode(load.Byte()); op != opcodeEnd {
		panic(fmt.Errorf("unexpected operation in initializer expression when expecting end: %s", op))
	}

	return
}

func readOffsetInitExpr(load loader.L, m *Module) uint32 {
	offset, t := readInitExpr(load, m)
	if t != types.I32 {
		panic(fmt.Errorf("offset initializer expression has invalid type: %s", t))
	}
	return uint32(int32(int64(offset)))
}

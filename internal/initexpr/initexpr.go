// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package initexpr

import (
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/wa"
	"gate.computer/wag/wa/opcode"
)

func Read(m *module.M, load loader.L) (valueBits uint64, t wa.Type) {
	op := opcode.Opcode(load.Byte())

	switch op {
	case opcode.I32Const:
		valueBits = uint64(int64(load.Varint32()))
		t = wa.I32

	case opcode.I64Const:
		valueBits = uint64(load.Varint64())
		t = wa.I64

	case opcode.F32Const:
		valueBits = uint64(load.Uint32())
		t = wa.F32

	case opcode.F64Const:
		valueBits = load.Uint64()
		t = wa.F64

	case opcode.GetGlobal:
		i := load.Varuint32()
		if i >= uint32(len(m.ImportGlobals)) {
			panic(module.Errorf("import global index out of bounds in initializer expression: %d", i))
		}
		g := m.Globals[i]
		valueBits = g.Init
		t = g.Type

	default:
		panic(module.Errorf("unsupported operation in initializer expression: %s", op))
	}

	if op := opcode.Opcode(load.Byte()); op != opcode.End {
		panic(module.Errorf("unexpected operation in initializer expression when expecting end: %s", op))
	}

	return
}

func ReadOffset(m *module.M, load loader.L) uint32 {
	offset, t := Read(m, load)
	if t != wa.I32 {
		panic(module.Errorf("offset initializer expression has invalid type: %s", t))
	}
	return uint32(int32(int64(offset)))
}

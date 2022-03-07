// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package initexpr

import (
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/wa"
	"gate.computer/wag/wa/opcode"
	"import.name/pan"
)

func Read(m *module.M, load *loader.L) (importIndex int, valueBits uint64, t wa.Type) {
	importIndex = -1

	switch op := opcode.Opcode(load.Byte()); op {
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
			pan.Panic(module.Errorf("import global index out of bounds in initializer expression: %d", i))
		}
		importIndex = int(i)
		t = m.Globals[i].Type

	default:
		pan.Panic(module.Errorf("unsupported operation in initializer expression: %s", op))
	}

	if op := opcode.Opcode(load.Byte()); op != opcode.End {
		pan.Panic(module.Errorf("unexpected operation in initializer expression when expecting end: %s", op))
	}

	return
}

func ReadOffset(m *module.M, load *loader.L) uint32 {
	index, value, t := Read(m, load)
	if t != wa.I32 {
		pan.Panic(module.Errorf("offset initializer expression has invalid type: %s", t))
	}

	value = m.EvaluateGlobalInitializer(index, value)
	return uint32(int32(int64(value)))
}

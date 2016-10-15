package wag

import (
	"fmt"

	"github.com/tsavola/wag/internal/types"
)

func readInitExpr(r reader, m *Module) (valueBits uint64, t types.T) {
	op := r.readOpcode()

	switch op {
	case opcodeI32Const:
		valueBits = uint64(int64(r.readVarint32()))
		t = types.I32

	case opcodeI64Const:
		valueBits = uint64(r.readVarint64())
		t = types.I64

	case opcodeF32Const:
		valueBits = uint64(r.readUint32())
		t = types.F32

	case opcodeF64Const:
		valueBits = r.readUint64()
		t = types.F64

	case opcodeGetGlobal:
		i := r.readVaruint32()
		if i >= uint32(m.numImportGlobals) {
			panic(fmt.Errorf("import global index out of bounds in initializer expression: %d", i))
		}
		g := m.globals[i]
		valueBits = g.init
		t = g.t

	default:
		panic(fmt.Errorf("unsupported operation in initializer expression: %s", op))
	}

	if op := r.readOpcode(); op != opcodeEnd {
		panic(fmt.Errorf("unexpected operation in initializer expression when expecting end: %s", op))
	}

	return
}

func readOffsetInitExpr(r reader, m *Module) (offset uint64) {
	offset, t := readInitExpr(r, m)
	if t != types.I32 {
		panic(fmt.Errorf("offset initializer expression has invalid type: %s", t))
	}
	return
}

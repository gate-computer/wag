package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/gen"
)

type imm struct {
	value interface{}
}

func imm8(x int) imm {
	return imm{int8(x)}
}

func uimm8(x int) imm {
	return imm{uint8(x)}
}

func imm16(x int) imm {
	return imm{int16(x)}
}

func imm32(x int) imm {
	return imm{int32(x)}
}

func imm64(x int64) imm {
	return imm{x}
}

func (imm imm) writeTo(code gen.Coder) {
	if imm.value != nil {
		if err := binary.Write(code, byteOrder, imm.value); err != nil {
			panic(err)
		}
	}
}

var (
	Void imm
)

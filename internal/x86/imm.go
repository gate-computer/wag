package x86

import (
	"encoding/binary"
	"io"
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

func imm32(x int) imm {
	return imm{int32(x)}
}

func imm64(x int) imm {
	return imm{int64(x)}
}

func (imm imm) writeTo(w io.Writer) {
	if imm.value != nil {
		if err := binary.Write(w, byteOrder, imm.value); err != nil {
			panic(err)
		}
	}
}

var (
	Void imm
)

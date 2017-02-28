package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/gen"
)

func writeInt32To(code gen.OpCoder, value int32) {
	binary.Write(code, binary.LittleEndian, value)
}

type imm struct {
	value interface{}
}

func (imm imm) writeTo(code gen.OpCoder) {
	if imm.value != nil {
		binary.Write(code, binary.LittleEndian, imm.value)
	}
}

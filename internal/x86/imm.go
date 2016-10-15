package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/gen"
)

func writeInt32To(code gen.OpCoder, value int32) {
	if err := binary.Write(code, binary.LittleEndian, value); err != nil {
		panic(err)
	}
}

type imm struct {
	value interface{}
}

func (imm imm) writeTo(code gen.OpCoder) {
	if imm.value != nil {
		if err := binary.Write(code, binary.LittleEndian, imm.value); err != nil {
			panic(err)
		}
	}
}

// var (
// 	Void imm
// )

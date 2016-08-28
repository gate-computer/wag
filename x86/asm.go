// +build amd64
package x86

import (
	"encoding/binary"
	"fmt"

	"github.com/tsavola/wag/ins"
)

const (
	rex  = 1 << 6
	rexW = rex | (1 << 3)

	modDisp8  = (0 << 1) | (1 << 0)
	modDisp16 = (1 << 1) | (0 << 0)
	modReg    = (1 << 1) | (1 << 0)

	paddingByte = 0xf4 // HLT instruction
)

func modRM(mod, ro, rm byte) byte {
	return (mod << 6) | (ro << 3) | rm
}

func sib(scale, index, base byte) byte {
	return (scale << 6) | (index << 3) | base
}

func encodeI32(x interface{}) (b []byte) {
	b = make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ins.ImmI32(x))
	return
}

func encodeI64(x interface{}) (b []byte) {
	b = make([]byte, 8)
	binary.LittleEndian.PutUint64(b, ins.ImmI64(x))
	return
}

type Assembler struct{}

func (Assembler) Encode(x interface{}) []byte {
	switch x := x.(type) {
	case ins.Add:
		switch x.Type {
		case ins.TypeI32:
			return []byte{0x01, modRM(modReg, x.SourceReg, x.TargetReg)}

		case ins.TypeI64:
			return []byte{rexW, 0x01, modRM(modReg, x.SourceReg, x.TargetReg)}
		}

	case ins.Call:
		return []byte{0xe8, 0x22, 0x44, 0x66, 0x88} // TODO

	case ins.MovImmToReg:
		switch x.Type {
		case ins.TypeI32:
			return append([]byte{0xb8 + x.TargetReg}, encodeI32(x.SourceImm)...)

		case ins.TypeI64:
			return append([]byte{rexW, 0xb8 + x.TargetReg}, encodeI64(x.SourceImm)...)
		}

	case ins.MovRegToReg:
		return []byte{rexW, 0x89, modRM(modReg, x.SourceReg, x.TargetReg)}

	case ins.MovVarToReg:
		var mod byte
		var offset []byte

		if x.SourceOffset < 0 {
			// this is an internal error
			panic(fmt.Errorf("local variable has negative stack offset: %d", x.SourceOffset))
		} else if x.SourceOffset < 0x80 {
			mod = modDisp8
			offset = []byte{uint8(x.SourceOffset)}
		} else if x.SourceOffset < 0x8000 {
			mod = modDisp16
			offset = make([]byte, 2)
			binary.LittleEndian.PutUint16(offset, uint16(x.SourceOffset))
		} else {
			panic(fmt.Errorf("local variable has too large stack offset: %d", x.SourceOffset))
		}

		rm := byte(1 << 2) // [SI]
		sp := byte(4)

		return append([]byte{rexW, 0x8b, modRM(mod, x.TargetReg, rm), sib(0, sp, sp)}, offset...)

	case ins.Pop:
		return []byte{0x58 + x.TargetReg}

	case ins.Push:
		return []byte{0x50 + x.SourceReg}

	case ins.Ret:
		return []byte{0xc3}

	case ins.XOR:
		return []byte{rexW, 0x31, modRM(modReg, x.SourceReg, x.TargetReg)}
	}

	panic(fmt.Errorf("instruction not supported by assembler: %#v", x))
}

func (Assembler) PaddingByte() byte {
	return paddingByte
}

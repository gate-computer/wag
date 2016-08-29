// +build amd64
package x86

import (
	"encoding/binary"
	"fmt"

	"github.com/tsavola/wag/internal/stubs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

const (
	rex  = 1 << 6
	rexW = rex | (1 << 3)

	modDisp8  = (0 << 1) | (1 << 0)
	modDisp16 = (1 << 1) | (0 << 0)
	modReg    = (1 << 1) | (1 << 0)

	stackReg = 4
)

var byteOrder = binary.LittleEndian

func modRM(mod, ro, rm byte) byte {
	return (mod << 6) | (ro << 3) | rm
}

func sib(scale, index, base byte) byte {
	return (scale << 6) | (index << 3) | base
}

func encodeI32(x interface{}) (b []byte) {
	b = make([]byte, 4)
	byteOrder.PutUint32(b, values.I32(x))
	return
}

func encodeI64(x interface{}) (b []byte) {
	b = make([]byte, 8)
	byteOrder.PutUint64(b, values.I64(x))
	return
}

type Mach struct{}

func (Mach) Add(t types.Type, sourceReg, targetReg byte) []byte {
	switch t {
	case types.I32:
		return []byte{0x01, modRM(modReg, sourceReg, targetReg)}

	case types.I64:
		return []byte{rexW, 0x01, modRM(modReg, sourceReg, targetReg)}

	default:
		panic(t)
	}
}

func (Mach) AddSP(offset int) []byte {
	return append([]byte{rexW, 0x81, modRM(modReg, 0, stackReg)}, encodeI32(int64(offset))...)
}

func (Mach) BrPlaceholder() []byte {
	return []byte{0xeb, 0} // jmp
}

func (Mach) BrIfNotPlaceholder(reg byte) []byte {
	return []byte{
		0x89, modRM(modReg, reg, reg), // mov to update status register
		0x74, 0, // jz // TODO
	}
}

func (Mach) CallPlaceholder() []byte {
	return []byte{0xe8, 0, 0, 0, 0}
}

func (Mach) Invalid() []byte {
	return []byte{0x0f, 0x0b}
}

func (Mach) MovImmToReg(t types.Type, sourceImm interface{}, targetReg byte) []byte {
	switch t {
	case types.I32:
		return append([]byte{0xb8 + targetReg}, encodeI32(sourceImm)...)

	case types.I64:
		return append([]byte{rexW, 0xb8 + targetReg}, encodeI64(sourceImm)...)

	default:
		panic(t)
	}
}

func (Mach) MovRegToReg(sourceReg, targetReg byte) []byte {
	return []byte{rexW, 0x89, modRM(modReg, sourceReg, targetReg)}
}

func (Mach) MovVarToReg(sourceOffset int, targetReg byte) []byte {
	var mod byte
	var offset []byte

	if sourceOffset < 0 {
		// this is an internal error
		panic(fmt.Errorf("local variable has negative stack offset: %d", sourceOffset))
	} else if sourceOffset < 0x80 {
		mod = modDisp8
		offset = []byte{uint8(sourceOffset)}
	} else if sourceOffset < 0x8000 {
		mod = modDisp16
		offset = make([]byte, 2)
		byteOrder.PutUint16(offset, uint16(sourceOffset))
	} else {
		panic(fmt.Errorf("local variable has too large stack offset: %d", sourceOffset))
	}

	rm := byte(1 << 2) // [SI]
	sp := byte(4)

	return append([]byte{rexW, 0x8b, modRM(mod, targetReg, rm), sib(0, sp, sp)}, offset...)
}

func (Mach) NE(t types.Type, sourceReg, targetReg, scratchReg byte) []byte {
	switch t {
	case types.I32:
		return []byte{
			rexW, 0x89, modRM(modReg, targetReg, scratchReg), // mov target, scratch
			rexW, 0x31, modRM(modReg, targetReg, targetReg), // xor target, target
			0xff, modRM(modReg, 0, targetReg), // inc target
			rexW, 0x29, modRM(modReg, sourceReg, scratchReg), // sub source, scratch
			rexW, 0x0f, 0x44, modRM(modReg, targetReg, scratchReg), // cmove scratch, target
		}

	default:
		panic(t)
	}
}

func (Mach) Pop(reg byte) []byte {
	return []byte{0x58 + reg}
}

func (Mach) Push(reg byte) []byte {
	return []byte{0x50 + reg}
}

func (Mach) Ret() []byte {
	return []byte{0xc3}
}

func (Mach) Sub(t types.Type, sourceReg, targetReg byte) []byte {
	switch t {
	case types.I32:
		return []byte{0x29, modRM(modReg, sourceReg, targetReg)}

	case types.I64:
		return []byte{rexW, 0x29, modRM(modReg, sourceReg, targetReg)}

	default:
		panic(t)
	}
}

func (Mach) XOR(sourceReg, targetReg byte) []byte {
	return []byte{rexW, 0x31, modRM(modReg, sourceReg, targetReg)}
}

func (Mach) UpdateBranches(stub *stubs.Label, code []byte) {
	for _, pos := range stub.BranchSites {
		offset := stub.Address - pos
		if offset < -128 || offset > 127 {
			panic(fmt.Errorf("branch offset too large: %d (FIXME)", offset))
		}
		code[pos-1] = byte(offset)
	}
}

func (Mach) UpdateCalls(stub *stubs.Function, code []byte) {
	for _, pos := range stub.CallSites {
		offset := stub.Address - pos
		byteOrder.PutUint32(code[pos-4:pos], uint32(int32(offset)))
	}
}

func (Mach) PaddingByte() byte {
	return 0xf4 // hlt
}

func (Mach) FunctionAlign() int {
	return 16
}

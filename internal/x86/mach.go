// +build amd64
package x86

import (
	"fmt"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/types"
)

const (
	rex  = 1 << 6
	rexW = rex | (1 << 3)

	modDisp8  = (0 << 1) | (1 << 0)
	modDisp16 = (1 << 1) | (0 << 0)
	modReg    = (1 << 1) | (1 << 0)

	stackReg = 4
)

func modRM(mod, ro, rm byte) byte {
	return (mod << 6) | (ro << 3) | rm
}

func sib(scale, index, base byte) byte {
	return (scale << 6) | (index << 3) | base
}

func getTypePrefix(t types.Type) (prefix []byte) {
	switch t {
	case types.I32:

	case types.I64:
		prefix = []byte{rexW}

	default:
		panic(t)
	}

	return
}

type Mach struct{}

const (
	opcodeXOR = 0x31
)

var simpleTypedBinaryOps = map[string]byte{
	"add": 0x01,
	"and": 0x21,
	"or":  0x09,
	"sub": 0x29,
	"xor": opcodeXOR,
}

func (m Mach) TypedBinaryInst(t types.Type, name string, sourceReg, targetReg, scratchReg byte) []byte {
	prefix := getTypePrefix(t)

	if opcode, found := simpleTypedBinaryOps[name]; found {
		return append(prefix, []byte{opcode, modRM(modReg, sourceReg, targetReg)}...)
	}

	switch name {
	case "ne":
		return append(append([]byte{
			rexW, 0x89, modRM(modReg, targetReg, scratchReg), // mov target, scratch
			rexW, 0x31, modRM(modReg, targetReg, targetReg), // xor target, target
			0xff, modRM(modReg, 0, targetReg), // inc target
		}, prefix...), []byte{
			rexW, 0x29, modRM(modReg, sourceReg, scratchReg), // sub source, scratch
			rexW, 0x0f, 0x44, modRM(modReg, targetReg, scratchReg), // cmove scratch, target
		}...)

	default:
		panic(name)
	}
}

func (Mach) AddToStackPtr(offset int) []byte {
	return append([]byte{rexW, 0x81, modRM(modReg, 0, stackReg)}, encodeUint32(uint32(offset))...)
}

func (Mach) BranchPlaceholder() []byte {
	return []byte{0xeb, 0} // jmp
}

func (Mach) BranchIfNotPlaceholder(reg byte) []byte {
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

func (Mach) MoveImmToReg(t types.Type, sourceImm interface{}, targetReg byte) []byte {
	switch t {
	case types.I32:
		return append([]byte{0xb8 + targetReg}, encodeI32(sourceImm)...)

	case types.I64:
		return append([]byte{rexW, 0xb8 + targetReg}, encodeI64(sourceImm)...)

	default:
		panic(t)
	}
}

func (Mach) MoveRegToReg(sourceReg, targetReg byte) []byte {
	return []byte{rexW, 0x89, modRM(modReg, sourceReg, targetReg)}
}

func (Mach) MoveVarToReg(sourceOffset int, targetReg byte) []byte {
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

func (Mach) Pop(reg byte) []byte {
	return []byte{0x58 + reg}
}

func (Mach) Push(reg byte) []byte {
	return []byte{0x50 + reg}
}

func (Mach) Ret() []byte {
	return []byte{0xc3}
}

func (m Mach) Clear(reg byte) []byte {
	return []byte{rexW, opcodeXOR, modRM(modReg, reg, reg)} // xor
}

func (Mach) UpdateBranches(l *links.L, code []byte) {
	for _, pos := range l.Sites {
		offset := l.Address - pos
		if offset < -128 || offset > 127 {
			panic(fmt.Errorf("branch offset too large: %d (FIXME)", offset))
		}
		code[pos-1] = byte(offset)
	}
}

func (Mach) UpdateCalls(l *links.L, code []byte) {
	for _, pos := range l.Sites {
		offset := l.Address - pos
		byteOrder.PutUint32(code[pos-4:pos], uint32(int32(offset)))
	}
}

func (Mach) PaddingByte() byte {
	return 0xf4 // hlt
}

func (Mach) FunctionAlign() int {
	return 16
}

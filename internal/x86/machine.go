// +build amd64
package x86

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
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

	functionAlign = 16
	paddingByte   = 0xf4 // hlt
)

var (
	byteOrder = binary.LittleEndian

	zero32 = make([]byte, 4)
)

type Machine struct{}

func (Machine) NewCoder() *Coder {
	return new(Coder)
}

type Coder struct {
	bytes.Buffer
}

func modRM(mod byte, ro, rm regs.R) byte {
	return (mod << 6) | (byte(ro) << 3) | byte(rm)
}

func sib(scale, index, base byte) byte {
	return (scale << 6) | (index << 3) | base
}

func sizePrefix(t types.T) []byte {
	switch {
	case t.Scalar32():
		return nil

	case t.Scalar64():
		return []byte{rexW}

	default:
		panic(t)
	}
}

func (code *Coder) TypedBinaryInst(t types.T, name string, source, target regs.R) {
	switch {
	case t.Int():
		code.intBinaryInst(t, name, source, target)

	case t.Float():
		code.floatBinaryInst(t, name, source, target)

	default:
		panic(t)
	}
}

var simpleIntBinaryOpcodes = map[string]byte{
	"add": 0x01,
	"and": 0x21,
	"or":  0x09,
	"sub": 0x29,
	"xor": 0x31,
}

func (code *Coder) intBinaryInst(t types.T, name string, source, target regs.R) {
	prefix := sizePrefix(t)

	// simple implementations

	if opcode, found := simpleIntBinaryOpcodes[name]; found {
		code.Write(prefix)
		code.WriteByte(opcode)
		code.WriteByte(modRM(modReg, source, target))
		return
	}

	// custom implementations

	switch name {
	case "ne":
		code.InstMoveRegToReg(target, regs.Scratch)
		code.InstClear(target)

		code.WriteByte(0xff) // inc
		code.WriteByte(modRM(modReg, 0, target))

		code.Write(prefix)
		code.WriteByte(0x29) // sub
		code.WriteByte(modRM(modReg, source, regs.Scratch))

		code.WriteByte(rexW)
		code.WriteByte(0x0f) // cmove
		code.WriteByte(0x44) //
		code.WriteByte(modRM(modReg, target, regs.Scratch))
		return

	default:
		panic(name)
	}
}

func (code *Coder) floatBinaryInst(t types.T, name string, source, target regs.R) {
	switch name {
	case "ne":
		// TODO
	}

	panic(fmt.Errorf("TODO: %s.%s", t, name))
}

func (code *Coder) InstAddToStackPtr(offset int) {
	if offset < -0x80000000 || offset > 0x7fffffff {
		panic(fmt.Errorf("stack offset too large: %d", offset))
	}

	code.WriteByte(rexW)
	code.WriteByte(0x81) // add
	code.WriteByte(modRM(modReg, 0, stackReg))
	binary.Write(code, byteOrder, uint32(offset))
}

func (code *Coder) InstBranchPlaceholder() {
	code.WriteByte(0xeb) // jmp
	code.WriteByte(0)    // dummy
}

func (code *Coder) InstBranchIfNotPlaceholder(reg regs.R) {
	code.WriteByte(0x89) // mov
	code.WriteByte(modRM(modReg, reg, reg))

	code.WriteByte(0x74) // jz
	code.WriteByte(0)    // dummy
}

func (code *Coder) InstCallPlaceholder() {
	code.WriteByte(0xe8) // call
	code.Write(zero32)   // dummy
}

func (code *Coder) InstClear(reg regs.R) {
	code.WriteByte(rexW)
	code.WriteByte(0x31) // xor
	code.WriteByte(modRM(modReg, reg, reg))
}

func (code *Coder) InstInvalid() {
	code.WriteByte(0x0f) // ub2
	code.WriteByte(0x0b) //
}

func (code *Coder) InstMoveImmToReg(t types.T, source interface{}, target regs.R) {
	prefix := sizePrefix(t)

	code.Write(prefix)
	code.WriteByte(0xb8 + byte(target)) // mov
	values.Write(code, byteOrder, t, source)

	switch {
	case t.Int():

	case t.Float():
		code.Write(prefix)
		code.WriteByte(0x0f) // movd
		code.WriteByte(0x6e) //
		code.WriteByte(modRM(modReg, target, target))

	default:
		panic(t)
	}
}

func (code *Coder) InstMoveRegToReg(source, target regs.R) {
	code.WriteByte(rexW)
	code.WriteByte(0x89) // mov
	code.WriteByte(modRM(modReg, source, target))
}

func (code *Coder) InstMoveVarToReg(sourceOffset int, target regs.R) {
	var disp byte
	var fixedOffset interface{}

	if sourceOffset < 0 {
		panic(fmt.Errorf("internal: local variable has negative stack offset: %d", sourceOffset))
	} else if sourceOffset < 0x80 {
		disp = modDisp8
		fixedOffset = uint8(sourceOffset)
	} else if sourceOffset < 0x8000 {
		disp = modDisp16
		fixedOffset = uint16(sourceOffset)
	} else {
		panic(fmt.Errorf("local variable has too large stack offset: %d", sourceOffset))
	}

	code.WriteByte(rexW)
	code.WriteByte(0x8b)                              // mov
	code.WriteByte(modRM(disp, target, regs.R(1<<2))) // si
	code.WriteByte(sib(0, 4, 4))                      // sp
	binary.Write(code, byteOrder, fixedOffset)
}

func (code *Coder) InstPop(reg regs.R) {
	code.WriteByte(0x58 + byte(reg))
}

func (code *Coder) InstPush(reg regs.R) {
	code.WriteByte(0x50 + byte(reg))
}

func (code *Coder) InstRet() {
	code.WriteByte(0xc3)
}

func (code *Coder) UpdateBranches(l *links.L) {
	for _, pos := range l.Sites {
		offset := l.Address - pos
		if offset < -128 || offset > 127 {
			panic(fmt.Errorf("branch offset too large: %d (FIXME)", offset))
		}

		code.Bytes()[pos-1] = byte(offset)
	}
}

func (code *Coder) UpdateCalls(l *links.L) {
	for _, pos := range l.Sites {
		offset := l.Address - pos
		if offset < -0x80000000 || offset > 0x7fffffff {
			panic(fmt.Errorf("call offset too large: %d", offset))
		}

		byteOrder.PutUint32(code.Bytes()[pos-4:pos], uint32(int32(offset)))
	}
}

func (code *Coder) PadFunction() {
	size := functionAlign - (code.Len() & (functionAlign - 1))

	for i := 0; i < size; i++ {
		code.WriteByte(paddingByte)
	}
}

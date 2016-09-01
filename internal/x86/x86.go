// +build amd64
package x86

import (
	"bytes"
	"encoding/binary"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

const (
	rexW = byte((1 << 6) | (1 << 3))

	modDisp8  = byte((0 << 1) | (1 << 0))
	modDisp16 = byte((1 << 1) | (0 << 0))
	modReg    = byte((1 << 1) | (1 << 0))

	segSI = 1 << 2

	//            regs.R0      rax
	//            regs.R1      rcx
	//            -            rdx
	regScratch  = regs.R(3) // rbx
	regStackPtr = 4         // rsp

	codeAlignment = 16
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

func (code *Coder) fromStack(mod byte, target regs.R) {
	code.WriteByte(modRM(mod, target, segSI))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
}

func (code *Coder) fromStackDisp(dispMod byte, disp interface{}, target regs.R) {
	code.fromStack(dispMod, target)
	binary.Write(code, byteOrder, disp)
}

func (code *Coder) toStack(mod byte, source regs.R) {
	code.WriteByte(modRM(mod, source, segSI))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
}

// regOp operates on a single register.
func regOp(intOp, floatOp func(regs.R), t types.T, subject regs.R) {
	switch t.Category() {
	case types.Int:
		intOp(subject)

	case types.Float:
		floatOp(subject)

	default:
		panic(t)
	}
}

// UnaryOp operates on a single typed register.
func (code *Coder) UnaryOp(name string, t types.T, subject regs.R) {
	switch t.Category() {
	case types.Int:
		code.intUnaryOp(name, t, subject)

	case types.Float:
		code.floatUnaryOp(name, t, subject)

	default:
		panic(t)
	}
}

// BinaryOp operates on two typed registers.
func (code *Coder) BinaryOp(name string, t types.T, source, target regs.R) {
	switch t.Category() {
	case types.Int:
		code.intBinaryOp(name, t, source, target)

	case types.Float:
		code.floatBinaryOp(name, t, source, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpAddToStackPtr(offset int) {
	code.opIntAdd64Imm(offset, regStackPtr)
}

func (code *Coder) OpInvalid() {
	// ub2
	code.WriteByte(0x0f)
	code.WriteByte(0x0b)
}

func (code *Coder) OpLoadStack(t types.T, sourceOffset int, target regs.R) {
	var dispMod byte
	var dispOffset interface{}

	switch {
	case sourceOffset < 0:
		panic(sourceOffset)

	case sourceOffset < 0x80:
		dispMod = modDisp8
		dispOffset = uint8(sourceOffset)

	case sourceOffset < 0x8000:
		dispMod = modDisp16
		dispOffset = uint16(sourceOffset)

	default:
		panic(sourceOffset)
	}

	switch t.Category() {
	case types.Int:
		code.instrIntMoveFromStackDisp(t, dispMod, dispOffset, target)

	case types.Float:
		code.instrFloatMoveFromStackDisp(t, dispMod, dispOffset, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpMove(t types.T, source, target regs.R) {
	code.BinaryOp("mov", t, source, target)
}

func (code *Coder) OpMoveImm(t types.T, value interface{}, target regs.R) {
	switch t.Category() {
	case types.Int:
		code.instrIntMoveImm(t, value, target)

	case types.Float:
		code.opFloatMoveImm(t, value, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpNop() {
	code.WriteByte(0x90)
}

func (code *Coder) OpPop(t types.T, target regs.R) {
	regOp(code.instrIntPop, code.opFloatPop, t, target)
}

func (code *Coder) OpPush(t types.T, source regs.R) {
	regOp(code.instrIntPush, code.opFloatPush, t, source)
}

func (code *Coder) OpReturn() {
	code.WriteByte(0xc3)
}

func (code *Coder) StubOpBranch() {
	// jmp
	code.WriteByte(0xeb)
	code.WriteByte(0)
}

func (code *Coder) StubOpBranchIfNot(t types.T, subject regs.R) {
	code.UnaryOp("eflags", t, subject)

	// jz
	code.WriteByte(0x74)
	code.WriteByte(0)
}

func (code *Coder) StubOpCall() {
	code.WriteByte(0xe8)
	code.Write(zero32)
}

func (code *Coder) UpdateBranches(l *links.L) {
	for _, pos := range l.Sites {
		offset := l.Address - pos
		if offset < -0x80 || 0x80 <= offset {
			panic(offset)
		}

		code.Bytes()[pos-1] = byte(offset)
	}
}

func (code *Coder) UpdateCalls(l *links.L) {
	for _, pos := range l.Sites {
		offset := l.Address - pos
		if offset < -0x80000000 || 0x80000000 <= offset {
			panic(offset)
		}

		byteOrder.PutUint32(code.Bytes()[pos-4:pos], uint32(int32(offset)))
	}
}

func (code *Coder) Align() {
	size := codeAlignment - (code.Len() & (codeAlignment - 1))
	if size < codeAlignment {
		for i := 0; i < size; i++ {
			code.WriteByte(paddingByte)
		}
	}
}

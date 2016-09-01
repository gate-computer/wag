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

	//           regs.R0      rax
	//           regs.R1      rcx
	//           -            rdx
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

func (code *Coder) UnaryOp(t types.T, name string, reg regs.R) {
	switch {
	case t.Int():
		code.intUnaryOp(t, name, reg)

	case t.Float():
		code.floatUnaryOp(t, name, reg)

	default:
		panic(t)
	}
}

func (code *Coder) BinaryOp(t types.T, name string, source, target regs.R) {
	switch {
	case t.Int():
		code.intBinaryOp(t, name, source, target)

	case t.Float():
		code.floatBinaryOp(t, name, source, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpAddToStackPtr(offset int) {
	switch {
	case -0x80 <= offset && offset < 0x80:
		code.instIntAddImm8(types.I64, int8(offset), regStackPtr)

	case -0x80000000 <= offset && offset < 0x80000000:
		code.instIntAddImm32(types.I64, int32(offset), regStackPtr)

	default:
		panic(offset)
	}
}

func (code *Coder) OpClear(reg regs.R) {
	code.instIntXor(types.I64, reg, reg)
}

func (code *Coder) OpInvalid() {
	// ub2
	code.WriteByte(0x0f)
	code.WriteByte(0x0b)
}

func (code *Coder) OpLoadStack(t types.T, sourceOffset int, target regs.R) {
	var dispMod byte
	var fixedOffset interface{}

	switch {
	case sourceOffset < 0:
		panic(sourceOffset)

	case sourceOffset < 0x80:
		dispMod = modDisp8
		fixedOffset = uint8(sourceOffset)

	case sourceOffset < 0x8000:
		dispMod = modDisp16
		fixedOffset = uint16(sourceOffset)

	default:
		panic(sourceOffset)
	}

	switch {
	case t.Int():
		code.instIntMoveFromStackDisp(t, dispMod, fixedOffset, target)

	case t.Float():
		code.instFloatMoveFromStackDisp(t, dispMod, fixedOffset, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpMove(t types.T, source, target regs.R) {
	switch {
	case t.Int():
		code.instIntMove(t, source, target)

	case t.Float():
		code.instFloatMove(t, source, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpMoveImm(t types.T, source interface{}, target regs.R) {
	switch {
	case t.Int():
		code.instIntMoveImm(t, source, target)

	case t.Float():
		code.instIntMoveImm(t, source, regScratch)
		code.instFloatMoveFromInt(t, regScratch, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpNop() {
	code.WriteByte(0x90)
}

func (code *Coder) OpPop(t types.T, reg regs.R) {
	switch {
	case t.Int():
		code.instIntPop(reg)

	case t.Float():
		code.opFloatPop(reg)

	default:
		panic(t)
	}
}

func (code *Coder) OpPush(t types.T, reg regs.R) {
	switch {
	case t.Int():
		code.instIntPush(reg)

	case t.Float():
		code.opFloatPush(reg)

	default:
		panic(t)
	}
}

func (code *Coder) OpReturn() {
	code.WriteByte(0xc3)
}

func (code *Coder) StubOpBranch() {
	// jmp
	code.WriteByte(0xeb)
	code.WriteByte(0)
}

func (code *Coder) StubOpBranchIfNot(t types.T, reg regs.R) {
	// update flags
	switch {
	case t.Int():
		code.instIntMove(t, reg, reg)

	case t.Float():
		code.instFloatEFLAGS(t, reg)
	}

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

package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

func intSizePrefix(t types.T) []byte {
	switch {
	case t.Scalar32():
		return nil

	case t.Scalar64():
		return []byte{rexW}

	default:
		panic(t)
	}
}

func (code *Coder) intUnaryOp(t types.T, name string, reg regs.R) {
	panic(name)
}

var intBinaryOpcodes = map[string]byte{
	"add": 0x01,
	"and": 0x21,
	"or":  0x09,
	"sub": 0x29,
	"xor": 0x31,
}

func (code *Coder) intBinaryOp(t types.T, name string, source, target regs.R) {
	prefix := intSizePrefix(t)

	if opcode, found := intBinaryOpcodes[name]; found {
		code.Write(prefix)
		code.WriteByte(opcode)
		code.WriteByte(modRM(modReg, source, target))
		return
	}

	switch name {
	case "ne":
		code.OpMove(t, target, regScratch)

		code.OpClear(target)

		code.WriteByte(0xff) // inc
		code.WriteByte(modRM(modReg, 0, target))

		code.Write(prefix)
		code.WriteByte(0x29) // sub
		code.WriteByte(modRM(modReg, source, regScratch))

		code.WriteByte(rexW)
		code.WriteByte(0x0f) // cmove
		code.WriteByte(0x44) //
		code.WriteByte(modRM(modReg, target, regScratch))
		return

	default:
		panic(name)
	}
}

// add sign-extended
func (code *Coder) instIntAddImm8(t types.T, imm int8, reg regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x83)
	code.WriteByte(modRM(modReg, 0, reg))
	code.WriteByte(uint8(imm))
}

// add sign-extended
func (code *Coder) instIntAddImm32(t types.T, imm int32, reg regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x81)
	code.WriteByte(modRM(modReg, 0, reg))
	binary.Write(code, byteOrder, imm)
}

// cmove
func (code *Coder) instIntCmove(t types.T, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x44)
	code.WriteByte(modRM(modReg, target, source))
}

// inc
func (code *Coder) instIntInc32(reg regs.R) {
	code.WriteByte(0xff)
	code.WriteByte(modRM(modReg, 0, reg))
}

// mov
func (code *Coder) instIntMove(t types.T, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x89)
	code.WriteByte(modRM(modReg, source, target))
}

// mov
func (code *Coder) instIntMoveImm(t types.T, source interface{}, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0xb8 + byte(target))
	values.Write(code, byteOrder, t, source)
}

// mov
func (code *Coder) instIntMoveFromStackDisp(t types.T, dispMod byte, offset interface{}, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x8b)
	code.WriteByte(modRM(dispMod, target, segSI))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
	binary.Write(code, byteOrder, offset)
}

// pop
func (code *Coder) instIntPop(reg regs.R) {
	code.WriteByte(0x58 + byte(reg))
}

// push
func (code *Coder) instIntPush(reg regs.R) {
	code.WriteByte(0x50 + byte(reg))
}

// xor
func (code *Coder) instIntXor(t types.T, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x31)
	code.WriteByte(modRM(modReg, target, source)) // XXX: check order
}

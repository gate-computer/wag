package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

func floatSizeCode(t types.T) byte {
	switch t {
	case types.F32:
		return 0xf3

	case types.F64:
		return 0xf2

	default:
		panic(t)
	}
}

func floatSizePrefix(t types.T) []byte {
	switch t {
	case types.F32:
		return nil

	case types.F64:
		return []byte{0x66}

	default:
		panic(t)
	}
}

func (code *Coder) floatUnaryOp(t types.T, name string, reg regs.R) {
	switch name {
	case "neg":
		code.instFloatMove(t, reg, regScratch)
		code.instFloatXor(reg, reg)
		code.instFloatSub(t, regScratch, reg)
		return
	}

	// TODO: panic
	code.OpInvalid()
}

func (code *Coder) floatBinaryOp(t types.T, name string, source, target regs.R) {
	switch name {
	case "ne":
		code.instIntXor(types.I32, regScratch, regScratch)
		code.instIntXor(types.I64, target, target)
		code.instIntInc32(target)
		code.instFloatCompare(t, source, target)
		code.instIntCmove(types.I32, regScratch, target)
		return
	}

	// TODO: panic
	code.OpInvalid()
}

func (code *Coder) opFloatPop(reg regs.R) {
	code.instFloatMoveFromStack(reg)
	code.instIntAddImm8(types.I64, 8, regStackPtr)
}

func (code *Coder) opFloatPush(reg regs.R) {
	code.instIntAddImm8(types.I64, -8, regStackPtr)
	code.instFloatMoveToStack(reg)
}

// ucomiss, ucomisd
func (code *Coder) instFloatCompare(t types.T, source, target regs.R) {
	code.Write(floatSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x2e)
	code.WriteByte(modRM(modReg, target, source))
}

// ?
func (code *Coder) instFloatEFLAGS(t types.T, reg regs.R) {
	code.OpInvalid()
}

// movss, movsd
func (code *Coder) instFloatMove(t types.T, source, target regs.R) {
	code.WriteByte(floatSizeCode(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x11)
	code.WriteByte(modRM(modReg, target, source))
}

// movd, movq
func (code *Coder) instFloatMoveFromInt(t types.T, source, target regs.R) {
	code.WriteByte(0x66)
	code.Write(intSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x6e)
	code.WriteByte(modRM(modReg, target, source))
}

// movdqa
func (code *Coder) instFloatMoveFromStack(source regs.R) {
	code.WriteByte(0x66)
	code.WriteByte(0x0f)
	code.WriteByte(0x6f)
	code.WriteByte(modRM(0, source, segSI))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
}

// movdqa
func (code *Coder) instFloatMoveFromStackDisp(t types.T, dispMod byte, offset interface{}, source regs.R) {
	code.WriteByte(floatSizeCode(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x6f)
	code.WriteByte(modRM(dispMod, source, segSI))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
	binary.Write(code, byteOrder, offset)
}

// movdqa
func (code *Coder) instFloatMoveToStack(source regs.R) {
	code.WriteByte(0x66)
	code.WriteByte(0x0f)
	code.WriteByte(0x7f)
	code.WriteByte(modRM(0, source, segSI))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
}

// subss, subsd
func (code *Coder) instFloatSub(t types.T, source, target regs.R) {
	code.WriteByte(floatSizeCode(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x5c)
	code.WriteByte(modRM(modReg, target, source))
}

// pxor
func (code *Coder) instFloatXor(source, target regs.R) {
	code.WriteByte(0x66)
	code.WriteByte(0x0f)
	code.WriteByte(0xef)
	code.WriteByte(modRM(modReg, target, source)) // XXX: check order
}

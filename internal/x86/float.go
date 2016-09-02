package x86

import (
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

func (code *Coder) floatUnaryOp(name string, t types.T, subject regs.R) {
	switch name {
	case "eflags": // internal
		code.OpInvalid() // TODO

	case "neg":
		code.instrFloatMov(t, subject, regScratch)
		code.instrFloatXor(subject, subject)
		code.instrFloatSub(t, regScratch, subject)

	default:
		panic(name)
	}
}

func (code *Coder) floatBinaryOp(name string, t types.T, source, target regs.R) {
	switch name {
	case "mov": // internal
		code.instrFloatMov(t, source, target)

	case "ne":
		code.intBinaryOp("xor", types.I32, regScratch, regScratch)
		code.instrIntMov32Imm(1, target)                  // int target reg
		code.instrFloatUcomi(t, source, target)           // float target reg
		code.instrIntCmove(types.I32, regScratch, target) // int target reg

	case "sub":
		code.instrFloatSub(t, source, target)

	case "xor":
		code.instrFloatXor(source, target)

	default:
		panic(name)
	}
}

func (code *Coder) opFloatMoveImm(t types.T, value interface{}, target regs.R) {
	code.instrIntMovImm(t, value, regScratch)
	code.instrFloatMovFromIntReg(t, regScratch, target)
}

func (code *Coder) opFloatPop(target regs.R) {
	code.instrFloatMovFromStack(types.F64, target)
	code.instrIntAdd64Imm(opcodeIntAdd64Imm8, int8(8), regStackPtr)
}

func (code *Coder) opFloatPush(source regs.R) {
	code.instrIntAdd64Imm(opcodeIntAdd64Imm8, int8(-8), regStackPtr)
	code.instrFloatMovToStack(types.F64, source)
}

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

// ucomiss, ucomisd
func (code *Coder) instrFloatUcomi(t types.T, source, target regs.R) {
	code.Write(floatSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x2e)
	code.WriteByte(modRM(modReg, target, source))
}

// movss, movsd
func (code *Coder) instrFloatMov(t types.T, source, target regs.R) {
	code.WriteByte(floatSizeCode(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x11)
	code.WriteByte(modRM(modReg, source, target))
}

// movd, movq
func (code *Coder) instrFloatMovFromIntReg(t types.T, source, target regs.R) {
	code.WriteByte(0x66)
	code.Write(intSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x6e)
	code.WriteByte(modRM(modReg, target, source))
}

// movddup
func (code *Coder) instrFloatMovFromStack(t types.T, target regs.R) {
	code.WriteByte(0x66)
	code.Write(intSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x6e)
	code.fromStack(0, target)
}

// movdqu
func (code *Coder) instrFloatMovFromBaseDisp(mod byte, disp interface{}, target regs.R) {
	code.WriteByte(0xf3)
	code.WriteByte(0x0f)
	code.WriteByte(0x6f)
	code.fromBaseDisp(mod, disp, target)
}

// movdqu
func (code *Coder) instrFloatMovToStack(t types.T, source regs.R) {
	code.WriteByte(0x66)
	code.Write(intSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x7e)
	code.toStack(0, source)
}

// subss, subsd
func (code *Coder) instrFloatSub(t types.T, source, target regs.R) {
	code.WriteByte(floatSizeCode(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x5c)
	code.WriteByte(modRM(modReg, target, source))
}

// xorps
func (code *Coder) instrFloatXor(source, target regs.R) {
	code.WriteByte(0x0f)
	code.WriteByte(0x57)
	code.WriteByte(modRM(modReg, source, target))
}

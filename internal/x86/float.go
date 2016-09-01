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
		code.floatBinaryOp("mov", t, subject, regScratch)
		code.floatBinaryOp("xor", t, subject, subject)
		code.floatBinaryOp("sub", t, regScratch, subject)

	default:
		panic(name)
	}
}

func (code *Coder) floatBinaryOp(name string, t types.T, source, target regs.R) {
	if opcode, found := floatBinaryOpcodes[name]; found {
		code.floatBinaryInstr(t, opcode, source, target)
		return
	}

	switch name {
	case "ne":
		code.intBinaryOp("xor", types.I32, regScratch, regScratch)
		code.opIntMoveImmValue1(types.I32, target)        // int target reg
		code.instrFloatCompare(t, source, target)         // float target reg
		code.instrIntCmove(types.I32, regScratch, target) // int target reg

	default:
		panic(name)
	}
}

func (code *Coder) opFloatPop(target regs.R) {
	code.instrFloatMoveFromStack(target)
	code.instrIntAdd64Imm(opcodeIntAdd64Imm8, 8, regStackPtr)
}

func (code *Coder) opFloatPush(source regs.R) {
	code.instrIntAdd64Imm(opcodeIntAdd64Imm8, -8, regStackPtr)
	code.instrFloatMoveToStack(source)
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

var floatBinaryOpcodes = map[string]byte{
	"mov": 0x11, // internal
	"sub": 0x5c,
	"xor": 0xef,
}

func (code *Coder) floatBinaryInstr(t types.T, opcodeFloatBinary byte, source, target regs.R) {
	code.WriteByte(floatSizeCode(t))
	code.WriteByte(0x0f)
	code.WriteByte(opcodeFloatBinary)
	code.WriteByte(modRM(modReg, target, source))
}

// ucomiss, ucomisd
func (code *Coder) instrFloatCompare(t types.T, source, target regs.R) {
	code.Write(floatSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x2e)
	code.WriteByte(modRM(modReg, target, source))
}

// movd, movq
func (code *Coder) instrFloatMoveFromIntReg(t types.T, source, target regs.R) {
	code.WriteByte(0x66)
	code.Write(intSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x6e)
	code.WriteByte(modRM(modReg, target, source))
}

// movdqa
func (code *Coder) instrFloatMoveFromStack(target regs.R) {
	code.WriteByte(0x66)
	code.WriteByte(0x0f)
	code.WriteByte(0x6f)
	code.fromStack(0, target)
}

// movdqa
func (code *Coder) instrFloatMoveFromStackDisp(t types.T, mod byte, disp interface{}, target regs.R) {
	code.WriteByte(floatSizeCode(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x6f)
	code.fromStackDisp(mod, disp, target)
}

// movdqa
func (code *Coder) instrFloatMoveToStack(source regs.R) {
	code.WriteByte(0x66)
	code.WriteByte(0x0f)
	code.WriteByte(0x7f)
	code.toStack(0, source)
}

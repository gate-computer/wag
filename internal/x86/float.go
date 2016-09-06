package x86

import (
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

func (code *Coder) opFloatUnary(name string, t types.T, subject regs.R) {
	switch name {
	case "neg":
		code.instrFloatMov(t, subject, regScratch)
		code.instrFloatXor(subject, subject)
		code.instrFloatSub(t, regScratch, subject)

	default:
		panic(name)
	}
}

func (code *Coder) opFloatBinary(name string, t types.T, source, target regs.R) {
	switch name {
	case "eq":
		code.instrFloatUcomi(t, source, target)
		code.instrIntSetcc(opcodeIntSete, target)
		code.instrIntMovZeroExt32(target, target)

	case "ne":
		code.instrFloatUcomi(t, source, target)
		code.instrIntSetcc(opcodeIntSetne, target)
		code.instrIntMovZeroExt32(target, target)

	case "sub":
		code.instrFloatSub(t, source, target)

	case "xor":
		code.instrFloatXor(source, target)

	default:
		panic(name)
	}
}

func (code *Coder) opFloatPop(target regs.R) {
	code.instrFloatMovFromStack(0, nil, target)
	code.instrIntImm(opcodeIntImmAdd, types.I64, wordSize, regStackPtr)
}

func (code *Coder) opFloatPush(source regs.R) {
	code.instrIntImm(opcodeIntImmSub, types.I64, wordSize, regStackPtr)
	code.instrFloatMovToStack(source)
}

func (code *Coder) instrFloatUcomi(t types.T, source, target regs.R) {
	code.Write(floatSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x2e) // ucomiss, ucomisd
	code.WriteByte(modRM(modReg, target, source))
}

func (code *Coder) instrFloatMov(t types.T, source, target regs.R) {
	code.WriteByte(floatSizeCode(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x11) // movss, movsd
	code.WriteByte(modRM(modReg, source, target))
}

func (code *Coder) instrFloatMovFromInt(t types.T, source, target regs.R) {
	code.WriteByte(0x66)
	code.Write(intPrefix(t, 0, false))
	code.WriteByte(0x0f)
	code.WriteByte(0x6e) // movd, movq
	code.WriteByte(modRM(modReg, target, source))
}

func (code *Coder) instrFloatMovFromStack(mod byte, disp interface{}, target regs.R) {
	if mod == 0 {
		code.WriteByte(0x66)
		code.WriteByte(rexW)
		code.WriteByte(0x0f)
		code.WriteByte(0x6e) // movq
	} else {
		code.WriteByte(0xf3)
		code.WriteByte(0x0f)
		code.WriteByte(0x6f) // movdqu
	}
	code.fromStack(mod, disp, target)
}

func (code *Coder) instrFloatMovToStack(source regs.R) {
	code.WriteByte(0x66)
	code.WriteByte(rexW)
	code.WriteByte(0x0f)
	code.WriteByte(0x7e) // movq
	code.toStack(0, nil, source)
}

func (code *Coder) instrFloatSub(t types.T, source, target regs.R) {
	code.WriteByte(floatSizeCode(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x5c) // subss, subsd
	code.WriteByte(modRM(modReg, target, source))
}

func (code *Coder) instrFloatXor(source, target regs.R) {
	code.WriteByte(0x0f)
	code.WriteByte(0x57) // xorps
	code.WriteByte(modRM(modReg, source, target))
}

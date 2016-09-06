package x86

import (
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

func intPrefix(t types.T, ro regs.R, signExt bool) (prefix []byte) {
	var rex byte

	if ro >= 8 {
		rex |= rexB
	}

	switch {
	case t.Size() == types.Size64 || signExt:
		rex |= rexW

	case t.Size() == types.Size32:

	default:
		panic(t)
	}

	if rex != 0 {
		prefix = []byte{rex}
	}

	return
}

func (code *Coder) opIntUnary(name string, t types.T, subject regs.R) {
	switch name {
	case "eqz":
		code.instrIntTest(t, subject, subject)
		code.instrIntSetcc(opcodeIntSete, subject)
		code.instrIntMovZeroExt32(subject, subject)

	default:
		panic(name)
	}
}

func (code *Coder) opIntBinary(name string, t types.T, source, target regs.R) {
	if opcode, found := opcodeIntBinary[name]; found {
		code.instrIntBinary(opcode, t, source, target)
		return
	}

	switch name {
	case "ne":
		code.opIntBinary("sub", t, source, target)
		code.instrIntSetcc(opcodeIntSetne, target)
		code.instrIntMovZeroExt32(target, target)

	default:
		panic(name)
	}
}

var opcodeIntBinary = map[string]byte{
	"add": 0x01,
	"and": 0x21,
	"or":  0x09,
	"sub": 0x29,
	"xor": 0x31,
}

func (code *Coder) instrIntBinary(opcode byte, t types.T, source, target regs.R) {
	code.Write(intPrefix(t, source, false))
	code.WriteByte(opcode)
	code.WriteByte(modRM(modReg, source, target))
}

const (
	opcodeIntImmAdd = 0x0
	opcodeIntImmSub = 0x5
)

func (code *Coder) instrIntImm(opcode byte, t types.T, value int, target regs.R) {
	var immsize byte
	var imm interface{}

	switch {
	case -0x80 <= value && value < 0x80:
		immsize = 0x83
		imm = int8(value)

	case -0x80000000 <= value && value < 0x80000000:
		immsize = 0x81
		imm = int32(value)

	default:
		panic(value)
	}

	code.Write(intPrefix(t, 0, false))
	code.WriteByte(immsize)
	code.WriteByte(modRM(modReg, regs.R(opcode), target))
	code.immediate(imm)
}

const (
	opcodeIntCmovl = 0x4c
)

func (code *Coder) instrIntCmov(opcode byte, t types.T, source, target regs.R) {
	code.Write(intPrefix(t, target, false))
	code.WriteByte(0x0f)
	code.WriteByte(opcode)
	code.WriteByte(modRM(modReg, target, source))
}

func (code *Coder) instrIntMov(t types.T, source, target regs.R, signExt bool) {
	if t.Size() == types.Size32 && signExt {
		code.Write(intPrefix(t, target, signExt))
		code.WriteByte(0x63) // movsxd
		code.WriteByte(modRM(modReg, target, source))
	} else {
		code.Write(intPrefix(t, source, signExt))
		code.WriteByte(0x89) // mov
		code.WriteByte(modRM(modReg, source, target))
	}
}

func (code *Coder) instrIntMovFromStack(t types.T, mod byte, disp interface{}, target regs.R, signExt bool) {
	code.Write(intPrefix(t, 0, signExt))

	if t.Size() == types.Size32 && signExt {
		code.WriteByte(0x63) // movsxd
	} else {
		code.WriteByte(0x8b) // mov
	}

	code.fromStack(mod, disp, target)
}

func (code *Coder) instrIntMovFromIndirect(t types.T, source, target regs.R, signExt bool) {
	code.Write(intPrefix(t, target, signExt))

	if t.Size() == types.Size32 && signExt {
		code.WriteByte(0x63) // movsxd
	} else {
		code.WriteByte(0x8b) // mov
	}

	code.WriteByte(modRM(0, target, source))
}

func (code *Coder) instrIntMovImm(t types.T, value interface{}, target regs.R) {
	code.Write(intPrefix(t, 0, false))
	code.WriteByte(0xb8 + byte(target))
	code.immediate(value)
}

func (code *Coder) instrIntMovZeroExt32(source, target regs.R) {
	code.WriteByte(0x0f)
	code.WriteByte(0xb6) // movzx
	code.WriteByte(modRM(modReg, target, source))
}

func (code *Coder) instrIntPop(target regs.R) {
	code.WriteByte(0x58 + byte(target))
}

func (code *Coder) instrIntPush(source regs.R) {
	code.WriteByte(0x50 + byte(source))
}

const (
	opcodeIntSete  = 0x94
	opcodeIntSetne = 0x95
)

func (code *Coder) instrIntSetcc(opcode byte, subject regs.R) {
	code.WriteByte(0x0f)
	code.WriteByte(opcode)
	code.WriteByte(modRM(modReg, 0, subject))
}

const (
	opcodeIntImmShl = 0x0
	opcodeIntImmShr = 0x5
)

func (code *Coder) instrIntImmSh(opcode byte, t types.T, count uint8, target regs.R) {
	code.Write(intPrefix(t, 0, false))
	code.WriteByte(0xc1)
	code.WriteByte(modRM(modReg, regs.R(opcode), target))
	code.immediate(count)
}

func (code *Coder) instrIntTest(t types.T, source, target regs.R) {
	code.Write(intPrefix(t, target, false))
	code.WriteByte(0x85)
	code.WriteByte(modRM(modReg, target, source))
}

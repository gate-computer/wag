package x86

import (
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

func (code *Coder) intUnaryOp(name string, t types.T, subject regs.R) {
	switch name {
	case "eqz":
		code.instrIntMov32Imm(1, regScratch)
		code.instrIntTest(t, subject, subject)
		code.instrIntCmove(types.I32, regScratch, subject)

	case "test": // internal
		code.instrIntTest(t, subject, subject)

	default:
		panic(name)
	}
}

func (code *Coder) intBinaryOp(name string, t types.T, source, target regs.R) {
	if opcode, found := intBinaryOpcodes[name]; found {
		code.intBinaryInstr(t, opcode, source, target)
		return
	}

	switch name {
	case "ne":
		code.OpMove(t, target, regScratch)
		code.instrIntMov32Imm(1, target)
		code.intBinaryOp("sub", t, source, regScratch)
		code.instrIntCmove(types.I32, regScratch, target)

	default:
		panic(name)
	}
}

var intBinaryOpcodes = map[string]byte{
	"add": 0x01,
	"and": 0x21,
	"mov": 0x89, // internal
	"or":  0x09,
	"sub": 0x29,
	"xor": 0x31,
}

func (code *Coder) intBinaryInstr(t types.T, opcodeIntBinary byte, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(opcodeIntBinary)
	code.WriteByte(modRM(modReg, source, target))
}

func (code *Coder) opIntAdd64Imm(value int, target regs.R) {
	switch {
	case -0x80 <= value && value < 0x80:
		code.instrIntAdd64Imm(opcodeIntAdd64Imm8, int8(value), target)

	case -0x80000000 <= value && value < 0x80000000:
		code.instrIntAdd64Imm(opcodeIntAdd64Imm32, int32(value), target)

	default:
		panic(value)
	}
}

func intSizePrefix(t types.T) []byte {
	switch t.Size() {
	case types.Size32:
		return nil

	case types.Size64:
		return []byte{rexW}

	default:
		panic(t)
	}
}

const (
	opcodeIntAdd64Imm8  = 0x83
	opcodeIntAdd64Imm32 = 0x81
)

// add sign-extended
func (code *Coder) instrIntAdd64Imm(opcodeIntAdd64Imm byte, value interface{}, target regs.R) {
	code.WriteByte(rexW)
	code.WriteByte(opcodeIntAdd64Imm)
	code.WriteByte(modRM(modReg, 0, target))
	code.immediate(value)
}

// cmove
func (code *Coder) instrIntCmove(t types.T, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(0x44)
	code.WriteByte(modRM(modReg, target, source))
}

// mov
func (code *Coder) instrIntMovImm(t types.T, value interface{}, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0xb8 + byte(target))
	code.immediate(values.Parse(t, value))
}

// mov
func (code *Coder) instrIntMov32Imm(value int32, target regs.R) {
	code.WriteByte(0xb8 + byte(target))
	code.immediate(value)
}

// mov
func (code *Coder) instrIntMovFromStackDisp(t types.T, mod byte, offset interface{}, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x8b)
	code.fromStackDisp(mod, offset, target)
}

// pop
func (code *Coder) instrIntPop(target regs.R) {
	code.WriteByte(0x58 + byte(target))
}

// push
func (code *Coder) instrIntPush(source regs.R) {
	code.WriteByte(0x50 + byte(source))
}

// test
func (code *Coder) instrIntTest(t types.T, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x85)
	code.WriteByte(modRM(modReg, target, source))
}

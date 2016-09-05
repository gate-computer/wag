package x86

import (
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

func (code *Coder) intUnaryOp(name string, t types.T, subject regs.R) {
	switch name {
	case "eqz":
		code.instrIntTest(t, subject, subject)
		code.instrIntSetcc(opcodeIntSete, subject)
		code.instrIntMovzx32(subject, subject)

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
		code.intBinaryOp("sub", t, source, target)
		code.instrIntSetcc(opcodeIntSetne, target)
		code.instrIntMovzx32(target, target)

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

func (code *Coder) intBinaryInstr(t types.T, opcode byte, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(opcode)
	code.WriteByte(modRM(modReg, source, target))
}

func (code *Coder) opIntAdd64Imm(value int, target regs.R) {
	switch {
	case -0x80 <= value && value < 0x80:
		code.instrIntAddSubImm(opcodeIntAddImm, types.I64, immsizeIntAddSub8, int8(value), target)

	case -0x80000000 <= value && value < 0x80000000:
		code.instrIntAddSubImm(opcodeIntAddImm, types.I64, immsizeIntAddSub32, int32(value), target)

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
	opcodeIntAddImm = 0x0
	opcodeIntSubImm = 0x5

	immsizeIntAddSub8  = 0x83
	immsizeIntAddSub32 = 0x81
)

func (code *Coder) instrIntAddSubImm(opcode byte, t types.T, immsize byte, value interface{}, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(immsize)
	code.WriteByte(modRM(modReg, regs.R(opcode), target))
	code.immediate(value)
}

const (
	opcodeIntCmove = 0x44
	opcodeIntCmovl = 0x4c
)

func (code *Coder) instrIntCmov(opcode byte, t types.T, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x0f)
	code.WriteByte(opcode)
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
func (code *Coder) instrIntMovFromStack(t types.T, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x8b)
	code.fromStack(0, target)
}

// mov
func (code *Coder) instrIntMovFromStackDisp(t types.T, mod byte, offset interface{}, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x8b)
	code.fromStackDisp(mod, offset, target)
}

// movsxd
func (code *Coder) instrIntMovsxdFromStack(target regs.R) {
	code.WriteByte(rexW)
	code.WriteByte(0x63)
	code.fromStack(0, target)
}

// movsxd
func (code *Coder) instrIntMovsxdFromStackDisp(mod byte, offset interface{}, target regs.R) {
	code.WriteByte(rexW)
	code.WriteByte(0x63)
	code.fromStackDisp(mod, offset, target)
}

// mov
func (code *Coder) instrIntMovFromMemIndirect(t types.T, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x8b)
	code.WriteByte(modRM(0, target, source))
}

// movsxd
func (code *Coder) instrIntMovsxd(source, target regs.R) {
	code.WriteByte(rexW)
	code.WriteByte(0x63)
	code.WriteByte(modRM(modReg, target, source))
}

// movsxd
func (code *Coder) instrIntMovsxdFromMemIndirect(source, target regs.R) {
	code.WriteByte(rexW)
	code.WriteByte(0x63)
	code.WriteByte(modRM(0, target, source))
}

// movzx
func (code *Coder) instrIntMovzx32(source, target regs.R) {
	code.WriteByte(0x0f)
	code.WriteByte(0xb6)
	code.WriteByte(modRM(modReg, target, source))
}

// pop
func (code *Coder) instrIntPop(target regs.R) {
	code.WriteByte(0x58 + byte(target))
}

// push
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
	opcodeIntShlImm = 0x0
	opcodeIntShrImm = 0x5
)

func (code *Coder) instrIntShImm(opcode byte, t types.T, count uint8, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0xc1)
	code.WriteByte(modRM(modReg, regs.R(opcode), target))
	code.immediate(count)
}

// test
func (code *Coder) instrIntTest(t types.T, source, target regs.R) {
	code.Write(intSizePrefix(t))
	code.WriteByte(0x85)
	code.WriteByte(modRM(modReg, target, source))
}

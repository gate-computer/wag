package x86

import (
	"strconv"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

const (
	rexW = (1 << 6) | (1 << 3)
	rexR = (1 << 6) | (1 << 2)
	rexX = (1 << 6) | (1 << 1)
	rexB = (1 << 6) | (1 << 0)
)

func writeRexTo(code gen.Coder, rex byte, ro, index, rmOrBase regs.R) {
	if ro >= 8 {
		rex |= rexR
	}
	if index >= 8 {
		rex |= rexX
	}
	if rmOrBase >= 8 {
		rex |= rexB
	}

	if rex != 0 {
		code.WriteByte(rex)
	}
}

type mod byte

const (
	ModIndir       = mod(0)
	ModIndirDisp8  = mod((0 << 7) | (1 << 6))
	ModIndirDisp32 = mod((1 << 7) | (0 << 6))
	ModReg         = mod((1 << 7) | (1 << 6))
)

func (mod mod) writeTo(code gen.Coder, ro, rm byte) {
	code.WriteByte(byte(mod) | ((ro & 7) << 3) | (rm & 7))
}

type mem byte

const (
	MemDisp32 = mem((1 << 2) | (1 << 0))
)

type modOp struct {
	mod    mod
	opcode byte
}

func (modOp modOp) writeTo(code gen.Coder, rm byte) {
	modOp.mod.writeTo(code, modOp.opcode, rm)
}

type modMem struct {
	mod mod
	mem mem
}

func (modMem modMem) writeTo(code gen.Coder, ro byte) {
	modMem.mod.writeTo(code, ro, byte(modMem.mem))
}

func dispMod(t types.T, offset int) (mod mod, disp imm) {
	switch {
	case offset == 0:
		mod = ModIndir

	case t.Size() == types.Size64 && (offset&7) != 0:
		panic(offset)

	case (offset & 3) != 0:
		panic(offset)

	case -0x80 <= offset && offset < 0x80:
		mod = ModIndirDisp8
		disp = imm8(offset)

	case -0x80000000 <= offset && offset < 0x80000000:
		mod = ModIndirDisp32
		disp = imm32(offset)

	default:
		panic(offset)
	}

	return
}

func writeSibTo(code gen.Coder, scale, index, base byte) {
	if scale >= 4 {
		panic(strconv.Itoa(int(scale)))
	}

	code.WriteByte((scale << 6) | ((index & 7) << 3) | (base & 7))
}

type sib struct {
	scale byte
	index byte
	base  byte
}

func (sib sib) writeTo(code gen.Coder) {
	writeSibTo(code, sib.scale, sib.index, sib.base)
}

type prefix interface {
	writeTo(gen.Coder, types.T, regs.R, regs.R, regs.R)
}

type nullaryInsn interface {
	op(code gen.Coder)
}

type unaryInsn interface {
	op(code gen.Coder, subject regs.R)
}

type binaryInsn interface {
	op(code gen.Coder, t types.T, target, source regs.R)
}

type insnFixed []byte

func (bytes insnFixed) op(code gen.Coder) {
	code.Write([]byte(bytes))
}

// TODO: does this work with rexB prefix?
type insnReg struct {
	base byte
}

func (i insnReg) op(code gen.Coder, reg regs.R) {
	if reg >= 8 {
		panic(reg)
	}

	code.WriteByte(i.base + (byte(reg) & 7))
}

type insnReg_sizeless_PrefixModOpReg struct {
	low  insnReg
	high insnPrefixModOpReg
}

func (i insnReg_sizeless_PrefixModOpReg) op(code gen.Coder, reg regs.R) {
	if reg < 8 {
		i.low.op(code, reg)
	} else {
		i.high.op(code, types.I32, reg)
	}
}

type insnModRegFromReg []byte

func (bytes insnModRegFromReg) op(code gen.Coder, target, source regs.R) {
	writeRexTo(code, 0, target, 0, source)
	code.Write([]byte(bytes))
	ModReg.writeTo(code, byte(target), byte(source))
}

type insnModOpReg struct {
	bytes []byte
	ro    byte
}

func (i insnModOpReg) op(code gen.Coder, reg regs.R) {
	writeRexTo(code, 0, 0, 0, reg)
	code.Write(i.bytes)
	ModReg.writeTo(code, i.ro, byte(reg))
}

type insnModRegMemImm struct {
	bytes  []byte
	modMem modMem
}

func (i insnModRegMemImm) op(code gen.Coder, reg regs.R, imm imm) {
	code.Write(i.bytes)
	i.modMem.writeTo(code, byte(reg))
	imm.writeTo(code)
}

type insnPrefixRegImm struct {
	prefix prefix
	base   byte
}

func (i insnPrefixRegImm) op(code gen.Coder, t types.T, reg regs.R, imm imm) {
	i.prefix.writeTo(code, t, 0, 0, reg)
	code.WriteByte(i.base + (byte(reg) & 7))
	imm.writeTo(code)
}

type insnPrefixModOpReg struct {
	prefix prefix
	bytes  []byte
	ro     byte
}

func (i insnPrefixModOpReg) op(code gen.Coder, t types.T, reg regs.R) {
	i.prefix.writeTo(code, t, 0, 0, reg)
	code.Write(i.bytes)
	ModReg.writeTo(code, i.ro, byte(reg))
}

type insnPrefixModRegFromReg struct {
	prefix prefix
	bytes  []byte
	mod    mod
}

func (i insnPrefixModRegFromReg) op(code gen.Coder, t types.T, target, source regs.R) {
	i.prefix.writeTo(code, t, target, 0, source)
	code.Write(i.bytes)
	i.mod.writeTo(code, byte(target), byte(source))
}

type insnPrefixModRegToReg struct {
	prefix prefix
	bytes  []byte
	mod    mod
}

func (i insnPrefixModRegToReg) op(code gen.Coder, t types.T, target, source regs.R) {
	i.prefix.writeTo(code, t, source, 0, target)
	code.Write(i.bytes)
	i.mod.writeTo(code, byte(source), byte(target))
}

type insnPrefixModRegFromRegDisp struct {
	prefix prefix
	bytes  []byte
}

func (i insnPrefixModRegFromRegDisp) op(code gen.Coder, t types.T, target, source regs.R, disp int) {
	mod, imm := dispMod(t, disp)

	i.prefix.writeTo(code, t, target, 0, source)
	code.Write(i.bytes)
	mod.writeTo(code, byte(target), byte(source))
	imm.writeTo(code)
}

type insnPrefixModOpRegImm struct {
	prefix prefix
	bytes  []byte
	ro     byte
}

func (i insnPrefixModOpRegImm) op(code gen.Coder, t types.T, reg regs.R, imm imm) {
	i.prefix.writeTo(code, t, 0, 0, reg)
	code.Write(i.bytes)
	ModReg.writeTo(code, i.ro, byte(reg))
	imm.writeTo(code)
}

type insnPrefixModRegSibImm struct {
	prefix prefix
	bytes  []byte
	sib    sib
}

func (i insnPrefixModRegSibImm) op(code gen.Coder, t types.T, reg regs.R, disp int) {
	mod, imm := dispMod(t, disp)

	i.prefix.writeTo(code, t, reg, 0, 0)
	code.Write(i.bytes)
	mod.writeTo(code, byte(reg), 1<<2)
	i.sib.writeTo(code)
	imm.writeTo(code)
}

type insnPrefixModRegCustomSibImm struct {
	prefix prefix
	bytes  []byte
}

func (i insnPrefixModRegCustomSibImm) op(code gen.Coder, t types.T, reg regs.R, scale uint8, index, base regs.R, disp int) {
	mod, imm := dispMod(t, disp)

	i.prefix.writeTo(code, t, reg, index, base)
	code.Write(i.bytes)
	mod.writeTo(code, byte(reg), 1<<2)
	writeSibTo(code, scale, byte(index), byte(base))
	imm.writeTo(code)
}

type insnPrefixArithmeticModOpRegImm struct {
	prefix prefix
	ro     byte
}

func (i insnPrefixArithmeticModOpRegImm) op(code gen.Coder, t types.T, reg regs.R, value int) {
	var opcode byte
	var imm imm

	switch {
	case -0x80 <= value && value < 0x80:
		opcode = 0x83
		imm = imm8(value)

	case -0x80000000 <= value && value < 0x80000000:
		opcode = 0x81
		imm = imm32(value)

	default:
		panic(value)
	}

	i.prefix.writeTo(code, t, 0, 0, reg)
	code.WriteByte(opcode)
	ModReg.writeTo(code, i.ro, byte(reg))
	imm.writeTo(code)
}

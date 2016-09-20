package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

type prefix interface {
	writeTo(code gen.Coder, t types.T, ro, index, rmOrBase byte)
}

const (
	rexW = (1 << 6) | (1 << 3)
	rexR = (1 << 6) | (1 << 2)
	rexX = (1 << 6) | (1 << 1)
	rexB = (1 << 6) | (1 << 0)
)

func writeRexTo(code gen.Coder, rex, ro, index, rmOrBase byte) {
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

func writeRexSizeTo(code gen.Coder, t types.T, ro, index, rmOrBase byte) {
	var rex byte

	switch t.Size() {
	case types.Size32:

	case types.Size64:
		rex |= rexW

	default:
		panic(t)
	}

	writeRexTo(code, rex, ro, index, rmOrBase)
}

type mod byte

const (
	ModMem       = mod(0)
	ModMemDisp8  = mod((0 << 7) | (1 << 6))
	ModMemDisp32 = mod((1 << 7) | (0 << 6))
	ModReg       = mod((1 << 7) | (1 << 6))
)

func dispMod(t types.T, baseReg regs.R, offset int) (mod mod, disp imm) {
	switch {
	case offset == 0 && (baseReg&7) != 0x5: // rbp and r13 need displacement
		mod = ModMem

	case t.Size() == types.Size64 && (offset&7) != 0:
		panic("alignment of displacement is not 8")

	case (offset & 3) != 0:
		panic("alignment of displacement is not 4")

	case -0x80 <= offset && offset < 0x80:
		mod = ModMemDisp8
		disp = imm8(offset)

	case -0x80000000 <= offset && offset < 0x80000000:
		mod = ModMemDisp32
		disp = imm32(offset)

	default:
		panic("displacement out of bounds")
	}

	return
}

func writeModTo(code gen.Coder, mod mod, ro, rm byte) {
	code.WriteByte(byte(mod) | ((ro & 7) << 3) | (rm & 7))
}

const (
	MemSIB    = byte((1 << 2))
	MemDisp32 = byte((1 << 2) | (1 << 0))
)

const (
	NoIndex = regs.R((1 << 2))
	NoBase  = regs.R((1 << 2) | (1 << 0))
)

func writeSibTo(code gen.Coder, scale byte, index, base regs.R) {
	if scale >= 4 {
		panic("scale factor out of bounds")
	}

	code.WriteByte((scale << 6) | (byte(index&7) << 3) | byte(base&7))
}

//
type insnConst []byte

func (bytes insnConst) op(code gen.Coder) {
	code.Write(bytes)
}

//
type insnO struct {
	opbase byte
}

func (i insnO) op(code gen.Coder, reg regs.R) {
	if reg >= 8 {
		panic("register not supported by instruction")
	}

	code.WriteByte(i.opbase + byte(reg))
}

//
type insnAddr8 []byte

func (bytes insnAddr8) op(code gen.Coder, addr int) (ok bool) {
	insnSize := len(bytes) + 1
	siteAddr := code.Len() + insnSize
	offset := addr - siteAddr

	if offset >= -0x80 && offset < 0x80 {
		code.Write(bytes)
		imm8(offset).writeTo(code)
		ok = true
	}

	return
}

//
type insnAddr32 []byte

func (bytes insnAddr32) op(code gen.Coder, addr int) {
	insnSize := len(bytes) + 4
	var offset int

	if addr != 0 {
		siteAddr := code.Len() + insnSize
		offset = addr - siteAddr
	} else {
		offset = -insnSize // infinite loop as placeholder
	}

	if offset >= -0x80000000 && offset < 0x80000000 {
		code.Write(bytes)
		imm32(offset).writeTo(code)
		return
	}

	panic("address out of bounds")
}

//
type insnAddr struct {
	rel8  insnAddr8
	rel32 insnAddr32
}

func (i insnAddr) op(code gen.Coder, addr int) {
	var ok bool
	if addr != 0 {
		ok = i.rel8.op(code, addr)
	}
	if !ok {
		i.rel32.op(code, addr)
	}
}

//
type insnRexOM struct {
	opcode []byte
	ro     byte
}

func (i insnRexOM) opReg(code gen.Coder, reg regs.R) {
	writeRexTo(code, 0, 0, 0, byte(reg))
	code.Write(i.opcode)
	writeModTo(code, ModReg, i.ro, byte(reg))
}

//
type insnRexOI struct {
	opbase byte
}

func (i insnRexOI) op(code gen.Coder, t types.T, reg regs.R, imm imm) {
	writeRexSizeTo(code, t, 0, 0, byte(reg))
	code.WriteByte(i.opbase + (byte(reg) & 7))
	imm.writeTo(code)
}

//
type insnRexM struct {
	opcode []byte
	ro     byte
}

func (i insnRexM) opReg(code gen.Coder, t types.T, reg regs.R) {
	writeRexSizeTo(code, t, 0, 0, byte(reg))
	code.Write(i.opcode)
	writeModTo(code, ModReg, i.ro, byte(reg))
}

func (i insnRexM) opIndirect(code gen.Coder, t types.T, reg regs.R, disp int) {
	if reg == 12 {
		panic("indirection through r12 not implemented")
	}

	mod, imm := dispMod(t, reg, disp)

	writeRexSizeTo(code, t, 0, 0, byte(reg))
	code.Write(i.opcode)
	writeModTo(code, mod, i.ro, byte(reg))
	imm.writeTo(code)
}

func (i insnRexM) opStack(code gen.Coder, t types.T, disp int) {
	mod, imm := dispMod(t, regStackPtr, disp)

	writeRexSizeTo(code, t, 0, 0, 0)
	code.Write(i.opcode)
	writeModTo(code, mod, i.ro, MemSIB)
	writeSibTo(code, 0, regStackPtr, regStackPtr)
	imm.writeTo(code)
}

//
type insnRexMI struct {
	opcode8  byte
	opcode32 byte
	ro       byte
}

func (i insnRexMI) opImm(code gen.Coder, t types.T, reg regs.R, value int) {
	var opcode byte
	var imm imm

	switch {
	case i.opcode8 != 0 && -0x80 <= value && value < 0x80:
		opcode = i.opcode8
		imm = imm8(value)

	case i.opcode32 != 0 && -0x80000000 <= value && value < 0x80000000:
		opcode = i.opcode32
		imm = imm32(value)

	default:
		panic("immediate value out of range")
	}

	writeRexSizeTo(code, t, 0, 0, byte(reg))
	code.WriteByte(opcode)
	writeModTo(code, ModReg, i.ro, byte(reg))
	imm.writeTo(code)
}

//
type insnPrefix struct {
	prefix   prefix
	opcodeRM []byte
	opcodeMR []byte
}

func (i insnPrefix) opFromReg(code gen.Coder, t types.T, target, source regs.R) {
	writePrefixRegInsnTo(code, i.prefix, t, i.opcodeRM, byte(target), byte(source))
}

func (i insnPrefix) opFromAddr(code gen.Coder, t types.T, target regs.R, scale uint8, index regs.R, addr int) {
	writePrefixAddrInsnTo(code, i.prefix, t, i.opcodeRM, target, scale, index, addr)
}

func (i insnPrefix) opFromIndirect(code gen.Coder, t types.T, target, source regs.R, disp int) {
	writePrefixIndirectInsnTo(code, i.prefix, t, i.opcodeRM, target, source, disp)
}

func (i insnPrefix) opFromStack(code gen.Coder, t types.T, target regs.R, disp int) {
	writePrefixStackInsnTo(code, i.prefix, t, i.opcodeRM, target, disp)
}

func (i insnPrefix) opToReg(code gen.Coder, t types.T, target, source regs.R) {
	writePrefixRegInsnTo(code, i.prefix, t, i.opcodeMR, byte(source), byte(target))
}

func (i insnPrefix) opToAddr(code gen.Coder, t types.T, source regs.R, scale uint8, index regs.R, addr int) {
	// XXX: unused, untested
	writePrefixAddrInsnTo(code, i.prefix, t, i.opcodeMR, source, scale, index, addr)
}

func (i insnPrefix) opToIndirect(code gen.Coder, t types.T, target, source regs.R, disp int) {
	// XXX: unused, untested
	writePrefixIndirectInsnTo(code, i.prefix, t, i.opcodeMR, source, target, disp)
}

func (i insnPrefix) opToStack(code gen.Coder, t types.T, source regs.R, disp int) {
	writePrefixStackInsnTo(code, i.prefix, t, i.opcodeMR, source, disp)
}

func writePrefixRegInsnTo(code gen.Coder, p prefix, t types.T, opcode []byte, ro, rm byte) {
	if opcode == nil {
		panic("instruction not supported")
	}

	p.writeTo(code, t, ro, 0, rm)
	code.Write(opcode)
	writeModTo(code, ModReg, ro, rm)
}

func writePrefixAddrInsnTo(code gen.Coder, p prefix, t types.T, opcode []byte, reg regs.R, scale uint8, index regs.R, addr int) {
	if opcode == nil {
		panic("instruction not supported")
	}
	if addr <= 0 || addr > 0x7fffffff {
		panic("absolute address is out of range")
	}

	p.writeTo(code, t, byte(reg), 0, 0)
	code.Write(opcode)
	writeModTo(code, ModMem, byte(reg), MemSIB)
	writeSibTo(code, scale, index, NoBase)
	imm32(addr).writeTo(code)
}

func writePrefixIndirectInsnTo(code gen.Coder, p prefix, t types.T, opcode []byte, reg, ptr regs.R, disp int) {
	if opcode == nil {
		panic("instruction not supported")
	}
	if ptr == 12 {
		panic("indirection through r12 not implemented")
	}

	mod, imm := dispMod(t, ptr, disp)

	p.writeTo(code, t, byte(reg), 0, byte(ptr))
	code.Write(opcode)
	writeModTo(code, mod, byte(reg), byte(ptr))
	imm.writeTo(code)
}

func writePrefixStackInsnTo(code gen.Coder, p prefix, t types.T, opcode []byte, reg regs.R, disp int) {
	mod, imm := dispMod(t, regStackPtr, disp)

	p.writeTo(code, t, byte(reg), 0, 0)
	code.Write(opcode)
	writeModTo(code, mod, byte(reg), MemSIB)
	writeSibTo(code, 0, regStackPtr, regStackPtr)
	imm.writeTo(code)
}

//
type pushPopInsn struct {
	regLow insnO
	regAny insnRexM
}

func (i pushPopInsn) op(code gen.Coder, reg regs.R) {
	if reg < 8 {
		i.regLow.op(code, reg)
	} else {
		i.regAny.opReg(code, types.I32, reg)
	}
}

//
type movImmInsn struct {
	imm32 insnRexMI
	imm   insnRexOI
}

func (i movImmInsn) op(code gen.Coder, t types.T, reg regs.R, value int64) {
	switch {
	case -0x80000000 <= value && value < 0x80000000:
		i.imm32.opImm(code, t, reg, int(value))

	case t.Size() == types.Size64 && value >= 0 && value < 0x100000000:
		// upper 32-bits will be zeroed automatically
		i.imm.op(code, types.I32, reg, imm{uint32(value)})

	default:
		i.imm.op(code, t, reg, imm64(value))
	}
}

//
type shiftImmInsn struct {
	one insnRexM
	any insnRexMI
}

func (i shiftImmInsn) op(code gen.Coder, t types.T, reg regs.R, value int) {
	if value == 1 {
		i.one.opReg(code, t, reg)
	} else {
		i.any.opImm(code, t, reg, value)
	}
}

//
type binaryInsn struct {
	insnPrefix
	insnRexMI
}

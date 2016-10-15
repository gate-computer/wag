package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

type prefix interface {
	writeTo(code gen.OpCoder, t types.T, ro, index, rmOrBase byte)
}

type constPrefix []byte

func (bytes constPrefix) writeTo(code gen.OpCoder, t types.T, ro, index, rmOrBase byte) {
	code.Write(bytes)
}

type multiPrefix []prefix

func (array multiPrefix) writeTo(code gen.OpCoder, t types.T, ro, index, rmOrBase byte) {
	for _, p := range array {
		p.writeTo(code, t, ro, index, rmOrBase)
	}
}

const (
	rex  = (1 << 6)
	rexW = rex | (1 << 3)
	rexR = rex | (1 << 2)
	rexX = rex | (1 << 1)
	rexB = rex | (1 << 0)
)

func writeRexTo(code gen.OpCoder, rex, ro, index, rmOrBase byte) {
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

func writeRexSizeTo(code gen.OpCoder, t types.T, ro, index, rmOrBase byte) {
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

func dispMod(t types.T, baseReg regs.R, offset int32) (mod mod, disp imm) {
	switch {
	case offset == 0 && (baseReg&7) != 0x5: // rbp and r13 need displacement
		mod = ModMem

	case offset >= -0x80 && offset < 0x80:
		mod = ModMemDisp8
		disp.value = int8(offset)

	default:
		mod = ModMemDisp32
		disp.value = int32(offset)
	}

	return
}

func writeModTo(code gen.OpCoder, mod mod, ro, rm byte) {
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

func writeSibTo(code gen.OpCoder, scale byte, index, base regs.R) {
	if scale >= 4 {
		panic("scale factor out of bounds")
	}

	code.WriteByte((scale << 6) | (byte(index&7) << 3) | byte(base&7))
}

//
type insnConst []byte

func (opcode insnConst) op(code gen.OpCoder) {
	code.Write(opcode)
}

//
type insnO struct {
	opbase byte
}

func (i insnO) op(code gen.OpCoder, reg regs.R) {
	if reg >= 8 {
		panic("register not supported by instruction")
	}

	code.WriteByte(i.opbase + byte(reg))
}

//
type insnI []byte

func (opcode insnI) op(code gen.OpCoder, imm imm) {
	code.Write(opcode)
	imm.writeTo(code)
}

//
type insnAddr8 []byte

func (opcode insnAddr8) size() int32 {
	return int32(len(opcode)) + 1
}

func (opcode insnAddr8) op(code gen.OpCoder, addr int32) (ok bool) {
	insnSize := int32(len(opcode)) + 1
	siteAddr := code.Len() + insnSize
	offset := addr - siteAddr

	if offset >= -0x80 && offset < 0x80 {
		code.Write(opcode)
		code.WriteByte(uint8(offset))
		ok = true
	}
	return
}

func (i insnAddr8) opStub(code gen.OpCoder) {
	i.op(code, code.Len()) // infinite loop as placeholder
}

//
type insnAddr32 []byte

func (opcode insnAddr32) size() int32 {
	return int32(len(opcode)) + 4
}

func (i insnAddr32) op(code gen.OpCoder, addr int32) {
	var offset int32
	if addr != 0 {
		siteAddr := code.Len() + i.size()
		offset = addr - siteAddr
	} else {
		offset = -i.size() // infinite loop as placeholder
	}
	i.writeTo(code, offset)
}

func (i insnAddr32) opMissingFunction(code gen.OpCoder) {
	siteAddr := code.Len() + i.size()
	i.writeTo(code, -siteAddr)
}

func (opcode insnAddr32) writeTo(code gen.OpCoder, offset int32) {
	code.Write(opcode)
	writeInt32To(code, int32(offset))
}

//
type insnAddr struct {
	rel8  insnAddr8
	rel32 insnAddr32
}

func (i insnAddr) op(code gen.OpCoder, addr int32) {
	var ok bool
	if addr != 0 {
		ok = i.rel8.op(code, addr)
	}
	if !ok {
		i.rel32.op(code, addr)
	}
}

//
type insnRex []byte

func (opcode insnRex) op(code gen.OpCoder, t types.T) {
	writeRexSizeTo(code, t, 0, 0, 0)
	code.Write(opcode)
}

//
type insnRexOM struct {
	opcode []byte
	ro     byte
}

func (i insnRexOM) opReg(code gen.OpCoder, reg regs.R) {
	writeRexTo(code, 0, 0, 0, byte(reg))
	code.Write(i.opcode)
	writeModTo(code, ModReg, i.ro, byte(reg))
}

//
type insnRexO struct {
	opbase byte
}

func (i insnRexO) op(code gen.OpCoder, t types.T, reg regs.R) {
	writeRexSizeTo(code, t, 0, 0, byte(reg))
	code.WriteByte(i.opbase + (byte(reg) & 7))
}

//
type insnRexOI struct {
	opbase byte
}

func (i insnRexOI) op(code gen.OpCoder, t types.T, reg regs.R, imm imm) {
	writeRexSizeTo(code, t, 0, 0, byte(reg))
	code.WriteByte(i.opbase + (byte(reg) & 7))
	imm.writeTo(code)
}

//
type insnRexM struct {
	opcode []byte
	ro     byte
}

func (i insnRexM) opReg(code gen.OpCoder, t types.T, reg regs.R) {
	writeRexSizeTo(code, t, 0, 0, byte(reg))
	code.Write(i.opcode)
	writeModTo(code, ModReg, i.ro, byte(reg))
}

func (i insnRexM) opIndirect(code gen.OpCoder, t types.T, reg regs.R, disp int32) {
	if reg == 12 {
		panic("indirection through r12 not implemented")
	}

	mod, imm := dispMod(t, reg, disp)

	writeRexSizeTo(code, t, 0, 0, byte(reg))
	code.Write(i.opcode)
	writeModTo(code, mod, i.ro, byte(reg))
	imm.writeTo(code)
}

func (i insnRexM) opStack(code gen.OpCoder, t types.T, disp int32) {
	mod, imm := dispMod(t, regStackPtr, disp)

	writeRexSizeTo(code, t, 0, 0, 0)
	code.Write(i.opcode)
	writeModTo(code, mod, i.ro, MemSIB)
	writeSibTo(code, 0, regStackPtr, regStackPtr)
	imm.writeTo(code)
}

var (
	NoRexMInsn = insnRexM{nil, 0}
)

//
type insnPrefix struct {
	prefix   prefix
	opcodeRM []byte
	opcodeMR []byte
}

func (i insnPrefix) opFromReg(code gen.OpCoder, t types.T, target, source regs.R) {
	writePrefixRegInsnTo(code, i.prefix, t, i.opcodeRM, byte(target), byte(source))
}

func (i insnPrefix) opFromAddr(code gen.OpCoder, t types.T, target regs.R, scale uint8, index regs.R, addr int32) {
	writePrefixAddrInsnTo(code, i.prefix, t, i.opcodeRM, target, scale, index, addr)
}

func (i insnPrefix) opFromIndirect(code gen.OpCoder, t types.T, target regs.R, scale uint8, index, base regs.R, disp int32) {
	writePrefixIndirectInsnTo(code, i.prefix, t, i.opcodeRM, target, scale, index, base, disp)
}

func (i insnPrefix) opFromStack(code gen.OpCoder, t types.T, target regs.R, disp int32) {
	writePrefixStackInsnTo(code, i.prefix, t, i.opcodeRM, target, disp)
}

func (i insnPrefix) opToReg(code gen.OpCoder, t types.T, target, source regs.R) {
	writePrefixRegInsnTo(code, i.prefix, t, i.opcodeMR, byte(source), byte(target))
}

func (i insnPrefix) opToAddr(code gen.OpCoder, t types.T, source regs.R, scale uint8, index regs.R, addr int32) {
	writePrefixAddrInsnTo(code, i.prefix, t, i.opcodeMR, source, scale, index, addr)
}

func (i insnPrefix) opToIndirect(code gen.OpCoder, t types.T, target regs.R, scale uint8, index, base regs.R, disp int32) {
	writePrefixIndirectInsnTo(code, i.prefix, t, i.opcodeMR, target, scale, index, base, disp)
}

func (i insnPrefix) opToStack(code gen.OpCoder, t types.T, source regs.R, disp int32) {
	writePrefixStackInsnTo(code, i.prefix, t, i.opcodeMR, source, disp)
}

func writePrefixRegInsnTo(code gen.OpCoder, p prefix, t types.T, opcode []byte, ro, rm byte) {
	if opcode == nil {
		panic("instruction not supported")
	}

	p.writeTo(code, t, ro, 0, rm)
	code.Write(opcode)
	writeModTo(code, ModReg, ro, rm)
}

func writePrefixAddrInsnTo(code gen.OpCoder, p prefix, t types.T, opcode []byte, reg regs.R, scale uint8, index regs.R, addr int32) {
	if opcode == nil {
		panic("instruction not supported")
	}

	p.writeTo(code, t, byte(reg), 0, 0)
	code.Write(opcode)
	writeModTo(code, ModMem, byte(reg), MemSIB)
	writeSibTo(code, scale, index, NoBase)
	writeInt32To(code, addr)
}

func writePrefixIndirectInsnTo(code gen.OpCoder, p prefix, t types.T, opcode []byte, reg regs.R, scale uint8, index, base regs.R, disp int32) {
	if opcode == nil {
		panic("instruction not supported")
	}
	if base == 12 {
		panic("r12 as base register not implemented")
	}

	mod, imm := dispMod(t, base, disp)

	p.writeTo(code, t, byte(reg), byte(index), byte(base))
	code.Write(opcode)

	if scale == 0 && index == NoIndex {
		writeModTo(code, mod, byte(reg), byte(base))
	} else {
		writeModTo(code, mod, byte(reg), MemSIB)
		writeSibTo(code, scale, index, base)
	}

	imm.writeTo(code)
}

func writePrefixStackInsnTo(code gen.OpCoder, p prefix, t types.T, opcode []byte, reg regs.R, disp int32) {
	mod, imm := dispMod(t, regStackPtr, disp)

	p.writeTo(code, t, byte(reg), 0, 0)
	code.Write(opcode)
	writeModTo(code, mod, byte(reg), MemSIB)
	writeSibTo(code, 0, regStackPtr, regStackPtr)
	imm.writeTo(code)
}

//
type insnPrefixRexRM struct {
	prefix prefix
	opcode []byte
}

func (i insnPrefixRexRM) opReg(code gen.OpCoder, floatType, intType types.T, target, source regs.R) {
	i.prefix.writeTo(code, floatType, 0, 0, 0)
	writeRexSizeTo(code, intType, byte(target), 0, byte(source))
	code.Write(i.opcode)
	writeModTo(code, ModReg, byte(target), byte(source))
}

//
type insnPrefixMI struct {
	prefix   prefix
	opcode8  byte
	opcode16 byte
	opcode32 byte
	ro       byte
}

func (i insnPrefixMI) opImm(code gen.OpCoder, t types.T, reg regs.R, value int32) {
	opcode, imm := i.immOpcode(value)

	i.prefix.writeTo(code, t, 0, 0, byte(reg))
	code.WriteByte(opcode)
	writeModTo(code, ModReg, i.ro, byte(reg))
	imm.writeTo(code)
}

func (i insnPrefixMI) opImmToIndirect(code gen.OpCoder, t types.T, reg regs.R, disp, value int32) {
	mod, immDisp := dispMod(t, reg, disp)
	opcode, immValue := i.immOpcode(value)

	i.prefix.writeTo(code, t, 0, 0, byte(reg))
	code.WriteByte(opcode)
	writeModTo(code, mod, i.ro, byte(reg))
	immDisp.writeTo(code)
	immValue.writeTo(code)
}

func (i insnPrefixMI) opImmToStack(code gen.OpCoder, t types.T, disp, value int32) {
	mod, immDisp := dispMod(t, regStackPtr, disp)
	opcode, immValue := i.immOpcode(value)

	i.prefix.writeTo(code, t, 0, 0, 0)
	code.WriteByte(opcode)
	writeModTo(code, mod, i.ro, MemSIB)
	writeSibTo(code, 0, regStackPtr, regStackPtr)
	immDisp.writeTo(code)
	immValue.writeTo(code)
}

func (i insnPrefixMI) immOpcode(value int32) (opcode byte, imm imm) {
	switch {
	case i.opcode8 != 0 && value >= -0x80 && value < 0x80:
		opcode = i.opcode8
		imm.value = int8(value)
		return

	case i.opcode16 != 0 && value >= -0x8000 && value < 0x8000:
		opcode = i.opcode16
		imm.value = int16(value)
		return

	case i.opcode32 != 0:
		opcode = i.opcode32
		imm.value = int32(value)
		return

	default:
		panic("immediate value out of range")
	}
}

var (
	NoPrefixMIInsn = insnPrefixMI{nil, 0, 0, 0, 0}
)

//
type insnSuffixRMI struct {
	opcode []byte
	suffix prefix
}

func (i insnSuffixRMI) opReg(code gen.OpCoder, t types.T, target, source regs.R, value int8) {
	code.Write(i.opcode)
	i.suffix.writeTo(code, t, byte(target), 0, byte(source))
	writeModTo(code, ModReg, byte(target), byte(source))
	code.WriteByte(uint8(value))
}

//
type binaryInsn struct {
	insnPrefix
	insnPrefixMI
}

//
type pushPopInsn struct {
	regLow insnO
	regAny insnRexM
}

func (i pushPopInsn) op(code gen.OpCoder, reg regs.R) {
	if reg < 8 {
		i.regLow.op(code, reg)
	} else {
		i.regAny.opReg(code, types.I32, reg)
	}
}

//
type xchgInsn struct {
	r0 insnRexO
	insnPrefix
}

func (i xchgInsn) opFromReg(code gen.OpCoder, t types.T, a, b regs.R) {
	switch {
	case a == regs.R(0):
		i.r0.op(code, t, b)

	case b == regs.R(0):
		i.r0.op(code, t, a)

	default:
		i.insnPrefix.opFromReg(code, t, a, b)
	}
}

//
type shiftImmInsn struct {
	one insnRexM
	any insnPrefixMI
}

func (i shiftImmInsn) defined() bool {
	return i.one.opcode != nil
}

func (i shiftImmInsn) op(code gen.OpCoder, t types.T, reg regs.R, value uint8) {
	if value == 1 {
		i.one.opReg(code, t, reg)
	} else {
		i.any.opImm(code, t, reg, int32(value))
	}
}

var (
	NoShiftImmInsn = shiftImmInsn{NoRexMInsn, NoPrefixMIInsn}
)

//
type movImmInsn struct {
	imm32 insnPrefixMI
	imm   insnRexOI
}

func (i movImmInsn) op(code gen.OpCoder, t types.T, reg regs.R, value int64) {
	switch {
	case value >= -0x80000000 && value < 0x80000000:
		i.imm32.opImm(code, t, reg, int32(value))

	case t.Size() == types.Size64 && value >= 0 && value < 0x100000000:
		i.imm.op(code, types.I32, reg, imm{uint32(value)})

	default:
		i.imm.op(code, t, reg, imm{value})
	}
}

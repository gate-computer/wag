package x86

import (
	"strconv"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

type prefix interface {
	writeTo(gen.Coder, types.T, regs.R, regs.R, regs.R)
}

type addrInsn interface {
	op(code gen.Coder, addr int)
}

type regInsn interface {
	op(code gen.Coder, subject regs.R)
}

type unaryInsn interface {
	opReg(code gen.Coder, t types.T, source regs.R)
	opIndirect(code gen.Coder, t types.T, source regs.R, disp int)
	opStack(code gen.Coder, t types.T, disp int)
}

type binaryRegInsn interface {
	opReg(code gen.Coder, t types.T, target, source regs.R)
	opFromAddr(code gen.Coder, t types.T, target regs.R, addr int)
	opFromIndirect(code gen.Coder, t types.T, target, source regs.R, disp int)
	opFromStack(code gen.Coder, t types.T, target regs.R, disp int)
}

type binaryArithmeticImmInsn interface {
	op(code gen.Coder, t types.T, target regs.R, value int)
}

type binaryImmInsn interface {
	op(code gen.Coder, t types.T, target regs.R, imm imm)
}

type binaryInsn struct {
	binaryRegInsn
	Imm binaryArithmeticImmInsn
}

func (i binaryInsn) op(code gen.Coder, t types.T, target regs.R, source values.Operand) {
	switch source.Storage {
	case values.ROData:
		i.opFromAddr(code, t, target, code.RODataAddr()+source.Addr())

	case values.VarMem:
		i.opFromStack(code, t, target, source.Offset())

	case values.Imm:
		i.Imm.op(code, t, target, int(source.ImmValue(t)))

	case values.VarReg, values.TempReg, values.BorrowedReg:
		i.opReg(code, t, target, source.Reg())

	default:
		panic(source)
	}

	code.Consumed(t, source)
}

type binaryIntDivMulInsn struct {
	unaryInsn
	shiftImm binaryImmInsn
}

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

type mem byte

const (
	MemSIB    = mem((1 << 2))
	MemDisp32 = mem((1 << 2) | (1 << 0))
)

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

func dispMod(t types.T, baseReg regs.R, offset int) (mod mod, disp imm) {
	switch {
	case offset == 0 && (baseReg&7) != 0x5: // rbp and r13 need displacement
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

const (
	NoIndex = (1 << 2)
	NoBase  = (1 << 2) | (1 << 0)
)

func writeSibTo(code gen.Coder, scale byte, index, base regs.R) {
	if scale >= 4 {
		panic(strconv.Itoa(int(scale)))
	}

	code.WriteByte((scale << 6) | (byte(index&7) << 3) | byte(base&7))
}

type sib struct {
	scale byte
	index regs.R
	base  regs.R
}

func (sib sib) writeTo(code gen.Coder) {
	writeSibTo(code, sib.scale, sib.index, sib.base)
}

type insnFixed []byte

func (bytes insnFixed) op(code gen.Coder) {
	code.Write([]byte(bytes))
}

type insnAddr struct {
	rel8  []byte
	rel32 []byte
}

func (i insnAddr) op(code gen.Coder, targetAddr int) {
	if i.rel8 != nil && targetAddr != 0 {
		insnSize := len(i.rel8) + 1
		siteAddr := code.Len() + insnSize
		offset := targetAddr - siteAddr

		if offset >= -0x80 && offset < 0x80 {
			code.Write(i.rel8)
			imm8(offset).writeTo(code)
			return
		}
	}

	insnSize := len(i.rel32) + 4
	var offset int

	if targetAddr != 0 {
		siteAddr := code.Len() + insnSize
		offset = targetAddr - siteAddr
	} else {
		offset = -insnSize // infinite loop as placeholder
	}

	if offset >= -0x80000000 && offset < 0x80000000 {
		code.Write(i.rel32)
		imm32(offset).writeTo(code)
		return
	}

	panic(offset)
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
		i.high.opReg(code, types.I32, reg)
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

func (i insnPrefixModOpReg) opReg(code gen.Coder, t types.T, reg regs.R) {
	i.prefix.writeTo(code, t, 0, 0, reg)
	code.Write(i.bytes)
	ModReg.writeTo(code, i.ro, byte(reg))
}

func (i insnPrefixModOpReg) opIndirect(code gen.Coder, t types.T, reg regs.R, disp int) {
	if reg == 12 {
		panic("indirection through r12 not implemented")
	}

	mod, imm := dispMod(t, reg, disp)

	i.prefix.writeTo(code, t, 0, 0, reg)
	code.Write(i.bytes)
	mod.writeTo(code, i.ro, byte(reg))
	imm.writeTo(code)
}

func (i insnPrefixModOpReg) opStack(code gen.Coder, t types.T, disp int) {
	mod, imm := dispMod(t, regStackPtr, disp)

	i.prefix.writeTo(code, t, 0, 0, 0)
	code.Write(i.bytes)
	modMem{mod, MemSIB}.writeTo(code, i.ro)
	sib{0, regStackPtr, regStackPtr}.writeTo(code)
	imm.writeTo(code)
}

type insnPrefixModRegFromReg struct {
	prefix prefix
	bytes  []byte
}

func (i insnPrefixModRegFromReg) opReg(code gen.Coder, t types.T, target, source regs.R) {
	i.prefix.writeTo(code, t, target, 0, source)
	code.Write(i.bytes)
	ModReg.writeTo(code, byte(target), byte(source))
}

func (i insnPrefixModRegFromReg) opFromAddr(code gen.Coder, t types.T, target regs.R, addr int) {
	if addr <= 0 || addr > 0x7fffffff {
		panic("absolute address is out of range")
	}

	i.prefix.writeTo(code, t, target, 0, 0)
	code.Write(i.bytes)
	modMem{ModIndir, MemDisp32}.writeTo(code, byte(target))
	imm32(addr).writeTo(code)
}

func (i insnPrefixModRegFromReg) opFromIndirect(code gen.Coder, t types.T, target, source regs.R, disp int) {
	if source == 12 {
		panic("indirection through r12 not implemented")
	}

	mod, imm := dispMod(t, source, disp)

	i.prefix.writeTo(code, t, target, 0, source)
	code.Write(i.bytes)
	mod.writeTo(code, byte(target), byte(source))
	imm.writeTo(code)
}

func (i insnPrefixModRegFromReg) opFromStack(code gen.Coder, t types.T, target regs.R, disp int) {
	mod, imm := dispMod(t, regStackPtr, disp)

	i.prefix.writeTo(code, t, target, 0, 0)
	code.Write(i.bytes)
	modMem{mod, MemSIB}.writeTo(code, byte(target))
	sib{0, regStackPtr, regStackPtr}.writeTo(code)
	imm.writeTo(code)
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
	mod, imm := dispMod(t, source, disp)

	i.prefix.writeTo(code, t, target, 0, source)
	code.Write(i.bytes)
	mod.writeTo(code, byte(target), byte(source))
	imm.writeTo(code)
}

func (i insnPrefixModRegFromRegDisp) opFromAddr(code gen.Coder, t types.T, target regs.R, addr int) {
	if addr <= 0 || addr > 0x7fffffff {
		panic("absolute address is out of range")
	}

	i.prefix.writeTo(code, t, target, 0, 0)
	code.Write(i.bytes)
	modMem{ModIndir, MemSIB}.writeTo(code, byte(target))
	writeSibTo(code, 0, NoIndex, NoBase)
	imm32(addr).writeTo(code)
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
	mod, imm := dispMod(t, i.sib.base, disp)

	i.prefix.writeTo(code, t, reg, 0, 0)
	code.Write(i.bytes)
	modMem{mod, MemSIB}.writeTo(code, byte(reg))
	i.sib.writeTo(code)
	imm.writeTo(code)
}

type insnPrefixModRegCustomSibImm struct {
	prefix prefix
	bytes  []byte
}

func (i insnPrefixModRegCustomSibImm) op(code gen.Coder, t types.T, reg regs.R, scale uint8, index, base regs.R, disp int) {
	mod, imm := dispMod(t, base, disp)

	i.prefix.writeTo(code, t, reg, index, base)
	code.Write(i.bytes)
	modMem{mod, MemSIB}.writeTo(code, byte(reg))
	writeSibTo(code, scale, index, base)
	imm.writeTo(code)
}

func (i insnPrefixModRegCustomSibImm) opFromAddr(code gen.Coder, t types.T, reg regs.R, scale uint8, index regs.R, addr int) {
	if addr <= 0 || addr > 0x7fffffff {
		panic("absolute address is out of range")
	}

	i.prefix.writeTo(code, t, reg, index, 0)
	code.Write(i.bytes)
	modMem{ModIndir, MemSIB}.writeTo(code, byte(reg))
	writeSibTo(code, scale, index, NoBase)
	imm32(addr).writeTo(code)
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

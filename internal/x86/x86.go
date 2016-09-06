// +build amd64

package x86

import (
	"bytes"
	"encoding/binary"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
)

const (
	rexB = byte((1 << 6) | (1 << 2))
	rexW = byte((1 << 6) | (1 << 3))

	modDisp8  = byte((0 << 1) | (1 << 0))
	modDisp32 = byte((1 << 1) | (0 << 0))
	modReg    = byte((1 << 1) | (1 << 0))

	// regs.R0 = rax
	// regs.R1 = rcx
	regScratch = regs.R(2) // rdx
	// rbx
	regStackPtr = 4 // rsp
	// rbp
	regRODataPtr = 6 // rsi
	regTextPtr   = 7 // rdi
	regTrapArg   = 7 // rdi
	regTrapFunc  = 8 // r8

	wordSize      = 8
	codeAlignment = 16
	paddingByte   = 0xf4 // hlt
)

var (
	byteOrder = binary.LittleEndian
)

type Machine struct{}

func (Machine) NewCoder() *Coder {
	return new(Coder)
}

func (Machine) ByteOrder() binary.ByteOrder {
	return byteOrder
}

func (Machine) FunctionCallStackOverhead() int {
	return wordSize // return address
}

type Coder struct {
	bytes.Buffer
}

func (code *Coder) immediate(value interface{}) {
	if err := binary.Write(code, byteOrder, value); err != nil {
		panic(err)
	}
}

// regOp operates on a single register.
func regOp(intOp, floatOp func(regs.R), t types.T, subject regs.R) {
	switch t.Category() {
	case types.Int:
		intOp(subject)

	case types.Float:
		floatOp(subject)

	default:
		panic(t)
	}
}

// UnaryOp operates on a single typed register.
func (code *Coder) UnaryOp(name string, t types.T, subject regs.R) {
	switch t.Category() {
	case types.Int:
		code.opIntUnary(name, t, subject)

	case types.Float:
		code.opFloatUnary(name, t, subject)

	default:
		panic(t)
	}
}

// BinaryOp operates on two typed registers.
func (code *Coder) BinaryOp(name string, t types.T, source, target regs.R) {
	switch t.Category() {
	case types.Int:
		code.opIntBinary(name, t, source, target)

	case types.Float:
		code.opFloatBinary(name, t, source, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpAddToStackPtr(offset int) {
	code.instrIntImm(opcodeIntImmAdd, types.I64, offset, regStackPtr)
}

func (code *Coder) OpBranchIndirect(reg regs.R) (branchAddr int) {
	code.instrLeaRIP(0, regScratch)
	branchAddr = code.Len()
	code.opIntBinary("add", types.I64, reg, regScratch)
	code.instrIndirect(opcodeIndirectJmp, regScratch)
	return
}

func (code *Coder) OpCallIndirectTrash(reg regs.R) {
	code.opIntBinary("add", types.I64, regTextPtr, reg)
	code.instrIndirect(opcodeIndirectCall, reg)
	return
}

func (code *Coder) OpInvalid() {
	code.instrUb2()
}

func (code *Coder) OpLoadRODataRegScaleExt(t types.T, addr int, dispType types.T, reg regs.R, scale uint8) {
	if addr < 0 || 0x80000000 <= addr {
		panic(addr)
	}

	if dispType != types.I64 {
		code.instrIntMov(types.I32, reg, reg, true)
	}

	code.instrIntImmSh(opcodeIntImmShl, types.I64, scale, reg)

	if addr != 0 {
		code.instrIntImm(opcodeIntImmAdd, types.I64, addr, reg)
	}

	code.opIntBinary("add", types.I64, regRODataPtr, reg)
	code.instrIntMovFromIndirect(t, reg, reg, true)
}

func (code *Coder) OpLoadStack(t types.T, sourceOffset int, target regs.R, signExt bool) {
	var dispMod byte
	var dispOffset interface{}

	switch {
	case sourceOffset < 0:
		panic(sourceOffset)

	case sourceOffset == 0:

	case t.Size() == types.Size64 && (sourceOffset&7) != 0:
		panic(sourceOffset)

	case (sourceOffset & 3) != 0:
		panic(sourceOffset)

	case sourceOffset < 0x80:
		dispMod = modDisp8
		dispOffset = int8(sourceOffset)

	case sourceOffset < 0x80000000:
		dispMod = modDisp32
		dispOffset = int32(sourceOffset)

	default:
		panic(sourceOffset)
	}

	switch t.Category() {
	case types.Int:
		code.instrIntMovFromStack(t, dispMod, dispOffset, target, signExt)

	case types.Float:
		code.instrFloatMovFromStack(dispMod, dispOffset, target) // TODO: signExt

	default:
		panic(t)
	}
}

func (code *Coder) OpMove(t types.T, source, target regs.R, signExt bool) {
	switch t.Category() {
	case types.Int:
		code.instrIntMov(t, source, target, signExt)

	case types.Float:
		code.instrFloatMov(t, source, target) // TODO: signExt

	default:
		panic(t)
	}
}

func (code *Coder) OpMoveImm(t types.T, token interface{}, target regs.R) {
	value := values.Parse(t, token)

	switch t.Category() {
	case types.Int:
		code.instrIntMovImm(t, value, target)

	case types.Float:
		code.instrIntMovImm(t, value, regScratch)
		code.instrFloatMovFromInt(t, regScratch, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpNop() {
	code.instrNop()
}

func (code *Coder) OpPop(t types.T, target regs.R) {
	regOp(code.instrIntPop, code.opFloatPop, t, target)
}

func (code *Coder) OpPush(t types.T, source regs.R) {
	regOp(code.instrIntPush, code.opFloatPush, t, source)
}

func (code *Coder) OpReturn() {
	code.instrRet()
}

func (code *Coder) OpShiftRightLogicalImm(t types.T, count uint8, target regs.R) {
	code.instrIntImmSh(opcodeIntImmShr, t, count, target)
}

func (code *Coder) OpTrap(id traps.Id) {
	code.instrIntMovImm(types.I64, int64(id), regTrapArg)
	code.instrIntMov(types.I64, regTrapFunc, regScratch, false)
	code.instrIndirect(opcodeIndirectCall, regScratch)
}

func (code *Coder) StubOpBranch() {
	code.stubInstrJmp()
}

func (code *Coder) StubOpBranchIf(t types.T, subject regs.R) {
	code.instrIntTest(t, subject, subject)
	code.stubInstrJcc(opcodeJne)
}

func (code *Coder) StubOpBranchIfNot(t types.T, subject regs.R) {
	code.instrIntTest(t, subject, subject)
	code.stubInstrJcc(opcodeJe)
}

func (code *Coder) StubOpBranchIfNotEqualImmTrash(t types.T, value int, subject regs.R) {
	code.instrIntImm(opcodeIntImmSub, t, value, subject)
	code.stubInstrJcc(opcodeJne)
}

func (code *Coder) StubOpBranchIfOutOfBounds(indexReg regs.R, upperBound int) {
	code.instrIntMovImm(types.I32, uint32(upperBound), regScratch)
	code.instrIntTest(types.I32, indexReg, indexReg)
	code.instrIntCmov(opcodeIntCmovl, types.I32, regScratch, indexReg) // negative index -> upper bound
	code.opIntBinary("sub", types.I32, indexReg, regScratch)
	code.stubInstrJcc(opcodeJle)
}

func (code *Coder) StubOpCall() {
	code.stubInstrCall()
}

func (code *Coder) UpdateBranches(l *links.L) {
	code.update(l)
}

func (code *Coder) UpdateCalls(l *links.L) {
	code.update(l)
}

func (code *Coder) update(l *links.L) {
	for _, addr := range l.Sites {
		offset := l.Address - addr
		if offset < -0x80000000 || 0x80000000 <= offset {
			panic(offset)
		}

		byteOrder.PutUint32(code.Bytes()[addr-4:addr], uint32(offset))
	}
}

func (code *Coder) Align() {
	size := codeAlignment - (code.Len() & (codeAlignment - 1))
	if size < codeAlignment {
		for i := 0; i < size; i++ {
			code.WriteByte(paddingByte)
		}
	}
}

func modRM(mod byte, ro, rm regs.R) byte {
	if rm >= 8 {
		panic(rm)
	}

	return (mod << 6) | (byte(ro&7) << 3) | byte(rm)
}

func sib(scale, index, base byte) byte {
	return (scale << 6) | (index << 3) | base
}

func (code *Coder) fromStack(mod byte, disp interface{}, target regs.R) {
	code.WriteByte(modRM(mod, target, 1<<2))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
	if disp != nil {
		code.immediate(disp)
	}
}

func (code *Coder) toStack(mod byte, disp interface{}, source regs.R) {
	code.WriteByte(modRM(mod, source, 1<<2))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
	if disp != nil {
		code.immediate(disp)
	}
}

const (
	opcodeIndirectCall = 0x2
	opcodeIndirectJmp  = 0x4
)

func (code *Coder) instrIndirect(opcode byte, addrReg regs.R) {
	code.WriteByte(0xff)
	code.WriteByte(modRM(modReg, regs.R(opcode), addrReg))
}

func (code *Coder) instrLeaRIP(disp int32, target regs.R) {
	code.WriteByte(rexW)
	code.WriteByte(0x8d)
	code.WriteByte(modRM(0, target, (1<<2)|(1<<0)))
	code.immediate(disp)
}

func (code *Coder) instrNop() {
	code.WriteByte(0x90)
}

func (code *Coder) instrRet() {
	code.WriteByte(0xc3)
}

func (code *Coder) instrUb2() {
	code.WriteByte(0x0f)
	code.WriteByte(0x0b)
}

func (code *Coder) stubInstrCall() {
	code.WriteByte(0xe8)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
}

const (
	opcodeJe  = 0x84
	opcodeJle = 0x8e
	opcodeJne = 0x85
)

func (code *Coder) stubInstrJcc(opcode byte) {
	code.WriteByte(0x0f)
	code.WriteByte(opcode)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
}

func (code *Coder) stubInstrJmp() {
	code.WriteByte(0xe9)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
}

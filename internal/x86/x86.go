// +build amd64
package x86

import (
	"bytes"
	"encoding/binary"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
)

const (
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
	// rdi

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
		code.intUnaryOp(name, t, subject)

	case types.Float:
		code.floatUnaryOp(name, t, subject)

	default:
		panic(t)
	}
}

// BinaryOp operates on two typed registers.
func (code *Coder) BinaryOp(name string, t types.T, source, target regs.R) {
	switch t.Category() {
	case types.Int:
		code.intBinaryOp(name, t, source, target)

	case types.Float:
		code.floatBinaryOp(name, t, source, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpAddToStackPtr(offset int) {
	code.opIntAdd64Imm(offset, regStackPtr)
}

func (code *Coder) OpBranchIndirect(reg regs.R) (branchAddr int) {
	code.instrLeaRIP(0, regScratch)
	branchAddr = code.Len()
	code.intBinaryOp("add", types.I64, reg, regScratch)
	code.instrJmpReg(regScratch)
	return
}

func (code *Coder) OpInvalid() {
	code.instrUb2()
}

func (code *Coder) OpLoadRODataDispRegScaleInplace(t types.T, addr int, dispType types.T, reg regs.R, scale uint8) {
	if addr < 0 || 0x80000000 <= addr {
		panic(addr)
	}

	if dispType != types.I64 {
		// TODO: sign-extend
	}

	code.instrIntShl64Imm8(scale, reg)

	if addr != 0 {
		code.instrIntAdd64Imm(opcodeIntAdd64Imm32, int32(addr), reg)
	}

	code.intBinaryOp("add", types.I64, regRODataPtr, reg)

	switch dispType {
	case types.I32:
		code.instrIntMovsxdFromMemIndirect(reg, reg)

	case types.I64:
		code.instrIntMovFromMemIndirect(t, reg, reg)

	default:
		panic(t)
	}
}

func (code *Coder) OpLoadStack(t types.T, sourceOffset int, target regs.R) {
	var dispMod byte
	var dispOffset interface{}

	switch {
	case sourceOffset < 0:
		panic(sourceOffset)

	case (sourceOffset & 7) != 0:
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
		code.instrIntMovFromStackDisp(t, dispMod, dispOffset, target)

	case types.Float:
		code.instrFloatMovFromStackDisp(dispMod, dispOffset, target)

	default:
		panic(t)
	}
}

func (code *Coder) OpMove(t types.T, source, target regs.R) {
	code.BinaryOp("mov", t, source, target)
}

func (code *Coder) OpMoveImm(t types.T, value interface{}, target regs.R) {
	switch t.Category() {
	case types.Int:
		code.instrIntMovImm(t, value, target)

	case types.Float:
		code.opFloatMoveImm(t, value, target)

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

func (code *Coder) StubOpBranch() {
	code.instrJmpDisp8Value0(opcodeJmp)
}

func (code *Coder) StubOpBranchIf(t types.T, subject regs.R) {
	code.UnaryOp("test", t, subject)
	code.instrJmpDisp8Value0(opcodeJne)
}

func (code *Coder) StubOpBranchIfNot(t types.T, subject regs.R) {
	code.UnaryOp("test", t, subject)
	code.instrJmpDisp8Value0(opcodeJe)
}

func (code *Coder) StubOpBranchIfOutOfBounds(t types.T, indexReg regs.R, upperBound interface{}) {
	code.instrIntMovImm(t, upperBound, regScratch)
	code.UnaryOp("test", t, indexReg)
	code.instrIntCmov(opcodeIntCmovl, t, regScratch, indexReg) // transform negative index to upper bound
	code.intBinaryOp("sub", t, indexReg, regScratch)
	code.instrJmpDisp8Value0(opcodeJle)
}

func (code *Coder) StubOpCall() {
	code.instrCallDisp32Value0()
}

func (code *Coder) UpdateBranches(l *links.L) {
	for _, addr := range l.Sites {
		offset := l.Address - addr
		if offset < -0x80 || 0x80 <= offset {
			panic(offset)
		}

		code.updateJmpDisp8(addr, int8(offset))
	}
}

func (code *Coder) UpdateCalls(l *links.L) {
	for _, addr := range l.Sites {
		offset := l.Address - addr
		if offset < -0x80000000 || 0x80000000 <= offset {
			panic(offset)
		}

		code.updateCallDisp32(addr, int32(offset))
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
	return (mod << 6) | (byte(ro) << 3) | byte(rm)
}

func sib(scale, index, base byte) byte {
	return (scale << 6) | (index << 3) | base
}

func (code *Coder) fromStack(mod byte, target regs.R) {
	code.WriteByte(modRM(mod, target, 1<<2))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
}

func (code *Coder) fromStackDisp(mod byte, disp interface{}, target regs.R) {
	code.fromStack(mod, target)
	code.immediate(disp)
}

func (code *Coder) toStack(mod byte, source regs.R) {
	code.WriteByte(modRM(mod, source, 1<<2))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
}

func (code *Coder) updateDataDisp32(addr int, disp int32) {
	byteOrder.PutUint32(code.Bytes()[addr-4:addr], uint32(disp))
}

// call
func (code *Coder) instrCallDisp32Value0() {
	code.WriteByte(0xe8)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
}

func (code *Coder) updateCallDisp32(addr int, disp int32) {
	byteOrder.PutUint32(code.Bytes()[addr-4:addr], uint32(disp))
}

// jmp
func (code *Coder) instrJmpReg(addrReg regs.R) {
	code.WriteByte(0xff)
	code.WriteByte(modRM(modReg, 0x4, addrReg))
}

const (
	opcodeJmp = 0xeb
	opcodeJe  = 0x74
	opcodeJne = 0x75
	opcodeJle = 0x7e
)

func (code *Coder) instrJmpDisp8Value0(opcode byte) {
	code.WriteByte(opcode)
	code.WriteByte(0)
}

func (code *Coder) updateJmpDisp8(addr int, disp int8) {
	code.Bytes()[addr-1] = byte(disp)
}

// lea
func (code *Coder) instrLeaRIP(disp int32, target regs.R) {
	code.WriteByte(rexW)
	code.WriteByte(0x8d)
	code.WriteByte(modRM(0, target, (1<<2)|(1<<0)))
	code.immediate(disp)
}

// nop
func (code *Coder) instrNop() {
	code.WriteByte(0x90)
}

// ret
func (code *Coder) instrRet() {
	code.WriteByte(0xc3)
}

// ub2
func (code *Coder) instrUb2() {
	code.WriteByte(0x0f)
	code.WriteByte(0x0b)
}

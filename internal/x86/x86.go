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

	//            regs.R0      rax
	//            regs.R1      rcx
	//            -            rdx
	regScratch  = regs.R(3) // rbx
	regStackPtr = 4         // rsp
	regBasePtr  = 5         // rbp

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

func (Machine) FunctionCallStackOverhead() int {
	return 2 * 8 // return address + caller's base ptr
}

type Coder struct {
	bytes.Buffer
}

func (code *Coder) immediate(value interface{}) {
	if err := binary.Write(code, byteOrder, value); err != nil {
		panic(err)
	}
}

func (code *Coder) FunctionPrologue() {
	code.instrIntPush(regBasePtr)
	code.intBinaryOp("mov", types.I64, regStackPtr, regBasePtr)
}

func (code *Coder) FunctionEpilogue() {
	code.intBinaryOp("mov", types.I64, regBasePtr, regStackPtr)
	code.instrIntPop(regBasePtr)
	code.instrRet()
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

func (code *Coder) OpInvalid() {
	code.instrUb2()
}

func (code *Coder) OpLoadLocal(t types.T, sourceOffset int, target regs.R) {
	var dispMod byte
	var dispOffset interface{}

	switch {
	case -0x80 <= sourceOffset && sourceOffset < 0x80:
		dispMod = modDisp8
		dispOffset = int8(sourceOffset)

	case -0x80000000 <= sourceOffset && sourceOffset < 0x80000000:
		dispMod = modDisp32
		dispOffset = int32(sourceOffset)

	default:
		panic(sourceOffset)
	}

	switch t.Category() {
	case types.Int:
		code.instrIntMovFromBaseDisp(t, dispMod, dispOffset, target)

	case types.Float:
		code.instrFloatMovFromBaseDisp(t, dispMod, dispOffset, target)

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

func (code *Coder) StubOpBranch() {
	code.instrJmpDisp8Value0()
}

func (code *Coder) StubOpBranchIf(t types.T, subject regs.R) {
	code.UnaryOp("eflags", t, subject)
	code.instrJneDisp8Value0()
}

func (code *Coder) StubOpBranchIfNot(t types.T, subject regs.R) {
	code.UnaryOp("eflags", t, subject)
	code.instrJeDisp8Value0()
}

func (code *Coder) StubOpCall() {
	code.instrCallDisp32Value0()
}

func (code *Coder) UpdateBranches(l *links.L) {
	for _, pos := range l.Sites {
		offset := l.Address - pos
		if offset < -0x80 || 0x80 <= offset {
			panic(offset)
		}

		code.updateJDisp8(pos, int8(offset))
	}
}

func (code *Coder) UpdateCalls(l *links.L) {
	for _, pos := range l.Sites {
		offset := l.Address - pos
		if offset < -0x80000000 || 0x80000000 <= offset {
			panic(offset)
		}

		code.updateCallDisp32(pos, int32(offset))
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

func (code *Coder) fromBaseDisp(mod byte, disp interface{}, target regs.R) {
	code.WriteByte(modRM(mod, target, (1<<2)|(1<<0)))
	code.immediate(disp)
}

func (code *Coder) toStack(mod byte, source regs.R) {
	code.WriteByte(modRM(mod, source, 1<<2))
	code.WriteByte(sib(0, regStackPtr, regStackPtr))
}

// call
func (code *Coder) instrCallDisp32Value0() {
	code.WriteByte(0xe8)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
	code.WriteByte(0)
}

func (code *Coder) updateCallDisp32(pos int, disp int32) {
	byteOrder.PutUint32(code.Bytes()[pos-4:pos], uint32(disp))
}

// jmp
func (code *Coder) instrJmpDisp8Value0() {
	code.WriteByte(0xeb)
	code.WriteByte(0)
}

// je
func (code *Coder) instrJeDisp8Value0() {
	code.WriteByte(0x74)
	code.WriteByte(0)
}

// jne
func (code *Coder) instrJneDisp8Value0() {
	code.WriteByte(0x75)
	code.WriteByte(0)
}

func (code *Coder) updateJDisp8(pos int, disp int8) {
	code.Bytes()[pos-1] = byte(disp)
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

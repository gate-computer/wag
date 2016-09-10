package x86

import (
	"bytes"
	"encoding/binary"

	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/traps"
)

const (
	// regs.R0 = rax
	// regs.R1 = rcx
	regDividendHi = regs.R2   // rdx
	regScratch    = regs.R(3) // rbx
	regStackPtr   = 4         // rsp
	regStackLimit = regs.R(5) // rbp
	regRODataPtr  = regs.R(6) // rsi
	regTextPtr    = regs.R(7) // rdi
	regTrapArg    = regs.R(7) // rdi
	regTrapFunc   = regs.R(8) // r8

	wordSize      = 8
	codeAlignment = 16
	paddingByte   = 0xcc // int3 instruction
)

var (
	byteOrder = binary.LittleEndian
)

var (
	Ret  = insnFixed{0xc3}
	Int3 = insnFixed{0xcc}
	Call = insnFixed{0xe8, 0, 0, 0, 0}
	Jmp  = insnFixed{0xe9, 0, 0, 0, 0}
	Je   = insnFixed{0x0f, 0x84, 0, 0, 0, 0}
	Jne  = insnFixed{0x0f, 0x85, 0, 0, 0, 0}
	Jl   = insnFixed{0x0f, 0x8c, 0, 0, 0, 0}
	Jle  = insnFixed{0x0f, 0x8e, 0, 0, 0, 0}

	Push = insnReg{0x50}
	Pop  = insnReg{0x58}

	CallIndirect = insnModOpReg{[]byte{0xff}, 2}
	JmpIndirect  = insnModOpReg{[]byte{0xff}, 4}
	Sete         = insnModOpReg{[]byte{0x0f, 0x94}, 0}
	Setne        = insnModOpReg{[]byte{0x0f, 0x95}, 0}
	Seta         = insnModOpReg{[]byte{0x0f, 0x97}, 0}
	Setl         = insnModOpReg{[]byte{0x0f, 0x9c}, 0}
	Setg         = insnModOpReg{[]byte{0x0f, 0x9f}, 0}

	LeaRip = insnModRegMemImm{[]byte{rexW, 0x8d}, modMem{ModIndir, MemDisp32}}

	LeaStack = insnPrefixModRegSibImm{rex, []byte{0x8d}, sib{0, regStackPtr, regStackPtr}}
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
	divideByZero links.L
}

func (code *Coder) DivideByZeroTarget() *links.L {
	return &code.divideByZero
}

// regOp operates on a single register.
func (code *Coder) regOp(intOp func(*Coder, regs.R), floatOp func(*Coder, types.T, regs.R), t types.T, subject regs.R) {
	switch t.Category() {
	case types.Int:
		intOp(code, subject)

	case types.Float:
		floatOp(code, t, subject)

	default:
		panic(t)
	}
}

// UnaryOp operates on a single typed register.
func (code *Coder) UnaryOp(name string, t types.T) {
	switch t.Category() {
	case types.Int:
		unaryIntOp(code, name, t)

	case types.Float:
		unaryFloatOp(code, name, t)

	default:
		panic(t)
	}
}

// BinaryOp operates on two typed registers, and trashes three registers.
func (code *Coder) BinaryOp(name string, t types.T) {
	switch t.Category() {
	case types.Int:
		binaryIntOp(code, name, t)

	case types.Float:
		binaryFloatOp(code, name, t)

	default:
		panic(t)
	}
}

func (code *Coder) OpAbort() {
	Int3.op(code)
}

func (code *Coder) OpAddImmToStackPtr(offset int) {
	switch {
	case offset > 0:
		AddImm.op(code, types.I64, regStackPtr, offset)

	case offset < 0:
		SubImm.op(code, types.I64, regStackPtr, -offset)
	}
}

func (code *Coder) OpAddToStackPtr(source regs.R) {
	Add.op(code, types.I64, regStackPtr, source)
}

func (code *Coder) OpBranchIndirect(t types.T, reg regs.R) (branchAddr int) {
	if t == types.I32 {
		Movsxd.op(code, types.I32, reg, reg)
	}

	LeaRip.op(code, regScratch, imm32(0))
	branchAddr = code.Len()
	Add.op(code, types.I64, regScratch, reg)
	JmpIndirect.op(code, regScratch)
	return
}

func (code *Coder) OpCallIndirectDisp32FromStack(ptrStackOffset int) {
	MovsxdFromStack.op(code, types.I32, regScratch, ptrStackOffset)
	Add.op(code, types.I64, regScratch, regTextPtr)
	CallIndirect.op(code, regScratch)
}

func (code *Coder) OpClear(subject regs.R) {
	Xor.op(code, types.I64, subject, subject)
}

func (code *Coder) OpLoadROIntIndex32ScaleDisp(t types.T, reg regs.R, scale uint8, addr int, signExt bool) {
	Movsxd.op(code, types.I32, reg, reg)

	if signExt && t == types.I32 {
		MovsxdFromIndirectScaleIndex.op(code, t, reg, scale, reg, regRODataPtr, addr)
	} else {
		MovFromIndirectScaleIndex.op(code, t, reg, scale, reg, regRODataPtr, addr)
	}
}

func (code *Coder) OpLoadStack(t types.T, target regs.R, sourceOffset int) {
	switch t.Category() {
	case types.Int:
		MovFromStack.op(code, t, target, sourceOffset)

	case types.Float:
		MovssMovsdFromStack.op(code, t, target, sourceOffset)

	default:
		panic(t)
	}
}

func (code *Coder) OpMove(t types.T, target, source regs.R) {
	switch t.Category() {
	case types.Int:
		Mov.op(code, t, target, source)

	case types.Float:
		MovssMovsd.op(code, t, target, source)

	default:
		panic(t)
	}
}

func (code *Coder) OpMoveImmInt(t types.T, target regs.R, value interface{}) {
	MovImm.op(code, t, target, imm{value})
}

func (code *Coder) OpLoadROFloatDisp(t types.T, target regs.R, addr int) {
	MovssMovsdFromIndirect.op(code, t, target, regRODataPtr, addr)
}

func (code *Coder) OpPop(t types.T, target regs.R) {
	code.regOp(Pop.op, popFloatOp, t, target)
}

func (code *Coder) OpPush(t types.T, source regs.R) {
	code.regOp(Push.op, pushFloatOp, t, source)
}

func (code *Coder) OpReturn() {
	Ret.op(code)
}

func (code *Coder) OpShiftRightLogical32Bits(subject regs.R) {
	ShrImm.op(code, types.I64, subject, uimm8(-32))
}

func (code *Coder) OpStoreStack(t types.T, targetOffset int, source regs.R) {
	switch t.Category() {
	case types.Int:
		MovToStack.op(code, t, source, targetOffset)

	case types.Float:
		MovssMovsdToStack.op(code, t, source, targetOffset)

	default:
		panic(t)
	}
}

func (code *Coder) OpTrap(id traps.Id) {
	MovImm.op(code, types.I64, regTrapArg, imm64(int(id)))
	Mov.op(code, types.I64, regScratch, regTrapFunc)
	CallIndirect.op(code, regScratch)
}

func (code *Coder) StubOpBranch() {
	Jmp.op(code)
}

func (code *Coder) StubOpBranchIf(subject regs.R) {
	Test.op(code, types.I32, subject, subject)
	Jne.op(code)
}

func (code *Coder) StubOpBranchIfNot(subject regs.R) {
	Test.op(code, types.I32, subject, subject)
	Je.op(code)
}

func (code *Coder) StubOpBranchIfNotEqualImm32(subject regs.R, value int) {
	CmpImm.op(code, types.I32, subject, value)
	Jne.op(code)
}

func (code *Coder) StubOpBranchIfOutOfBounds(indexReg regs.R, upperBound int) {
	MovImm.op(code, types.I32, regScratch, imm32(upperBound))
	Test.op(code, types.I32, indexReg, indexReg)
	Cmovl.op(code, types.I32, indexReg, regScratch) // negative index -> upper bound
	Cmp.op(code, types.I32, regScratch, indexReg)
	Jle.op(code)
}

func (code *Coder) StubOpBranchIfStackExhausted() (stackUsageAddr int) {
	LeaStack.op(code, types.I64, regScratch, -0x80000000) // reserve 32-bit displacement
	stackUsageAddr = code.Len()
	Cmp.op(code, types.I64, regScratch, regStackLimit)
	Jl.op(code)
	return
}

func (code *Coder) StubOpCall() {
	Call.op(code)
}

func (code *Coder) UpdateBranches(l *links.L) {
	code.updateSites(l)
}

func (code *Coder) UpdateCalls(l *links.L) {
	code.updateSites(l)
}

func (code *Coder) UpdateStackDisp(addr int, value int) {
	code.updateAddr(addr, -value)
}

func (code *Coder) updateAddr(addr int, value int) {
	if value < -0x80000000 || 0x80000000 <= value {
		panic(value)
	}

	byteOrder.PutUint32(code.Bytes()[addr-4:addr], uint32(value))
}

func (code *Coder) updateSites(l *links.L) {
	for _, addr := range l.Sites {
		code.updateAddr(addr, l.Address-addr)
	}
}

func (code *Coder) AlignFunction() {
	size := codeAlignment - (code.Len() & (codeAlignment - 1))
	if size < codeAlignment {
		for i := 0; i < size; i++ {
			code.WriteByte(paddingByte)
		}
	}
}

package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
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

	wordSize          = 8
	functionAlignment = 16
	paddingByte       = 0xcc // int3 instruction
)

var (
	byteOrder = binary.LittleEndian

	nopSequences = [][]byte{
		[]byte{0x90},
		[]byte{0x66, 0x90},
		[]byte{0x0f, 0x1f, 0x00},
		[]byte{0x0f, 0x1f, 0x40, 0x00},
		[]byte{0x0f, 0x1f, 0x44, 0x00, 0x00},
		[]byte{0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},
		[]byte{0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
		[]byte{0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
)

var (
	Nop  = insnFixed{0x90}
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

type X86 struct{}

func (x86 X86) WordSize() int                  { return wordSize }
func (x86 X86) ByteOrder() binary.ByteOrder    { return binary.LittleEndian }
func (x86 X86) FunctionCallStackOverhead() int { return wordSize }
func (x86 X86) FunctionAlignment() int         { return functionAlignment }

// UnaryOp operates on a single typed register.
func (x86 X86) UnaryOp(code *gen.Coder, name string, t types.T, x values.Operand) values.Operand {
	switch t.Category() {
	case types.Int:
		return x86.unaryIntOp(code, name, t, x)

	case types.Float:
		x86.unaryFloatOp(code, name, t, x)
		return values.RegOperand(regs.R0)

	default:
		panic(t)
	}
}

// BinaryOp operates on two typed registers, and trashes three registers.
func (x86 X86) BinaryOp(code *gen.Coder, name string, t types.T, a, b values.Operand) values.Operand {
	if reg, ok := b.CheckReg(); ok && reg == regs.R0 {
		b = x86.OpMove(code, t, regScratch, b)
	}

	x86.getRegOperandIn(code, t, regs.R0, a)

	switch t.Category() {
	case types.Int:
		return x86.binaryIntOp(code, name, t, b)

	case types.Float:
		x86.binaryFloatOp(code, name, t, b)
		return values.RegOperand(regs.R0)

	default:
		panic(t)
	}
}

func (x86 X86) OpAbort(code *gen.Coder) {
	Int3.op(code)
}

func (x86 X86) OpAddImmToStackPtr(code *gen.Coder, offset int) {
	switch {
	case offset > 0:
		AddImm.op(code, types.I64, regStackPtr, offset)

	case offset < 0:
		SubImm.op(code, types.I64, regStackPtr, -offset)
	}
}

func (x86 X86) OpAddToStackPtr(code *gen.Coder, source regs.R) {
	Add.op(code, types.I64, regStackPtr, source)
}

func (x86 X86) OpBranchIndirect(code *gen.Coder, t types.T, reg regs.R) (branchAddr int) {
	if t == types.I32 {
		Movsxd.op(code, types.I32, reg, reg)
	}

	LeaRip.op(code, regScratch, imm32(0))
	branchAddr = code.Len()
	Add.op(code, types.I64, regScratch, reg)
	JmpIndirect.op(code, regScratch)
	return
}

func (x86 X86) OpCallIndirectDisp32FromStack(code *gen.Coder, ptrStackOffset int) {
	MovsxdFromStack.op(code, types.I32, regScratch, ptrStackOffset)
	Add.op(code, types.I64, regScratch, regTextPtr)
	CallIndirect.op(code, regScratch)
}

func (x86 X86) OpClear(code *gen.Coder, subject regs.R) {
	Xor.op(code, types.I64, subject, subject)
}

func (x86 X86) OpLoadROIntIndex32ScaleDisp(code *gen.Coder, t types.T, reg regs.R, scale uint8, addr int, signExt bool) {
	Movsxd.op(code, types.I32, reg, reg)

	if signExt && t == types.I32 {
		MovsxdFromIndirectScaleIndex.op(code, t, reg, scale, reg, regRODataPtr, addr)
	} else {
		MovFromIndirectScaleIndex.op(code, t, reg, scale, reg, regRODataPtr, addr)
	}
}

func (x86 X86) OpMove(code *gen.Coder, t types.T, targetReg regs.R, source values.Operand) values.Operand {
	switch t.Category() {
	case types.Int:
		switch source.Storage {
		case values.Imm:
			switch source.ImmValue(t) {
			case 0:
				Xor.op(code, t, targetReg, targetReg)

			default:
				MovImm.op(code, t, targetReg, imm{source.Imm(t)})
			}

		case values.StackOffset:
			MovFromStack.op(code, t, targetReg, source.Offset())

		case values.Reg:
			if sourceReg := source.Reg(); sourceReg != targetReg {
				Mov.op(code, t, targetReg, sourceReg)
			}

		case values.StackPop:
			Pop.op(code, targetReg)

		default:
			panic(source)
		}

	case types.Float:
		switch source.Storage {
		case values.StackOffset:
			MovssMovsdFromStack.op(code, t, targetReg, source.Offset())

		case values.ROData:
			MovssMovsdFromIndirect.op(code, t, targetReg, regRODataPtr, source.Addr())

		case values.Reg:
			if sourceReg := source.Reg(); sourceReg != targetReg {
				MovssMovsd.op(code, t, targetReg, sourceReg)
			}

		case values.StackPop:
			popFloatOp(code, t, targetReg)

		default:
			panic(source)
		}

	default:
		panic(t)
	}

	return values.RegOperand(targetReg)
}

func (x86 X86) OpPush(code *gen.Coder, t types.T, source values.Operand) {
	reg := x86.getTempRegOperand(code, t, source)

	switch t.Category() {
	case types.Int:
		Push.op(code, reg)

	case types.Float:
		pushFloatOp(code, t, reg)

	default:
		panic(t)
	}
}

func (x86 X86) OpReturn(code *gen.Coder) {
	Ret.op(code)
}

func (x86 X86) OpShiftRightLogical32Bits(code *gen.Coder, subject regs.R) {
	ShrImm.op(code, types.I64, subject, uimm8(-32))
}

func (x86 X86) OpStoreStack(code *gen.Coder, t types.T, targetOffset int, source values.Operand) {
	sourceReg := x86.getTempRegOperand(code, t, source)

	switch t.Category() {
	case types.Int:
		MovToStack.op(code, t, sourceReg, targetOffset)

	case types.Float:
		MovssMovsdToStack.op(code, t, sourceReg, targetOffset)

	default:
		panic(t)
	}
}

func (x86 X86) OpTrap(code *gen.Coder, id traps.Id) {
	MovImm.op(code, types.I64, regTrapArg, imm64(int(id)))
	Mov.op(code, types.I64, regScratch, regTrapFunc)
	CallIndirect.op(code, regScratch)
}

func (x86 X86) StubOpBranch(code *gen.Coder) {
	Jmp.op(code)
}

func (x86 X86) StubOpBranchIf(code *gen.Coder, subject values.Operand) {
	reg := x86.getTempRegOperand(code, types.I32, subject)

	Test.op(code, types.I32, reg, reg)
	Jne.op(code)
}

func (x86 X86) StubOpBranchIfNot(code *gen.Coder, subject values.Operand) {
	reg := x86.getTempRegOperand(code, types.I32, subject)

	Test.op(code, types.I32, reg, reg)
	Je.op(code)
}

func (x86 X86) StubOpBranchIfNotEqualImm32(code *gen.Coder, operand values.Operand, value int) {
	reg := x86.getTempRegOperand(code, types.I32, operand)

	CmpImm.op(code, types.I32, reg, value)
	Jne.op(code)
}

func (x86 X86) StubOpBranchIfOutOfBounds(code *gen.Coder, indexReg regs.R, upperBound int) {
	MovImm.op(code, types.I32, regScratch, imm32(upperBound))
	Test.op(code, types.I32, indexReg, indexReg)
	Cmovl.op(code, types.I32, indexReg, regScratch) // negative index -> upper bound
	Cmp.op(code, types.I32, regScratch, indexReg)
	Jle.op(code)
}

func (x86 X86) StubOpBranchIfStackExhausted(code *gen.Coder) (stackUsageAddr int) {
	LeaStack.op(code, types.I64, regScratch, -0x80000000) // reserve 32-bit displacement
	stackUsageAddr = code.Len()
	Cmp.op(code, types.I64, regScratch, regStackLimit)
	Jl.op(code)
	return
}

func (x86 X86) StubOpCall(code *gen.Coder) {
	Call.op(code)
}

func (x86 X86) UpdateBranches(code *gen.Coder, l *links.L) {
	x86.updateSites(code, l)
}

func (x86 X86) UpdateCalls(code *gen.Coder, l *links.L) {
	x86.updateSites(code, l)
}

func (x86 X86) UpdateStackDisp(code *gen.Coder, addr int, value int) {
	x86.updateAddr(code, addr, -value)
}

func (x86 X86) updateAddr(code *gen.Coder, addr int, value int) {
	if value < -0x80000000 || 0x80000000 <= value {
		panic(value)
	}

	byteOrder.PutUint32(code.Bytes()[addr-4:addr], uint32(value))
}

func (x86 X86) updateSites(code *gen.Coder, l *links.L) {
	for _, addr := range l.Sites {
		x86.updateAddr(code, addr, l.Address-addr)
	}
}

func (x86 X86) AlignFunction(code *gen.Coder) {
	size := functionAlignment - (code.Len() & (functionAlignment - 1))
	if size < functionAlignment {
		for i := 0; i < size; i++ {
			code.WriteByte(paddingByte)
		}
	}
}

func (x86 X86) DeleteCode(code *gen.Coder, addrBegin, addrEnd int) {
	for i := addrBegin; i < addrEnd; i++ {
		code.Bytes()[i] = paddingByte
	}
}

func (x86 X86) DisableCode(code *gen.Coder, addrBegin, addrEnd int) {
	buf := code.Bytes()[addrBegin:addrEnd]
	for len(buf) > 0 {
		n := len(buf)
		if n > len(nopSequences) {
			n = len(nopSequences)
		}
		copy(buf[:n], nopSequences[n-1])
		buf = buf[n:]
	}
}

func (x86 X86) getTempRegOperand(code *gen.Coder, t types.T, o values.Operand) regs.R {
	if o.Storage != values.Reg {
		o = x86.OpMove(code, t, regScratch, o)
	}
	return o.Reg()
}

func (x86 X86) getRegOperandIn(code *gen.Coder, t types.T, target regs.R, o values.Operand) {
	if reg, ok := o.CheckReg(); !(ok && reg == target) {
		x86.OpMove(code, t, target, o)
	}
}

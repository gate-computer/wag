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
	wordSize          = 8
	functionAlignment = 16
	paddingByte       = 0xcc // int3 instruction
)

const (
	regResult     = regs.R(0)  // rax or xmm0
	regDividendLo = regs.R(0)  // rax
	regTrapFunc   = regs.R(0)  // mm0
	regScratch    = regs.R(2)  // rdx
	regDividendHi = regs.R(2)  // rdx
	regStackPtr   = 4          // rsp
	regTrapArg    = regs.R(7)  // rdi
	regStackLimit = regs.R(13) // r13
	regTextPtr    = regs.R(14) // r14
	regRODataPtr  = regs.R(15) // r15
)

var availableIntRegs = [][]bool{
	[]bool{
		false, // rax = result
		true,  // rcx
		false, // rdx = scratch
		true,  // rbx
		false, // rsp
		true,  // rbp
		true,  // rsi
		true,  // rdi
	},
	[]bool{
		true,  // r8
		true,  // r9
		true,  // r10
		true,  // r11
		true,  // r12
		false, // r13
		false, // r14
		false, // r15
	},
}

var availableFloatRegs = [][]bool{
	[]bool{
		false, // xmm0 = result
		true,
		true,
		true,
		true,
		true,
		true,
		true,
	},
	[]bool{
		true,
		true,
		true,
		true,
		true,
		true,
		true,
		true,
	},
}

var (
	byteOrder = binary.LittleEndian
)

var (
	Nop  = insnFixed{0x90}
	Ret  = insnFixed{0xc3}
	Int3 = insnFixed{0xcc}
	Call = insnFixed{0xe8, 0, 0, 0, 0}
	Jmp  = insnFixed{0xe9, 0, 0, 0, 0}
	Jb   = insnFixed{0x0f, 0x82, 0, 0, 0, 0}
	Jae  = insnFixed{0x0f, 0x83, 0, 0, 0, 0}
	Je   = insnFixed{0x0f, 0x84, 0, 0, 0, 0}
	Jne  = insnFixed{0x0f, 0x85, 0, 0, 0, 0}
	Jbe  = insnFixed{0x0f, 0x86, 0, 0, 0, 0}
	Ja   = insnFixed{0x0f, 0x87, 0, 0, 0, 0}
	Jl   = insnFixed{0x0f, 0x8c, 0, 0, 0, 0}
	Jge  = insnFixed{0x0f, 0x8d, 0, 0, 0, 0}
	Jle  = insnFixed{0x0f, 0x8e, 0, 0, 0, 0}
	Jg   = insnFixed{0x0f, 0x8f, 0, 0, 0, 0}

	CallIndirect = insnModOpReg{[]byte{0xff}, 2}
	JmpIndirect  = insnModOpReg{[]byte{0xff}, 4}
	Setb         = insnModOpReg{[]byte{0x0f, 0x92}, 0}
	Setae        = insnModOpReg{[]byte{0x0f, 0x93}, 0}
	Sete         = insnModOpReg{[]byte{0x0f, 0x94}, 0}
	Setne        = insnModOpReg{[]byte{0x0f, 0x95}, 0}
	Setbe        = insnModOpReg{[]byte{0x0f, 0x96}, 0}
	Seta         = insnModOpReg{[]byte{0x0f, 0x97}, 0}
	Setl         = insnModOpReg{[]byte{0x0f, 0x9c}, 0}
	Setge        = insnModOpReg{[]byte{0x0f, 0x9d}, 0}
	Setle        = insnModOpReg{[]byte{0x0f, 0x9e}, 0}
	Setg         = insnModOpReg{[]byte{0x0f, 0x9f}, 0}

	MovqFromMMX = insnPrefixModRegToReg{rexSize, []byte{0x0f, 0x7e}, ModReg}

	LeaRip = insnModRegMemImm{[]byte{rexW, 0x8d}, modMem{ModIndir, MemDisp32}}

	LeaStack = insnPrefixModRegSibImm{rexSize, []byte{0x8d}, sib{0, regStackPtr, regStackPtr}}
)

var jccInsns = []nullaryInsn{
	Je,  // EQ
	Jne, // NE
	Jge, // GE_S
	Jg,  // GT_S
	Jae, // GE_U
	Ja,  // GT_U
	Jle, // LE_S
	Jl,  // LT_S
	Jbe, // LE_U
	Jb,  // LT_U
}

var setccInsns = []unaryInsn{
	Sete,  // EQ
	Setne, // NE
	Setge, // GE_S
	Setg,  // GT_S
	Setae, // GE_U
	Seta,  // GT_U
	Setle, // LE_S
	Setl,  // LT_S
	Setbe, // LE_U
	Setb,  // LT_U
}

var nopSequences = [][]byte{
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

type X86 struct{}

func (x86 X86) WordSize() int                  { return wordSize }
func (x86 X86) ByteOrder() binary.ByteOrder    { return binary.LittleEndian }
func (x86 X86) FunctionCallStackOverhead() int { return wordSize }
func (x86 X86) FunctionAlignment() int         { return functionAlignment }
func (x86 X86) ResultReg() regs.R              { return regResult }
func (x86 X86) AvailableIntRegs() [][]bool     { return availableIntRegs }
func (x86 X86) AvailableFloatRegs() [][]bool   { return availableFloatRegs }

func (x86 X86) RegGroupPreference(t types.T) int {
	switch t {
	case types.I32, types.F32, types.F64:
		// 64-bit floats don't use rexW prefix, but latter float regs need rexB
		return 0

	case types.I64:
		// instructions will have rexW prefix anyway
		return 1

	default:
		panic(t)
	}
}

// UnaryOp operates on a single typed register.
func (x86 X86) UnaryOp(code gen.RegCoder, name string, t types.T, x values.Operand) values.Operand {
	switch t.Category() {
	case types.Int:
		return x86.unaryIntOp(code, name, t, x)

	case types.Float:
		return x86.unaryFloatOp(code, name, t, x)

	default:
		panic(t)
	}
}

// BinaryOp operates on two typed registers, and trashes three registers.
func (x86 X86) BinaryOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	switch t.Category() {
	case types.Int:
		return x86.binaryIntOp(code, name, t, a, b)

	case types.Float:
		return x86.binaryFloatOp(code, name, t, a, b)

	default:
		panic(t)
	}
}

func (x86 X86) OpAbort(code gen.Coder) {
	Int3.op(code)
}

func (x86 X86) OpAddImmToStackPtr(code gen.Coder, offset int) {
	switch {
	case offset > 0:
		AddImm.op(code, types.I64, regStackPtr, offset)

	case offset < 0:
		SubImm.op(code, types.I64, regStackPtr, -offset)
	}
}

func (x86 X86) OpAddToStackPtr(code gen.Coder, source regs.R) {
	Add.op(code, types.I64, regStackPtr, source)
}

func (x86 X86) OpBranchIndirect(code gen.Coder, t types.T, reg regs.R) (branchAddr int) {
	if t == types.I32 {
		Movsxd.op(code, types.I32, reg, reg)
	}

	LeaRip.op(code, regScratch, imm32(0))
	branchAddr = code.Len()
	Add.op(code, types.I64, regScratch, reg)
	JmpIndirect.op(code, regScratch)
	return
}

func (x86 X86) OpCallIndirectDisp32FromStack(code gen.Coder, ptrStackOffset int) {
	MovsxdFromStack.op(code, types.I32, regScratch, ptrStackOffset)
	Add.op(code, types.I64, regScratch, regTextPtr)
	CallIndirect.op(code, regScratch)
}

// OpLoadROIntIndex32ScaleDisp must not allocate registers.
func (x86 X86) OpLoadROIntIndex32ScaleDisp(code gen.Coder, t types.T, reg regs.R, scale uint8, addr int, signExt bool) {
	Movsxd.op(code, types.I32, reg, reg)

	if signExt && t == types.I32 {
		MovsxdFromIndirectScaleIndex.op(code, t, reg, scale, reg, regRODataPtr, addr)
	} else {
		MovFromIndirectScaleIndex.op(code, t, reg, scale, reg, regRODataPtr, addr)
	}
}

// TODO: rename this to something else
// OpMove must not update CPU's condition flags.
func (x86 X86) OpMove(code gen.RegCoder, t types.T, targetReg regs.R, x values.Operand) values.Operand {
	switch t.Category() {
	case types.Int:
		switch x.Storage {
		case values.Imm:
			value := x.ImmValue(t)

			switch {
			case value == 0:
				Xor.op(code, t, targetReg, targetReg)

			case -0x80000000 <= value && value < 0x80000000:
				MovImm32.op(code, t, targetReg, imm32(int(value)))

			case t.Size() == types.Size64 && value >= 0 && value < 0x100000000:
				// upper 32-bits will be zeroed automatically
				MovImm32.op(code, types.I32, targetReg, imm{uint32(value)})

			default:
				MovImm.op(code, t, targetReg, imm{x.Imm(t)})
			}

		case values.RegVar:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				Mov.op(code, t, targetReg, sourceReg)
			}

		case values.RegTemp:
			sourceReg := x.Reg()
			if sourceReg == targetReg {
				panic("moving temporary integer register to itself")
			}
			Mov.op(code, t, targetReg, sourceReg)
			code.FreeReg(t, sourceReg)

		case values.StackVar:
			MovFromStack.op(code, t, targetReg, x.Offset())

		case values.StackPop:
			Pop.op(code, targetReg)

		case values.ConditionFlags:
			if t.Size() != types.Size32 {
				panic(t)
			}
			setccInsns[int(x.Condition())].op(code, targetReg)
			Movzx8.op(code, targetReg, targetReg)

		default:
			panic(x)
		}

	case types.Float:
		switch x.Storage {
		case values.ROData:
			MovssMovsdFromIndirect.op(code, t, targetReg, regRODataPtr, x.Addr())

		case values.RegVar:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				MovssMovsd.op(code, t, targetReg, sourceReg)
			}

		case values.RegTemp:
			sourceReg := x.Reg()
			if sourceReg == targetReg {
				panic("moving temporary float register to itself")
			}
			MovssMovsd.op(code, t, targetReg, sourceReg)
			code.FreeReg(t, sourceReg)

		case values.StackVar:
			MovssMovsdFromStack.op(code, t, targetReg, x.Offset())

		case values.StackPop:
			popFloatOp(code, t, targetReg)

		default:
			panic(x)
		}

	default:
		panic(t)
	}

	return values.RegTempOperand(targetReg)
}

func (x86 X86) OpMoveReg(code gen.Coder, t types.T, targetReg, sourceReg regs.R) {
	if targetReg == sourceReg {
		panic("target and source registers are the same")
	}

	switch t.Category() {
	case types.Int:
		Mov.op(code, t, targetReg, sourceReg)

	case types.Float:
		MovssMovsd.op(code, t, targetReg, sourceReg)

	default:
		panic(t)
	}
}

func (x86 X86) OpPush(code gen.RegCoder, t types.T, x values.Operand) {
	reg, own := x86.opBorrowReg(code, t, x)
	if own {
		defer code.FreeReg(t, reg)
	}

	switch t.Category() {
	case types.Int:
		Push.op(code, reg)

	case types.Float:
		pushFloatOp(code, t, reg)

	default:
		panic(t)
	}
}

// OpPushIntReg must not allocate registers.
func (x86 X86) OpPushIntReg(code gen.Coder, sourceReg regs.R) {
	Push.op(code, sourceReg)
}

func (x86 X86) OpReturn(code gen.Coder) {
	Ret.op(code)
}

// OpShiftRightLogical32Bits must not allocate registers.
func (x86 X86) OpShiftRightLogical32Bits(code gen.Coder, subject regs.R) {
	ShrImm.op(code, types.I64, subject, uimm8(-32))
}

func (x86 X86) OpStoreStack(code gen.RegCoder, t types.T, offset int, x values.Operand) {
	reg, own := x86.opBorrowReg(code, t, x)
	if own {
		defer code.FreeReg(t, reg)
	}

	switch t.Category() {
	case types.Int:
		MovToStack.op(code, t, reg, offset)

	case types.Float:
		MovssMovsdToStack.op(code, t, reg, offset)

	default:
		panic(t)
	}
}

func (x86 X86) OpTrap(code gen.Coder, id traps.Id) {
	MovImm32.op(code, types.I64, regTrapArg, imm32(int(id)))
	MovqFromMMX.op(code, types.I64, regScratch, regTrapFunc)
	CallIndirect.op(code, regScratch)
}

func (x86 X86) StubOpBranch(code gen.Coder) {
	Jmp.op(code)
}

func (x86 X86) StubOpBranchIf(code gen.RegCoder, x values.Operand, yes bool) {
	cond, ok := x.CheckConditionFlags()
	if !ok {
		reg, own := x86.opBorrowReg(code, types.I32, x)
		if own {
			defer code.FreeReg(types.I32, reg)
		}

		Test.op(code, types.I32, reg, reg)
		cond = values.NE
	}

	if !yes {
		cond = values.InvertedConditions[cond]
	}

	jccInsns[int(cond)].op(code)
}

// StubOpBranchIfNotEqualImm32 must not allocate registers.
func (x86 X86) StubOpBranchIfNotEqualImm32(code gen.Coder, reg regs.R, value int) {
	CmpImm.op(code, types.I32, reg, value)
	Jne.op(code)
}

// StubOpBranchIfOutOfBounds must not allocate registers.
func (x86 X86) StubOpBranchIfOutOfBounds(code gen.Coder, indexReg regs.R, upperBound int) {
	MovImm32.op(code, types.I32, regScratch, imm32(upperBound))
	Test.op(code, types.I32, indexReg, indexReg)
	Cmovl.op(code, types.I32, indexReg, regScratch) // negative index -> upper bound
	Cmp.op(code, types.I32, regScratch, indexReg)
	Jle.op(code)
}

func (x86 X86) StubOpBranchIfStackExhausted(code gen.Coder) (stackUsageAddr int) {
	LeaStack.op(code, types.I64, regScratch, -0x80000000) // reserve 32-bit displacement
	stackUsageAddr = code.Len()
	Cmp.op(code, types.I64, regScratch, regStackLimit)
	Jl.op(code)
	return
}

func (x86 X86) StubOpCall(code gen.Coder) {
	Call.op(code)
}

func (x86 X86) UpdateBranches(code gen.Coder, l *links.L) {
	x86.updateSites(code, l)
}

func (x86 X86) UpdateCalls(code gen.Coder, l *links.L) {
	x86.updateSites(code, l)
}

func (x86 X86) UpdateStackDisp(code gen.Coder, addr int, value int) {
	x86.updateAddr(code, addr, -value)
}

func (x86 X86) updateAddr(code gen.Coder, addr int, value int) {
	if value < -0x80000000 || 0x80000000 <= value {
		panic(value)
	}

	byteOrder.PutUint32(code.Bytes()[addr-4:addr], uint32(value))
}

func (x86 X86) updateSites(code gen.Coder, l *links.L) {
	for _, addr := range l.Sites {
		x86.updateAddr(code, addr, l.Address-addr)
	}
}

func (x86 X86) AlignFunction(code gen.Coder) {
	size := functionAlignment - (code.Len() & (functionAlignment - 1))
	if size < functionAlignment {
		for i := 0; i < size; i++ {
			code.WriteByte(paddingByte)
		}
	}
}

func (x86 X86) DeleteCode(code gen.Coder, addrBegin, addrEnd int) {
	for i := addrBegin; i < addrEnd; i++ {
		code.Bytes()[i] = paddingByte
	}
}

func (x86 X86) DisableCode(code gen.Coder, addrBegin, addrEnd int) {
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

func (x86 X86) opOwnReg(code gen.RegCoder, t types.T, x values.Operand) (reg regs.R) {
	reg, ok := x.CheckRegTemp()
	if !ok {
		reg = code.OpAllocReg(t)
		x86.OpMove(code, t, reg, x)
	}
	return
}

func (x86 X86) opBorrowReg(code gen.RegCoder, t types.T, x values.Operand) (reg regs.R, own bool) {
	reg, ok := x.CheckRegVar()
	if !ok {
		reg = x86.opOwnReg(code, t, x)
		own = true
	}
	return
}

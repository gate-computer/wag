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

	paddingByte = 0xcc // int3 instruction
)

const (
	regResult      = regs.R(0)  // rax or xmm0
	regTrapFuncMMX = regs.R(0)  // mm0
	regScratch     = regs.R(2)  // rdx or xmm2
	regStackPtr    = regs.R(4)  // rsp
	regTrapArg     = regs.R(7)  // rdi
	regTextPtr     = regs.R(12) // r12
	regStackLimit  = regs.R(13) // r13
)

var availableIntRegs = [][]bool{
	[]bool{
		false, // rax = result / dividend low bits
		true,  // rcx
		false, // rdx = scratch / dividend high bits
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
		false, // r12 = text ptr
		false, // r13 = stack limit
		true,  // r14
		true,  // r15
	},
}

var availableFloatRegs = [][]bool{
	[]bool{
		false, // xmm0 = result
		true,
		false, // xmm2 = scratch
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
	Ret  = insnFixed{0xc3}
	Int3 = insnFixed{0xcc}

	Call = insnAddr{nil, []byte{0xe8}}
	Jmp  = insnAddr{[]byte{0xeb}, []byte{0xe9}}
	Jb   = insnAddr{[]byte{0x72}, []byte{0x0f, 0x82}}
	Jae  = insnAddr{[]byte{0x73}, []byte{0x0f, 0x83}}
	Je   = insnAddr{[]byte{0x74}, []byte{0x0f, 0x84}}
	Jne  = insnAddr{[]byte{0x75}, []byte{0x0f, 0x85}}
	Jbe  = insnAddr{[]byte{0x76}, []byte{0x0f, 0x86}}
	Ja   = insnAddr{[]byte{0x77}, []byte{0x0f, 0x87}}
	Jl   = insnAddr{[]byte{0x7c}, []byte{0x0f, 0x8c}}
	Jge  = insnAddr{[]byte{0x7d}, []byte{0x0f, 0x8d}}
	Jle  = insnAddr{[]byte{0x7e}, []byte{0x0f, 0x8e}}
	Jg   = insnAddr{[]byte{0x7f}, []byte{0x0f, 0x8f}}

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

var jccInsns = []addrInsn{
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

var setccInsns = []regInsn{
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

func (mach X86) WordSize() int                  { return wordSize }
func (mach X86) ByteOrder() binary.ByteOrder    { return binary.LittleEndian }
func (mach X86) FunctionCallStackOverhead() int { return wordSize }
func (mach X86) FunctionAlignment() int         { return functionAlignment }
func (mach X86) ResultReg() regs.R              { return regResult }
func (mach X86) AvailableIntRegs() [][]bool     { return availableIntRegs }
func (mach X86) AvailableFloatRegs() [][]bool   { return availableFloatRegs }

func (mach X86) RegGroupPreference(t types.T) int {
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
func (mach X86) UnaryOp(code gen.RegCoder, name string, t types.T, x values.Operand) values.Operand {
	switch t.Category() {
	case types.Int:
		return mach.unaryIntOp(code, name, t, x)

	case types.Float:
		return mach.unaryFloatOp(code, name, t, x)

	default:
		panic(t)
	}
}

// BinaryOp operates on two typed registers.
func (mach X86) BinaryOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) values.Operand {
	switch t.Category() {
	case types.Int:
		return mach.binaryIntOp(code, name, t, a, b)

	case types.Float:
		return mach.binaryFloatOp(code, name, t, a, b)

	default:
		panic(t)
	}
}

func (mach X86) OpAbort(code gen.Coder) {
	Int3.op(code)
}

// OpAddImmToStackPtr must not allocate registers.
func (mach X86) OpAddImmToStackPtr(code gen.Coder, offset int) {
	switch {
	case offset > 0:
		AddImm.op(code, types.I64, regStackPtr, offset)

	case offset < 0:
		SubImm.op(code, types.I64, regStackPtr, -offset)
	}
}

// OpAddToStackPtr must not allocate registers.
func (mach X86) OpAddToStackPtr(code gen.Coder, source regs.R) {
	Add.opReg(code, types.I64, regStackPtr, source)
}

// OpBranchIndirect must not allocate registers.
func (mach X86) OpBranchIndirect(code gen.Coder, t types.T, reg regs.R) (branchAddr int) {
	if t == types.I32 {
		Movsxd.opReg(code, types.I32, reg, reg)
	}

	LeaRip.op(code, regScratch, imm32(0))
	branchAddr = code.Len()
	Add.opReg(code, types.I64, regScratch, reg)
	JmpIndirect.op(code, regScratch)
	return
}

func (mach X86) OpCallIndirectDisp32FromStack(code gen.Coder, ptrStackOffset int) {
	MovsxdFromStack.op(code, types.I32, regScratch, ptrStackOffset)
	Add.opReg(code, types.I64, regScratch, regTextPtr)
	CallIndirect.op(code, regScratch)
}

func (mach X86) OpInit(code gen.Coder) {
	AddImm.op(code, types.I64, regStackLimit, wordSize) // reserve space for trap handler call
}

// OpLoadROIntIndex32ScaleDisp must not allocate registers.
func (mach X86) OpLoadROIntIndex32ScaleDisp(code gen.Coder, t types.T, reg regs.R, scale uint8, addr int, signExt bool) {
	Movsxd.opReg(code, types.I32, reg, reg)

	if signExt && t == types.I32 {
		MovsxdFromIndirectScaleIndex.opFromAddr(code, t, reg, scale, reg, code.RODataAddr()+addr)
	} else {
		MovFromIndirectScaleIndex.opFromAddr(code, t, reg, scale, reg, code.RODataAddr()+addr)
	}
}

// OpMove must not update CPU's condition flags.
func (mach X86) OpMove(code gen.Coder, t types.T, targetReg regs.R, x values.Operand) {
	switch t.Category() {
	case types.Int:
		switch x.Storage {
		case values.Imm:
			value := x.ImmValue(t)

			switch {
			case value == 0:
				Xor.opReg(code, t, targetReg, targetReg)

			case -0x80000000 <= value && value < 0x80000000:
				MovImm32.op(code, t, targetReg, imm32(int(value)))

			case t.Size() == types.Size64 && value >= 0 && value < 0x100000000:
				// upper 32-bits will be zeroed automatically
				MovImm32.op(code, types.I32, targetReg, imm{uint32(value)})

			default:
				MovImm.op(code, t, targetReg, imm{x.Imm(t)})
			}

		case values.VarMem:
			MovFromStack.op(code, t, targetReg, x.Offset())

		case values.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				Mov.op(code, t, targetReg, sourceReg)
			}

		case values.TempReg:
			sourceReg := x.Reg()
			if sourceReg == targetReg {
				panic("moving temporary integer register to itself")
			}
			Mov.op(code, t, targetReg, sourceReg)

		case values.Stack:
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
		case values.Imm:
			if x.ImmValue(t) != 0 {
				panic(x)
			}
			XorpsXorpd.op(code, t, targetReg, targetReg)

		case values.ROData:
			MovssMovsdFromIndirect.opFromAddr(code, t, targetReg, code.RODataAddr()+x.Addr())

		case values.VarMem:
			MovssMovsdFromStack.op(code, t, targetReg, x.Offset())

		case values.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				MovssMovsd.op(code, t, targetReg, sourceReg)
			}

		case values.TempReg:
			sourceReg := x.Reg()
			if sourceReg == targetReg {
				panic("moving temporary float register to itself")
			}
			MovssMovsd.op(code, t, targetReg, sourceReg)

		case values.Stack:
			popFloatOp(code, t, targetReg)

		default:
			panic(x)
		}

	default:
		panic(t)
	}

	code.Consumed(t, x)
}

// OpMoveReg must not allocate registers.
func (mach X86) OpMoveReg(code gen.Coder, t types.T, targetReg, sourceReg regs.R) {
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

// OpPush must not allocate registers nor update CPU's condition flags.
func (mach X86) OpPush(code gen.Coder, t types.T, x values.Operand) {
	reg, ok := x.CheckTempReg()
	if ok {
		defer code.FreeReg(t, reg)
	} else {
		reg, ok = x.CheckVarReg()
		if !ok {
			reg = regScratch
			mach.OpMove(code, t, reg, x)
		}
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
func (mach X86) OpPushIntReg(code gen.Coder, sourceReg regs.R) {
	Push.op(code, sourceReg)
}

func (mach X86) OpReturn(code gen.Coder) {
	Ret.op(code)
}

// OpShiftRightLogical32Bits must not allocate registers.
func (mach X86) OpShiftRightLogical32Bits(code gen.Coder, subject regs.R) {
	ShrImm.op(code, types.I64, subject, uimm8(-32))
}

// OpStoreStack must not allocate registers.
func (mach X86) OpStoreStack(code gen.Coder, t types.T, offset int, x values.Operand) {
	reg, ok := x.CheckTempReg()
	if ok {
		defer code.FreeReg(t, reg)
	} else {
		reg, ok = x.CheckVarReg()
		if !ok {
			reg = regScratch
			mach.OpMove(code, t, reg, x)
		}
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

func (mach X86) OpTrap(code gen.Coder, id traps.Id) {
	MovImm32.op(code, types.I64, regTrapArg, imm32(int(id)))
	MovqFromMMX.op(code, types.I64, regScratch, regTrapFuncMMX)
	CallIndirect.op(code, regScratch)
	Int3.op(code) // if trap handler returns
}

func (mach X86) OpBranch(code gen.Coder, addr int) {
	Jmp.op(code, addr)
}

func (mach X86) OpBranchIf(code gen.Coder, x values.Operand, yes bool, addr int) {
	cond, ok := x.CheckConditionFlags()
	if !ok {
		reg, own := mach.opBorrowScratchReg(code, types.I32, x)
		if own {
			defer code.FreeReg(types.I32, reg)
		}

		Test.op(code, types.I32, reg, reg)
		cond = values.NE
	}

	if !yes {
		cond = values.InvertedConditions[cond]
	}

	jccInsns[int(cond)].op(code, addr)
}

// OpBranchIfNotEqualImm32 must not allocate registers.
func (mach X86) OpBranchIfNotEqualImm32(code gen.Coder, reg regs.R, value int, addr int) {
	CmpImm.op(code, types.I32, reg, value)
	Jne.op(code, addr)
}

// OpBranchIfOutOfBounds must not allocate registers.
func (mach X86) OpBranchIfOutOfBounds(code gen.Coder, indexReg regs.R, upperBound int, addr int) {
	MovImm32.op(code, types.I32, regScratch, imm32(upperBound))
	Test.op(code, types.I32, indexReg, indexReg)
	Cmovl.opReg(code, types.I32, indexReg, regScratch) // negative index -> upper bound
	Cmp.opReg(code, types.I32, regScratch, indexReg)
	Jle.op(code, addr)
}

func (mach X86) OpTrapIfStackExhausted(code gen.Coder) (stackUsageAddr int) {
	LeaStack.op(code, types.I64, regScratch, -0x80000000) // reserve 32-bit displacement
	stackUsageAddr = code.Len()
	Cmp.opReg(code, types.I64, regScratch, regStackLimit)
	Jl.op(code, code.TrapLinks().CallStackExhausted.FinalAddress())
	return
}

func (mach X86) OpCall(code gen.Coder, addr int) {
	Call.op(code, addr)
}

func (mach X86) UpdateBranches(code gen.Coder, l *links.L) {
	mach.updateSites(code, l)
}

func (mach X86) UpdateCalls(code gen.Coder, l *links.L) {
	mach.updateSites(code, l)
}

func (mach X86) UpdateStackDisp(code gen.Coder, addr int, value int) {
	mach.updateAddr(code, addr, -value)
}

func (mach X86) updateAddr(code gen.Coder, addr int, value int) {
	if value < -0x80000000 || 0x80000000 <= value {
		panic(value)
	}

	byteOrder.PutUint32(code.Bytes()[addr-4:addr], uint32(value))
}

func (mach X86) updateSites(code gen.Coder, l *links.L) {
	targetAddr := l.FinalAddress()
	for _, siteAddr := range l.Sites {
		mach.updateAddr(code, siteAddr, targetAddr-siteAddr)
	}
}

func (mach X86) AlignFunction(code gen.Coder) {
	size := functionAlignment - (code.Len() & (functionAlignment - 1))
	if size < functionAlignment {
		for i := 0; i < size; i++ {
			code.WriteByte(paddingByte)
		}
	}
}

func (mach X86) DeleteCode(code gen.Coder, addrBegin, addrEnd int) {
	for i := addrBegin; i < addrEnd; i++ {
		code.Bytes()[i] = paddingByte
	}
}

func (mach X86) DisableCode(code gen.Coder, addrBegin, addrEnd int) {
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

// opBorrowScratchReg returns either the register of the given operand, or the
// reserved scratch register with the value of the operand.
func (mach X86) opBorrowScratchReg(code gen.Coder, t types.T, x values.Operand) (reg regs.R, own bool) {
	reg, ok := x.CheckVarReg()
	if ok {
		return
	}

	reg, ok = x.CheckTempReg()
	if ok {
		own = true
		return
	}

	reg = regScratch
	mach.OpMove(code, t, reg, x)
	return
}

// opBorrowResultReg returns either the register of the given operand, or the
// reserved result register with the value of the operand.
func (mach X86) opBorrowResultReg(code gen.RegCoder, t types.T, x values.Operand) (reg regs.R, own bool) {
	reg, ok := x.CheckVarReg()
	if !ok {
		reg = mach.opResultReg(code, t, x)
		own = (reg != regResult)
	}

	return
}

// opResultReg returns either the register of the given operand, or the
// reserved result register with the value of the operand.  The caller has
// exclusive ownership of the register.
func (mach X86) opResultReg(code gen.RegCoder, t types.T, x values.Operand) (reg regs.R) {
	reg, ok := x.CheckTempReg()
	if !ok {
		reg, ok = code.TryAllocReg(t)
		if !ok {
			reg = regResult
		}

		if x.Storage != values.Nowhere {
			mach.OpMove(code, t, reg, x)
		}
	}

	return
}

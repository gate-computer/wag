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
	regMemoryPtr   = regs.R(14) // r14
	regMemoryLimit = regs.R(15) // r15
)

var availableIntRegs = [][]bool{
	[]bool{
		false, // rax = result / dividend low bits
		true,  // rcx
		false, // rdx = scratch / dividend high bits
		true,  // rbx
		false, // rsp = stack ptr
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
		false, // r14 = memory ptr
		false, // r15 = memory limit
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
	Ret  = insnConst{0xc3}
	Int3 = insnConst{0xcc}

	PushImm32 = insnI{0x68}
	PushImm8  = insnI{0x6a}

	CallRel = insnAddr32{0xe8}
	JmpRel  = insnAddr{insnAddr8{0xeb}, insnAddr32{0xe9}}
	Jb      = insnAddr{insnAddr8{0x72}, insnAddr32{0x0f, 0x82}}
	Jae     = insnAddr{insnAddr8{0x73}, insnAddr32{0x0f, 0x83}}
	Je      = insnAddr{insnAddr8{0x74}, insnAddr32{0x0f, 0x84}}
	Jne     = insnAddr{insnAddr8{0x75}, insnAddr32{0x0f, 0x85}}
	Jbe     = insnAddr{insnAddr8{0x76}, insnAddr32{0x0f, 0x86}}
	Ja      = insnAddr{insnAddr8{0x77}, insnAddr32{0x0f, 0x87}}
	Jp      = insnAddr{insnAddr8{0x7a}, insnAddr32{0x0f, 0x8a}}
	Jnp     = insnAddr{insnAddr8{0x7b}, insnAddr32{0x0f, 0x8b}}
	Jl      = insnAddr{insnAddr8{0x7c}, insnAddr32{0x0f, 0x8c}}
	Jge     = insnAddr{insnAddr8{0x7d}, insnAddr32{0x0f, 0x8d}}
	Jle     = insnAddr{insnAddr8{0x7e}, insnAddr32{0x0f, 0x8e}}
	Jg      = insnAddr{insnAddr8{0x7f}, insnAddr32{0x0f, 0x8f}}

	Call  = insnRexOM{[]byte{0xff}, 2}
	Jmp   = insnRexOM{[]byte{0xff}, 4}
	Setb  = insnRexOM{[]byte{0x0f, 0x92}, 0}
	Setae = insnRexOM{[]byte{0x0f, 0x93}, 0}
	Sete  = insnRexOM{[]byte{0x0f, 0x94}, 0}
	Setne = insnRexOM{[]byte{0x0f, 0x95}, 0}
	Setbe = insnRexOM{[]byte{0x0f, 0x96}, 0}
	Seta  = insnRexOM{[]byte{0x0f, 0x97}, 0}
	Setp  = insnRexOM{[]byte{0x0f, 0x9a}, 0}
	Setnp = insnRexOM{[]byte{0x0f, 0x9b}, 0}
	Setl  = insnRexOM{[]byte{0x0f, 0x9c}, 0}
	Setge = insnRexOM{[]byte{0x0f, 0x9d}, 0}
	Setle = insnRexOM{[]byte{0x0f, 0x9e}, 0}
	Setg  = insnRexOM{[]byte{0x0f, 0x9f}, 0}

	Lea     = insnPrefix{Rex, []byte{0x8d}, nil}
	MovqMMX = insnPrefix{Rex, nil, []byte{0x0f, 0x7e}}
)

var conditionInsns = []struct {
	jcc   insnAddr
	setcc insnRexOM
	cmov  insnPrefix
}{
	{Je, Sete, Cmove},    // EQ
	{Jne, Setne, Cmovne}, // NE
	{Jge, Setge, Cmovge}, // GESigned
	{Jg, Setg, Cmovg},    // GTSigned
	{Jae, Setae, Cmovae}, // GEUnsigned
	{Ja, Seta, Cmova},    // GTUnsigned
	{Jle, Setle, Cmovle}, // LESigned
	{Jl, Setl, Cmovl},    // LTSigned
	{Jbe, Setbe, Cmovbe}, // LEUnsigned
	{Jb, Setb, Cmovb},    // LTUnsigned

	{Je, Sete, Cmove},    // OrderedAndEQ
	{Jne, Setne, Cmovne}, // OrderedAndNE
	{Jge, Setge, Cmovge}, // OrderedAndGE
	{Jg, Setg, Cmovg},    // OrderedAndGT
	{Jle, Setle, Cmovle}, // OrderedAndLE
	{Jl, Setl, Cmovl},    // OrderedAndLT

	{Je, Sete, Cmove},    // UnorderedOrEQ
	{Jne, Setne, Cmovne}, // UnorderedOrNE
	{Jge, Setge, Cmovge}, // UnorderedOrGE
	{Jg, Setg, Cmovg},    // UnorderedOrGT
	{Jle, Setle, Cmovle}, // UnorderedOrLE
	{Jl, Setl, Cmovl},    // UnorderedOrLT
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

func (mach X86) WordSize() int                { return wordSize }
func (mach X86) ByteOrder() binary.ByteOrder  { return binary.LittleEndian }
func (mach X86) FunctionAlignment() int       { return functionAlignment }
func (mach X86) ResultReg() regs.R            { return regResult }
func (mach X86) AvailableIntRegs() [][]bool   { return availableIntRegs }
func (mach X86) AvailableFloatRegs() [][]bool { return availableFloatRegs }

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
		Add.opImm(code, types.I64, regStackPtr, offset)

	case offset < 0:
		Sub.opImm(code, types.I64, regStackPtr, -offset)
	}
}

// OpAddToStackPtr must not allocate registers.
func (mach X86) OpAddToStackPtr(code gen.Coder, source regs.R) {
	Add.opFromReg(code, types.I64, regStackPtr, source)
}

// OpBranchIndirect32 must not allocate registers.  The supplied register is
// trashed.
func (mach X86) OpBranchIndirect32(code gen.Coder, reg regs.R, regZeroExt bool) {
	if !regZeroExt {
		Mov.opFromReg(code, types.I32, reg, reg)
	}

	Add.opFromReg(code, types.I64, reg, regTextPtr)
	Jmp.opReg(code, reg)
}

func (mach X86) OpCallIndirectDisp32FromStack(code gen.Coder, ptrStackOffset int) {
	Movsxd.opFromStack(code, types.I32, regScratch, ptrStackOffset)
	Add.opFromReg(code, types.I64, regScratch, regTextPtr)
	Call.opReg(code, regScratch)
	code.AddIndirectCallSite()
}

func (mach X86) OpInit(code gen.Coder, start *links.L) {
	Add.opImm(code, types.I64, regStackLimit, wordSize) // reserve space for trap handler call
	Add.opImm(code, types.I64, regStackPtr, wordSize)   // overwrite return address
	CallRel.op(code, start.Address)
	code.AddCallSite(start)
}

// OpLoadROIntIndex32ScaleDisp must not allocate registers.
func (mach X86) OpLoadROIntIndex32ScaleDisp(code gen.Coder, t types.T, reg regs.R, regZeroExt bool, scale uint8, addr int) (resultZeroExt bool) {
	if !regZeroExt {
		Mov.opFromReg(code, types.I32, reg, reg)
	}

	Mov.opFromAddr(code, t, reg, scale, reg, code.RODataAddr()+addr)
	resultZeroExt = true
	return
}

// OpMove must not update CPU's condition flags.
//
// X86 implementation note: must not use regScratch or regResult in this
// function, because we may be moving to one of them.
func (mach X86) OpMove(code gen.Coder, t types.T, targetReg regs.R, x values.Operand) (zeroExt bool) {
	switch t.Category() {
	case types.Int:
		switch x.Storage {
		case values.Imm:
			zeroExt = MovImm64.op(code, t, targetReg, x.ImmValue(t))

		case values.VarMem:
			Mov.opFromStack(code, t, targetReg, x.Offset())
			zeroExt = true

		case values.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				Mov.opFromReg(code, t, targetReg, sourceReg)
				zeroExt = true
			}

		case values.TempReg:
			sourceReg := x.Reg()
			if sourceReg == targetReg {
				panic("moving temporary integer register to itself")
			}
			Mov.opFromReg(code, t, targetReg, sourceReg)
			zeroExt = true

		case values.Stack:
			Pop.op(code, targetReg)

		case values.ConditionFlags:
			if t.Size() != types.Size32 {
				panic(t)
			}

			var end links.L

			cond := x.Condition()
			setcc := conditionInsns[cond].setcc

			switch {
			case cond >= values.MinUnorderedOrCondition:
				MovImm.opImm(code, t, targetReg, 1) // true
				Jp.rel8.opStub(code)                // if unordered, else
				end.AddSite(code.Len())             //
				setcc.opReg(code, targetReg)        // cond

				zeroExt = true

			case cond >= values.MinOrderedAndCondition:
				MovImm.opImm(code, t, targetReg, 0) // false
				Jp.rel8.opStub(code)                // if unordered, else
				end.AddSite(code.Len())             //
				setcc.opReg(code, targetReg)        // cond

				zeroExt = true

			default:
				setcc.opReg(code, targetReg)
				Movzx8.opFromReg(code, t, targetReg, targetReg)
			}

			end.SetAddress(code.Len())
			mach.updateSites8(code, &end)

		default:
			panic(x)
		}

	case types.Float:
		switch x.Storage {
		case values.Imm:
			if x.ImmValue(t) != 0 {
				panic(x)
			}
			XorpSSE.opFromReg(code, t, targetReg, targetReg)

		case values.ROData:
			MovsSSE.opFromAddr(code, t, targetReg, 0, NoIndex, code.RODataAddr()+x.Addr())

		case values.VarMem:
			MovsSSE.opFromStack(code, t, targetReg, x.Offset())

		case values.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				MovsSSE.opFromReg(code, t, targetReg, sourceReg)
			}

		case values.TempReg:
			sourceReg := x.Reg()
			if sourceReg == targetReg {
				panic("moving temporary float register to itself")
			}
			MovsSSE.opFromReg(code, t, targetReg, sourceReg)

		case values.Stack:
			popFloatOp(code, t, targetReg)

		default:
			panic(x)
		}

	default:
		panic(t)
	}

	code.Consumed(t, x)

	return
}

// OpMoveReg must not allocate registers.
func (mach X86) OpMoveReg(code gen.Coder, t types.T, targetReg, sourceReg regs.R) {
	if targetReg == sourceReg {
		panic("target and source registers are the same")
	}

	switch t.Category() {
	case types.Int:
		Mov.opFromReg(code, t, targetReg, sourceReg)

	case types.Float:
		MovsSSE.opFromReg(code, t, targetReg, sourceReg)

	default:
		panic(t)
	}
}

// OpPush must not allocate registers nor update CPU's condition flags.
func (mach X86) OpPush(code gen.Coder, t types.T, x values.Operand) {
	if value, ok := x.CheckImmValue(t); ok {
		switch {
		case -0x80 <= value && value < 0x80:
			PushImm8.op(code, imm8(int(value)))
			return

		case -0x80000000 <= value && value < 0x80000000:
			PushImm32.op(code, imm32(int(value)))
			return
		}
	}

	// TODO: more addressing modes

	reg, _, ok := x.CheckTempReg()
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

func (mach X86) OpSelect(code gen.RegCoder, t types.T, a, b, condOperand values.Operand) values.Operand {
	var cond values.Condition

	switch condOperand.Storage {
	case values.VarMem:
		Cmp.opImmToStack(code, types.I32, condOperand.Offset(), 0)
		cond = values.NE

	case values.VarReg, values.TempReg:
		reg := condOperand.Reg()
		Test.opFromReg(code, types.I32, reg, reg)
		cond = values.NE

	case values.Stack:
		mach.OpAddImmToStackPtr(code, 8) // do before cmp to avoid overwriting flags
		Cmp.opImmToStack(code, types.I32, -8, 0)
		cond = values.NE

	case values.ConditionFlags:
		cond = condOperand.Condition()

	default:
		panic(condOperand)
	}

	code.Consumed(types.I32, condOperand)

	targetReg, _ := mach.opResultReg(code, t, b)

	switch t.Category() {
	case types.Int:
		cmov := conditionInsns[cond].cmov

		switch a.Storage {
		case values.ROData:
			cmov.opFromAddr(code, t, targetReg, 0, NoIndex, a.Addr())

		case values.VarMem:
			cmov.opFromStack(code, t, targetReg, a.Offset())

		default:
			aReg, _, own := mach.opBorrowScratchReg(code, t, a)
			if own {
				defer code.FreeReg(t, aReg)
			}

			cmov.opFromReg(code, t, targetReg, aReg)
		}

	case types.Float:
		var moveIt links.L
		var end links.L

		cond = values.InvertedConditions[cond]
		notCondJump := conditionInsns[cond].jcc

		switch {
		case cond >= values.MinUnorderedOrCondition:
			Jp.rel8.opStub(code) // move it if unordered
			moveIt.AddSite(code.Len())

			notCondJump.rel8.opStub(code) // break if not cond
			end.AddSite(code.Len())

		case cond >= values.MinOrderedAndCondition:
			Jp.rel8.opStub(code) // break if unordered
			end.AddSite(code.Len())

			notCondJump.rel8.opStub(code) // break if not cond
			end.AddSite(code.Len())

		default:
			notCondJump.rel8.opStub(code) // break if not cond
			end.AddSite(code.Len())
		}

		moveIt.SetAddress(code.Len())
		mach.updateSites8(code, &moveIt)

		mach.OpMove(code, t, targetReg, a)

		end.SetAddress(code.Len())
		mach.updateSites8(code, &end)

	default:
		panic(t)
	}

	// cmov zero-extends the target unconditionally
	return values.TempRegOperand(targetReg, true)
}

// OpShiftRightLogical32Bits must not allocate registers.
func (mach X86) OpShiftRightLogical32Bits(code gen.Coder, subject regs.R) {
	ShrImm.op(code, types.I64, subject, -32)
}

// OpStoreStack must not allocate registers.
func (mach X86) OpStoreStack(code gen.Coder, t types.T, offset int, x values.Operand) {
	reg, _, ok := x.CheckTempReg()
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
		Mov.opToStack(code, t, reg, offset)

	case types.Float:
		MovsSSE.opToStack(code, t, reg, offset)

	default:
		panic(t)
	}
}

func (mach X86) OpTrapImplementation(code gen.Coder, id traps.Id) {
	Mov.opImm(code, types.I32, regTrapArg, int(id)) // automatic zero-extension
	MovqMMX.opToReg(code, types.I64, regScratch, regTrapFuncMMX)
	Jmp.opReg(code, regScratch)
}

func (mach X86) OpBranch(code gen.Coder, addr int) int {
	JmpRel.op(code, addr)
	return code.Len()
}

func (mach X86) OpBranchIf(code gen.Coder, x values.Operand, yes bool, addr int) (sites []int) {
	cond, ok := x.CheckConditionFlags()
	if !ok {
		reg, _, own := mach.opBorrowScratchReg(code, types.I32, x)
		if own {
			defer code.FreeReg(types.I32, reg)
		}

		Test.opFromReg(code, types.I32, reg, reg)
		cond = values.NE
	}

	if !yes {
		cond = values.InvertedConditions[cond]
	}

	condInsn := conditionInsns[cond].jcc

	switch {
	case cond >= values.MinUnorderedOrCondition:
		Jp.op(code, addr)
		sites = append(sites, code.Len())

		condInsn.op(code, addr)

	case cond >= values.MinOrderedAndCondition:
		first := Jp.rel8         // 8 bits is enough for sure...
		second := condInsn.rel32 // predictable size, simpler code

		first.op(code, code.Len()+first.size()+second.size()) // jump after the second jump
		second.op(code, addr)

	default:
		condInsn.op(code, addr)
	}

	sites = append(sites, code.Len()) // final jump
	return
}

// OpBranchIfEqualImm32 must not allocate registers.
func (mach X86) OpBranchIfEqualImm32(code gen.Coder, reg regs.R, value int, addr int) int {
	Cmp.opImm(code, types.I32, reg, value)
	Je.op(code, addr)
	return code.Len()
}

// OpBranchIfOutOfBounds must not allocate registers.
func (mach X86) OpBranchIfOutOfBounds(code gen.Coder, indexReg regs.R, upperBound int, addr int) int {
	MovImm.opImm(code, types.I32, regScratch, upperBound)
	Test.opFromReg(code, types.I32, indexReg, indexReg)
	Cmovl.opFromReg(code, types.I32, indexReg, regScratch) // negative index -> upper bound
	Cmp.opFromReg(code, types.I32, regScratch, indexReg)
	Jle.op(code, addr)
	return code.Len()
}

func (mach X86) OpFunctionPrologue(code gen.Coder) (entryAddr, stackUsageAddr int) {
	var trap links.L

	trap.SetAddress(code.Len())
	CallRel.op(code, code.TrapLinks().CallStackExhausted.Address)
	code.AddCallSite(&code.TrapLinks().CallStackExhausted)

	if n := functionAlignment - (code.Len() & (functionAlignment - 1)); n < functionAlignment {
		for i := 0; i < n; i++ {
			code.WriteByte(paddingByte)
		}
	}

	entryAddr = code.Len()
	Lea.opFromStack(code, types.I64, regScratch, -0x80000000) // reserve 32-bit displacement
	stackUsageAddr = code.Len()
	Cmp.opFromReg(code, types.I64, regScratch, regStackLimit)
	Jl.op(code, trap.FinalAddress())
	return
}

func (mach X86) OpCall(code gen.Coder, l *links.L) {
	CallRel.op(code, l.Address)
	code.AddCallSite(l)
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

func (mach X86) updateAddr8(code gen.Coder, addr int, value int) {
	if value < -0x80 || 0x80 <= value {
		panic(value)
	}

	code.Bytes()[addr-1] = byte(value)
}

func (mach X86) updateSites(code gen.Coder, l *links.L) {
	targetAddr := l.FinalAddress()
	for _, siteAddr := range l.Sites {
		mach.updateAddr(code, siteAddr, targetAddr-siteAddr)
	}
}

func (mach X86) updateSites8(code gen.Coder, l *links.L) {
	targetAddr := l.FinalAddress()
	for _, siteAddr := range l.Sites {
		mach.updateAddr8(code, siteAddr, targetAddr-siteAddr)
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
func (mach X86) opBorrowScratchReg(code gen.Coder, t types.T, x values.Operand) (reg regs.R, zeroExt, own bool) {
	reg, ok := x.CheckVarReg()
	if ok {
		return
	}

	reg, zeroExt, ok = x.CheckTempReg()
	if ok {
		own = true
		return
	}

	reg = regScratch
	mach.OpMove(code, t, reg, x)
	zeroExt = true
	return
}

// opBorrowResultReg returns either the register of the given operand, or the
// reserved result register with the value of the operand.
func (mach X86) opBorrowResultReg(code gen.RegCoder, t types.T, x values.Operand) (reg regs.R, zeroExt, own bool) {
	reg, ok := x.CheckVarReg()
	if !ok {
		reg, zeroExt = mach.opResultReg(code, t, x)
		own = (reg != regResult)
	}

	return
}

// opResultReg returns either the register of the given operand, or the
// reserved result register with the value of the operand.  The caller has
// exclusive ownership of the register.
func (mach X86) opResultReg(code gen.RegCoder, t types.T, x values.Operand) (reg regs.R, zeroExt bool) {
	reg, zeroExt, ok := x.CheckTempReg()
	if !ok {
		reg, ok = code.TryAllocReg(t)
		if !ok {
			reg = regResult
		}

		if x.Storage != values.Nowhere {
			mach.OpMove(code, t, reg, x)
			zeroExt = true
		}
	}

	return
}

func binaryInsnOp(code gen.Coder, insn binaryInsn, t types.T, target regs.R, source values.Operand) {
	switch source.Storage {
	case values.ROData:
		insn.opFromAddr(code, t, target, 0, NoIndex, code.RODataAddr()+source.Addr())

	case values.VarMem:
		insn.opFromStack(code, t, target, source.Offset())

	case values.Imm:
		insn.opImm(code, t, target, int(source.ImmValue(t)))

	case values.VarReg, values.TempReg, values.BorrowedReg:
		insn.opFromReg(code, t, target, source.Reg())

	default:
		panic(source)
	}

	code.Consumed(t, source)
}

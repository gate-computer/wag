// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
	"github.com/tsavola/wag/types"
)

const (
	// Don't use RegResult for effective addresses etc. to avoid information
	// leaks.  Void functions may leave information in the result register, and
	// call stack could be rewritten during snapshot/restore to cause void
	// function to return to a non-void call site.

	RegResult         = regs.R(0)  // rax or xmm0
	RegShiftCount     = regs.R(1)  // rcx
	RegScratch        = regs.R(2)  // rdx or xmm2
	RegImportArgCount = regs.R(2)  // rdx
	RegImportSigIndex = regs.R(3)  // rbx
	RegStackPtr       = regs.R(4)  // rsp
	RegSuspendFlag    = regs.R(9)  // r9
	RegTextBase       = regs.R(12) // r12
	RegStackLimit     = regs.R(13) // r13
	RegMemoryBase     = regs.R(14) // r14
	RegMemoryLimit    = regs.R(15) // r15

	RegTrapHandlerMMX     = regs.R(0) // mm0
	RegMemoryGrowLimitMMX = regs.R(1) // mm1
	RegScratchMMX         = regs.R(2) // mm2
)

const (
	FunctionAlignment = 16
	PaddingByte       = 0xcc // int3 instruction
)

var paramRegs [2][]regs.R
var availRegs = gen.RegMask(
	gen.RegCategoryMask(gen.RegCategoryInt, &paramRegs[gen.RegCategoryInt],
		false, // rax
		true,  // rcx
		false, // rdx
		true,  // rbx
		false, // rsp
		true,  // rbp
		true,  // rsi
		true,  // rdi
		true,  // r8
		false, // r9
		true,  // r10
		true,  // r11
		false, // r12
		false, // r13
		false, // r14
		false, // r15
	),
	gen.RegCategoryMask(gen.RegCategoryFloat, &paramRegs[gen.RegCategoryFloat],
		false, // xmm0
		true,  // xmm1
		false, // xmm2
		true,  // xmm3
		true,  // xmm4
		true,  // xmm5
		true,  // xmm6
		true,  // xmm7
		true,  // xmm8
		true,  // xmm9
		true,  // xmm10
		true,  // xmm11
		true,  // xmm12
		true,  // xmm13
		true,  // xmm14
		true,  // xmm15
	),
)

var (
	ret = insnConst{0xc3}

	pushImm32 = insnI{0x68}
	pushImm8  = insnI{0x6a}

	callRel = insnAddr32{0xe8}
	jmpRel  = insnAddr{insnAddr8{0xeb}, insnAddr32{0xe9}}
	jb      = insnAddr{insnAddr8{0x72}, insnAddr32{0x0f, 0x82}}
	jae     = insnAddr{insnAddr8{0x73}, insnAddr32{0x0f, 0x83}}
	je      = insnAddr{insnAddr8{0x74}, insnAddr32{0x0f, 0x84}}
	jne     = insnAddr{insnAddr8{0x75}, insnAddr32{0x0f, 0x85}}
	jbe     = insnAddr{insnAddr8{0x76}, insnAddr32{0x0f, 0x86}}
	ja      = insnAddr{insnAddr8{0x77}, insnAddr32{0x0f, 0x87}}
	js      = insnAddr{insnAddr8{0x78}, insnAddr32{0x0f, 0x88}}
	jp      = insnAddr{insnAddr8{0x7a}, insnAddr32{0x0f, 0x8a}}
	jl      = insnAddr{insnAddr8{0x7c}, insnAddr32{0x0f, 0x8c}}
	jge     = insnAddr{insnAddr8{0x7d}, insnAddr32{0x0f, 0x8d}}
	jle     = insnAddr{insnAddr8{0x7e}, insnAddr32{0x0f, 0x8e}}
	jg      = insnAddr{insnAddr8{0x7f}, insnAddr32{0x0f, 0x8f}}

	cdqCqo = insnRex{0x99}

	call  = insnRexOM{[]byte{0xff}, 2}
	jmp   = insnRexOM{[]byte{0xff}, 4}
	setb  = insnRexOM{[]byte{0x0f, 0x92}, 0}
	setae = insnRexOM{[]byte{0x0f, 0x93}, 0}
	sete  = insnRexOM{[]byte{0x0f, 0x94}, 0}
	setne = insnRexOM{[]byte{0x0f, 0x95}, 0}
	setbe = insnRexOM{[]byte{0x0f, 0x96}, 0}
	seta  = insnRexOM{[]byte{0x0f, 0x97}, 0}
	setl  = insnRexOM{[]byte{0x0f, 0x9c}, 0}
	setge = insnRexOM{[]byte{0x0f, 0x9d}, 0}
	setle = insnRexOM{[]byte{0x0f, 0x9e}, 0}
	setg  = insnRexOM{[]byte{0x0f, 0x9f}, 0}

	lea    = insnPrefix{rexSize, []byte{0x8d}, nil}
	movMMX = insnPrefix{rexSize, []byte{0x0f, 0x6e}, []byte{0x0f, 0x7e}}
)

var conditionInsns = []struct {
	jcc   insnAddr
	setcc insnRexOM
	cmov  insnPrefix
}{
	values.Eq:            {je, sete, cmove},
	values.Ne:            {jne, setne, cmovne},
	values.GeS:           {jge, setge, cmovge},
	values.GtS:           {jg, setg, cmovg},
	values.GeU:           {jae, setae, cmovae},
	values.GtU:           {ja, seta, cmova},
	values.LeS:           {jle, setle, cmovle},
	values.LtS:           {jl, setl, cmovl},
	values.LeU:           {jbe, setbe, cmovbe},
	values.LtU:           {jb, setb, cmovb},
	values.OrderedAndEq:  {je, sete, cmove},
	values.OrderedAndNe:  {jne, setne, cmovne},
	values.OrderedAndGe:  {jae, setae, cmovae},
	values.OrderedAndGt:  {ja, seta, cmova},
	values.OrderedAndLe:  {jbe, setbe, cmovbe},
	values.OrderedAndLt:  {jb, setb, cmovb},
	values.UnorderedOrEq: {je, sete, cmove},
	values.UnorderedOrNe: {jne, setne, cmovne},
	values.UnorderedOrGe: {jae, setae, cmovae},
	values.UnorderedOrGt: {ja, seta, cmova},
	values.UnorderedOrLe: {jbe, setbe, cmovbe},
	values.UnorderedOrLt: {jb, setb, cmovb},
}

var nopSequences = [][]byte{
	{0x90},
	{0x66, 0x90},
	{0x0f, 0x1f, 0x00},
	{0x0f, 0x1f, 0x40, 0x00},
	{0x0f, 0x1f, 0x44, 0x00, 0x00},
	{0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},
	{0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},
	{0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
}

type X86 struct{}

func (mach X86) AvailRegs() uint64      { return availRegs }
func (mach X86) ParamRegs() [2][]regs.R { return paramRegs }
func (mach X86) ClearInsnCache()        {}

// OpAddImmToStackPtr must not allocate registers.
func (mach X86) OpAddImmToStackPtr(code gen.Coder, offset int32) {
	if offset != 0 {
		add.opImm(code, types.I64, RegStackPtr, offset)
	}
}

// OpAddToStackPtr must not allocate registers.
func (mach X86) OpAddToStackPtr(code gen.Coder, source regs.R) {
	add.opFromReg(code, types.I64, RegStackPtr, source)
}

func (mach X86) OpEnterFunction(code gen.Coder) {
	var skip links.L

	test.opFromReg(code, types.I64, RegSuspendFlag, RegSuspendFlag)
	je.rel8.opStub(code)
	skip.AddSite(code.Len())

	code.OpTrapCall(traps.Suspended)

	skip.Addr = code.Len()
	mach.updateBranches8(code, &skip)
}

func (mach X86) OpEnterImportFunction(code gen.OpCoder, absAddr uint64, variadic bool, argCount, sigIndex int) {
	if variadic {
		mach.opMoveIntImm(code, RegImportArgCount, int64(argCount))
		mach.opMoveIntImm(code, RegImportSigIndex, int64(sigIndex))
	}
	mach.opMoveIntImm(code, RegResult, int64(absAddr))
	jmp.opReg(code, RegResult)
	// Void import functions must make sure that they don't return any damaging
	// information in result register (including the absolute jump target).
}

// OpBranchIndirect32 must not allocate registers.  The supplied register is
// trashed.
func (mach X86) OpBranchIndirect32(code gen.Coder, reg regs.R, regZeroExt bool) {
	if !regZeroExt {
		mov.opFromReg(code, types.I32, reg, reg)
	}

	add.opFromReg(code, types.I64, reg, RegTextBase)
	jmp.opReg(code, reg)
}

func (mach X86) OpCall(code gen.Coder, addr int32) (retAddr int32) {
	if addr == 0 {
		if Native {
			// address slot must be aligned
			if relPos := (code.Len() + callRel.size()) & 3; relPos > 0 {
				padSize := 4 - relPos
				code.Write(nopSequences[padSize-1])
			}
		}
		callRel.opMissingFunction(code)
	} else {
		callRel.op(code, addr)
	}
	return code.Len()
}

// OpCallIndirect using table index located in result register.
func (mach X86) OpCallIndirect(code gen.Coder, tableLen, sigIndex int32) int32 {
	var outOfBounds links.L
	var checksOut links.L

	mach.opCompareBounds(code, RegResult, tableLen)
	jle.rel8.opStub(code)
	outOfBounds.AddSite(code.Len())

	mov.opFromAddr(code, types.I64, RegResult, 3, RegResult, code.RODataAddr()+gen.ROTableAddr)
	mov.opFromReg(code, types.I32, RegScratch, RegResult) // zero-extended function address
	shrImm.op(code, types.I64, RegResult, 32)             // signature index
	cmp.opImm(code, types.I32, RegResult, sigIndex)
	je.rel8.opStub(code)
	checksOut.AddSite(code.Len())

	code.OpTrapCall(traps.IndirectCallSignature)

	outOfBounds.Addr = code.Len()
	mach.updateBranches8(code, &outOfBounds)

	code.OpTrapCall(traps.IndirectCallIndex)

	checksOut.Addr = code.Len()
	mach.updateBranches8(code, &checksOut)

	add.opFromReg(code, types.I64, RegScratch, RegTextBase)
	call.opReg(code, RegScratch)
	return code.Len()
}

// OpGetGlobal must not update CPU's condition flags.
func (mach X86) OpGetGlobal(code gen.RegCoder, t types.T, offset int32) values.Operand {
	reg, ok := code.TryAllocReg(t)
	if !ok {
		reg = RegResult
	}

	if t.Category() == types.Int {
		mov.opFromIndirect(code, t, reg, 0, NoIndex, RegMemoryBase, offset)
	} else {
		movSSE.opFromIndirect(code, t, reg, 0, NoIndex, RegMemoryBase, offset)
	}

	return values.TempRegOperand(t, reg, true)
}

// OpSetGlobal must not update CPU's condition flags.
func (mach X86) OpSetGlobal(code gen.Coder, offset int32, x values.Operand) {
	var reg regs.R

	if x.Storage.IsReg() {
		reg = x.Reg()
		code.Discard(x)
	} else {
		mach.OpMove(code, RegScratch, x, true)
		reg = RegScratch
	}

	if x.Type.Category() == types.Int {
		mov.opToIndirect(code, x.Type, reg, 0, NoIndex, RegMemoryBase, offset)
	} else {
		movSSE.opToIndirect(code, x.Type, reg, 0, NoIndex, RegMemoryBase, offset)
	}
}

func (mach X86) OpInit(code gen.OpCoder) {
	if code.Len() == 0 || code.Len() > FunctionAlignment {
		panic("inconsistency")
	}
	code.Align(FunctionAlignment, PaddingByte)
	add.opImm(code, types.I64, RegStackLimit, gen.StackReserve)

	var notResume links.L

	test.opFromReg(code, types.I64, RegResult, RegResult)
	je.rel8.opStub(code)
	notResume.AddSite(code.Len())
	ret.op(code) // simulate return from snapshot function call

	notResume.Addr = code.Len()
	mach.updateBranches8(code, &notResume)
}

func (mach X86) OpInitCall(code gen.OpCoder) (retAddr int32) {
	// no alignment since initial calls are always generated before execution
	callRel.opMissingFunction(code)
	return code.Len()
}

// OpLoadROIntIndex32ScaleDisp must not allocate registers.
func (mach X86) OpLoadROIntIndex32ScaleDisp(code gen.Coder, t types.T, reg regs.R, regZeroExt bool, scale uint8, addr int32) (resultZeroExt bool) {
	if !regZeroExt {
		mov.opFromReg(code, types.I32, reg, reg)
	}

	mov.opFromAddr(code, t, reg, scale, reg, code.RODataAddr()+addr)
	resultZeroExt = true
	return
}

// OpMove must not update CPU's condition flags if preserveFlags is set.
//
// X86 implementation note: must not blindly rely on RegScratch or RegResult in
// this function because we may be moving to one of them.
func (mach X86) OpMove(code gen.Coder, targetReg regs.R, x values.Operand, preserveFlags bool) (zeroExt bool) {
	switch x.Type.Category() {
	case types.Int:
		switch x.Storage {
		case values.Imm:
			if value := x.ImmValue(); value == 0 && !preserveFlags {
				xor.opFromReg(code, types.I32, targetReg, targetReg)
			} else {
				movImm64.op(code, x.Type, targetReg, value)
			}
			zeroExt = true

		case values.VarMem:
			mov.opFromStack(code, x.Type, targetReg, x.VarMemOffset())
			zeroExt = true

		case values.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				mov.opFromReg(code, x.Type, targetReg, sourceReg)
				zeroExt = true
			}

		case values.TempReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				mov.opFromReg(code, x.Type, targetReg, sourceReg)
				zeroExt = true
			} else if targetReg == RegResult {
				zeroExt = x.RegZeroExt()
			} else {
				panic("moving temporary integer register to itself")
			}

		case values.Stack:
			pop.op(code, targetReg)

		case values.ConditionFlags:
			if x.Type != types.I32 {
				panic(x)
			}

			var end links.L

			cond := x.Condition()
			setcc := conditionInsns[cond].setcc

			switch {
			case cond >= values.MinUnorderedOrCondition:
				movImm.opImm(code, x.Type, targetReg, 1) // true
				jp.rel8.opStub(code)                     // if unordered, else
				end.AddSite(code.Len())                  //
				setcc.opReg(code, targetReg)             // cond

			case cond >= values.MinOrderedAndCondition:
				movImm.opImm(code, x.Type, targetReg, 0) // false
				jp.rel8.opStub(code)                     // if unordered, else
				end.AddSite(code.Len())                  //
				setcc.opReg(code, targetReg)             // cond

			default:
				setcc.opReg(code, targetReg)
				movzx8.opFromReg(code, x.Type, targetReg, targetReg)
			}

			end.Addr = code.Len()
			mach.updateBranches8(code, &end)

			zeroExt = true

		default:
			panic(x)
		}

	case types.Float:
		switch x.Storage {
		case values.Imm:
			if value := x.ImmValue(); value == 0 {
				pxorSSE.opFromReg(code, x.Type, targetReg, targetReg)
			} else {
				movImm64.op(code, x.Type, RegScratch, value) // integer scratch register
				movSSE.opFromReg(code, x.Type, targetReg, RegScratch)
			}

		case values.VarMem:
			movsSSE.opFromStack(code, x.Type, targetReg, x.VarMemOffset())

		case values.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				movsSSE.opFromReg(code, x.Type, targetReg, sourceReg)
			}

		case values.TempReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				movsSSE.opFromReg(code, x.Type, targetReg, sourceReg)
			} else if targetReg != RegResult {
				panic("moving temporary float register to itself")
			}

		case values.Stack:
			popFloatOp(code, x.Type, targetReg)

		default:
			panic(x)
		}

	default:
		panic(x)
	}

	code.Consumed(x)

	return
}

// OpMoveReg must not allocate registers.
func (mach X86) OpMoveReg(code gen.Coder, t types.T, targetReg, sourceReg regs.R) {
	if targetReg == sourceReg {
		panic("target and source registers are the same")
	}

	switch t.Category() {
	case types.Int:
		mov.opFromReg(code, t, targetReg, sourceReg)

	case types.Float:
		movsSSE.opFromReg(code, t, targetReg, sourceReg)

	default:
		panic(t)
	}
}

// opMoveIntImm may update CPU's condition flags.
func (mach X86) opMoveIntImm(code gen.OpCoder, reg regs.R, value int64) {
	if value == 0 {
		xor.opFromReg(code, types.I32, reg, reg)
	} else {
		movImm64.op(code, types.I64, reg, value)
	}
}

// OpClearIntResultReg may update CPU's condition flags.
func (mach X86) OpClearIntResultReg(code gen.OpCoder) {
	xor.opFromReg(code, types.I32, RegResult, RegResult)
}

// OpPush must not allocate registers, and must not update CPU's condition
// flags unless the operand is the condition flags.
func (mach X86) OpPush(code gen.Coder, x values.Operand) {
	var reg regs.R

	switch {
	case x.Storage.IsReg():
		reg = x.Reg()

	case x.Storage == values.Imm:
		value := x.ImmValue()

		switch {
		case value >= -0x80 && value < 0x80:
			pushImm8.op(code, imm{int8(value)})
			return

		case value >= -0x80000000 && value < 0x80000000:
			pushImm32.op(code, imm{int32(value)})
			return
		}

		fallthrough

	default:
		reg = RegScratch
		mach.OpMove(code, reg, x, true)
	}

	switch x.Type.Category() {
	case types.Int:
		push.op(code, reg)

	case types.Float:
		pushFloatOp(code, x.Type, reg)

	default:
		panic(x)
	}

	if x.Storage == values.TempReg {
		code.FreeReg(x.Type, reg)
	}
}

func (mach X86) OpReturn(code gen.Coder) {
	ret.op(code)
}

func (mach X86) OpSelect(code gen.RegCoder, a, b, condOperand values.Operand) values.Operand {
	defer code.Consumed(condOperand)

	var cond values.Condition

	switch condOperand.Storage {
	case values.VarMem:
		cmp.opImmToStack(code, types.I32, condOperand.VarMemOffset(), 0)
		cond = values.Ne

	case values.VarReg, values.TempReg:
		reg := condOperand.Reg()
		test.opFromReg(code, types.I32, reg, reg)
		cond = values.Ne

	case values.Stack:
		mach.OpAddImmToStackPtr(code, 8) // do before cmp to avoid overwriting flags
		cmp.opImmToStack(code, types.I32, -8, 0)
		cond = values.Ne

	case values.ConditionFlags:
		cond = condOperand.Condition()

	case values.Imm:
		if condOperand.ImmValue() != 0 {
			code.Consumed(b)
			return a
		} else {
			code.Consumed(a)
			return b
		}

	default:
		panic(condOperand)
	}

	t := a.Type
	targetReg, _ := mach.opMaybeResultReg(code, b, true)

	switch t.Category() {
	case types.Int:
		cmov := conditionInsns[cond].cmov

		switch a.Storage {
		case values.VarMem:
			cmov.opFromStack(code, t, targetReg, a.VarMemOffset())

		default:
			aReg, _, own := mach.opBorrowMaybeScratchReg(code, a, true)
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
			jp.rel8.opStub(code) // move it if unordered
			moveIt.AddSite(code.Len())

			notCondJump.rel8.opStub(code) // break if not cond
			end.AddSite(code.Len())

		case cond >= values.MinOrderedAndCondition:
			jp.rel8.opStub(code) // break if unordered
			end.AddSite(code.Len())

			notCondJump.rel8.opStub(code) // break if not cond
			end.AddSite(code.Len())

		default:
			notCondJump.rel8.opStub(code) // break if not cond
			end.AddSite(code.Len())
		}

		moveIt.Addr = code.Len()
		mach.updateBranches8(code, &moveIt)

		mach.OpMove(code, targetReg, a, false)

		end.Addr = code.Len()
		mach.updateBranches8(code, &end)

	default:
		panic(t)
	}

	// cmov zero-extends the target unconditionally
	return values.TempRegOperand(t, targetReg, true)
}

// OpShiftRightLogical32Bits must not allocate registers.
func (mach X86) OpShiftRightLogical32Bits(code gen.Coder, subject regs.R) {
	shrImm.op(code, types.I64, subject, 32)
}

// OpStoreStack must not allocate registers.
func (mach X86) OpStoreStack(code gen.Coder, offset int32, x values.Operand) {
	var reg regs.R

	if x.Storage.IsReg() {
		reg = x.Reg()
	} else {
		reg = RegScratch
		mach.OpMove(code, reg, x, true)
	}

	mach.OpStoreStackReg(code, x.Type, offset, reg)

	if x.Storage == values.TempReg {
		code.FreeReg(x.Type, reg)
	}
}

// OpStoreStackReg must not allocate registers.
func (mach X86) OpStoreStackReg(code gen.OpCoder, t types.T, offset int32, reg regs.R) {
	switch t.Category() {
	case types.Int:
		mov.opToStack(code, t, reg, offset)

	case types.Float:
		movsSSE.opToStack(code, t, reg, offset)

	default:
		panic(t)
	}
}

// OpCopyStack must not allocate registers.
func (mach X86) OpCopyStack(code gen.OpCoder, targetOffset, sourceOffset int32) {
	mov.opFromStack(code, types.I64, RegScratch, sourceOffset)
	mov.opToStack(code, types.I64, RegScratch, targetOffset)
}

// OpSwap must not allocate registers, or update CPU's condition flags.
func (mach X86) OpSwap(code gen.Coder, cat gen.RegCategory, a, b regs.R) {
	if cat == gen.RegCategoryInt {
		xchg.opFromReg(code, types.I64, a, b)
	} else {
		movSSE.opFromReg(code, types.F64, RegScratch, a)
		movSSE.opFromReg(code, types.F64, a, b)
		movSSE.opFromReg(code, types.F64, b, RegScratch)
	}
}

func (mach X86) OpEnterExitTrapHandler(code gen.OpCoder) {
	shlImm.op(code, types.I64, RegResult, 32) // exit code at top, trap id (0) at bottom
	movMMX.opToReg(code, types.I64, RegScratch, RegTrapHandlerMMX)
	jmp.opReg(code, RegScratch)
}

// OpEnterTrapHandler must not generate over 16 bytes of code.
func (mach X86) OpEnterTrapHandler(code gen.OpCoder, id traps.Id) {
	mov.opImm(code, types.I32, RegResult, int32(id)) // automatic zero-extension
	movMMX.opToReg(code, types.I64, RegScratch, RegTrapHandlerMMX)
	jmp.opReg(code, RegScratch)
}

func (mach X86) OpBranch(code gen.Coder, addr int32) int32 {
	jmpRel.op(code, addr)
	return code.Len()
}

func (mach X86) OpBranchIf(code gen.Coder, x values.Operand, yes bool, addr int32) (sites []int32) {
	var cond values.Condition

	if x.Storage == values.ConditionFlags {
		cond = x.Condition()
	} else {
		reg, _, own := mach.opBorrowMaybeScratchReg(code, x, false)
		if own {
			defer code.FreeReg(types.I32, reg)
		}

		test.opFromReg(code, types.I32, reg, reg)
		cond = values.Ne
	}

	if !yes {
		cond = values.InvertedConditions[cond]
	}

	var end links.L

	switch {
	case cond >= values.MinUnorderedOrCondition:
		jp.op(code, addr)
		sites = append(sites, code.Len())

	case cond >= values.MinOrderedAndCondition:
		jp.rel8.opStub(code)
		end.AddSite(code.Len())
	}

	conditionInsns[cond].jcc.op(code, addr)
	sites = append(sites, code.Len())

	end.Addr = code.Len()
	mach.updateBranches8(code, &end)
	return
}

// OpBranchIfOutOfBounds must not allocate registers.  indexReg will be
// zero-extended.
func (mach X86) OpBranchIfOutOfBounds(code gen.Coder, indexReg regs.R, upperBound, addr int32) int32 {
	mach.opCompareBounds(code, indexReg, upperBound)
	jle.op(code, addr) // TODO: is this the correct comparison?
	return code.Len()
}

func (mach X86) opCompareBounds(code gen.Coder, indexReg regs.R, upperBound int32) {
	movImm.opImm(code, types.I32, RegScratch, upperBound)
	test.opFromReg(code, types.I32, indexReg, indexReg)
	cmovl.opFromReg(code, types.I32, indexReg, RegScratch) // negative index -> upper bound
	cmp.opFromReg(code, types.I32, RegScratch, indexReg)
}

func (mach X86) OpTrapIfStackExhausted(code gen.Coder) (stackCheckAddr int32) {
	var checked links.L

	lea.opFromStack(code, types.I64, RegScratch, -0x80000000) // reserve 32-bit displacement
	stackCheckAddr = code.Len()

	cmp.opFromReg(code, types.I64, RegScratch, RegStackLimit)

	jge.rel8.opStub(code)
	checked.AddSite(code.Len())

	code.OpTrapCall(traps.CallStackExhausted)

	checked.Addr = code.Len()
	mach.updateBranches8(code, &checked)
	return
}

// UpdateBranches modifies 32-bit relocations of Jmp and Jcc instructions.
func (mach X86) UpdateBranches(code gen.OpCoder, l *links.L) {
	labelAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		mach.updateAddr32(code, retAddr, labelAddr-retAddr)
	}
}

// updateBranches8 modifies 8-bit relocations of Jmp and Jcc instructions.
func (mach X86) updateBranches8(code gen.OpCoder, l *links.L) {
	labelAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		mach.updateAddr8(code, retAddr, labelAddr-retAddr)
	}
}

// UpdateStackDisp modifies the 32-bit displacement of a Lea instruction.
func (mach X86) UpdateStackCheck(code gen.OpCoder, addr, disp int32) {
	mach.updateAddr32(code, addr, -disp)
}

func (mach X86) updateAddr32(code gen.OpCoder, addr, value int32) {
	binary.LittleEndian.PutUint32(code.Bytes()[addr-4:addr], uint32(value))
}

func (mach X86) updateAddr8(code gen.OpCoder, addr, value int32) {
	if value < -0x80 || value >= 0x80 {
		panic(value)
	}
	code.Bytes()[addr-1] = uint8(value)
}

// UpdateCalls modifies CallRel instructions, possibly while they are being
// executed.
func (mach X86) UpdateCalls(code gen.OpCoder, l *links.L) {
	funcAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		mach.PutUint32(code.Bytes()[retAddr-4:retAddr], uint32(funcAddr-retAddr))
	}
}

// opBorrowMaybeScratchReg returns either the register of the given operand, or
// the reserved scratch register with the value of the operand.
func (mach X86) opBorrowMaybeScratchReg(code gen.Coder, x values.Operand, preserveFlags bool) (reg regs.R, zeroExt, own bool) {
	if x.Storage.IsReg() {
		reg = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		reg = RegScratch
		zeroExt = mach.OpMove(code, reg, x, preserveFlags)
	}
	own = (x.Storage == values.TempReg)
	return
}

func (mach X86) opBorrowMaybeScratchRegOperand(code gen.RegCoder, x values.Operand, preserveFlags bool) values.Operand {
	reg, _, own := mach.opBorrowMaybeScratchReg(code, x, preserveFlags)
	return values.RegOperand(own, x.Type, reg)
}

// opBorrowMaybeResultReg returns either the register of the given operand, or
// the reserved result register with the value of the operand.
func (mach X86) opBorrowMaybeResultReg(code gen.RegCoder, x values.Operand, preserveFlags bool) (reg regs.R, zeroExt, own bool) {
	if x.Storage == values.VarReg {
		reg = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		reg, zeroExt = mach.opMaybeResultReg(code, x, preserveFlags)
		own = (reg != RegResult)
	}
	return
}

// opMaybeResultReg returns either the register of the given operand, or the
// reserved result register with the value of the operand.  The caller has
// exclusive ownership of the register.
func (mach X86) opMaybeResultReg(code gen.RegCoder, x values.Operand, preserveFlags bool) (reg regs.R, zeroExt bool) {
	if x.Storage == values.TempReg {
		reg = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		var ok bool

		reg, ok = code.TryAllocReg(x.Type)
		if !ok {
			reg = RegResult
		}

		if x.Storage != values.Nowhere {
			mach.OpMove(code, reg, x, preserveFlags)
			zeroExt = true
		}
	}
	return
}

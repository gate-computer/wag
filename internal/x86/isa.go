// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"encoding/binary"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/trap"
)

const (
	// Don't use RegResult for effective addresses etc. to avoid information
	// leaks.  Void functions may leave information in the result register, and
	// call stack could be rewritten during snapshot/restore to cause void
	// function to return to a non-void call site.

	RegResult         = regs.Result // rax or xmm0
	RegShiftCount     = regs.R(1)   // rcx
	RegScratch        = regs.R(2)   // rdx or xmm2
	RegImportArgCount = regs.R(2)   // rdx
	RegImportSigIndex = regs.R(3)   // rbx
	RegStackPtr       = regs.R(4)   // rsp
	RegSuspendFlag    = regs.R(9)   // r9
	RegTextBase       = regs.R(12)  // r12
	RegStackLimit     = regs.R(13)  // r13
	RegMemoryBase     = regs.R(14)  // r14
	RegMemoryLimit    = regs.R(15)  // r15

	RegTrapHandlerMMX     = regs.R(0) // mm0
	RegMemoryGrowLimitMMX = regs.R(1) // mm1
	RegScratchMMX         = regs.R(2) // mm2
)

const (
	FuncAlignment = 16
	PaddingByte   = 0xcc // int3 instruction
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

type ISA struct{}

func (ISA) AvailRegs() uint64      { return availRegs }
func (ISA) ParamRegs() [2][]regs.R { return paramRegs }
func (ISA) ClearInsnCache()        {}

// UpdateBranches modifies 32-bit relocations of Jmp and Jcc instructions.
func (ISA) UpdateBranches(text []byte, l *links.L) {
	labelAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		updateTextAddr(text, retAddr, labelAddr-retAddr)
	}
}

// UpdateStackCheck modifies the 32-bit displacement of a Lea instruction.
func (ISA) UpdateStackCheck(text []byte, addr, disp int32) {
	updateTextAddr(text, addr, -disp)
}

func updateTextAddr(text []byte, addr, value int32) {
	binary.LittleEndian.PutUint32(text[addr-4:addr], uint32(value))
}

// UpdateCalls modifies CallRel instructions, possibly while they are being
// executed.
func (ISA) UpdateCalls(text []byte, l *links.L) {
	funcAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		atomicPutUint32(text[retAddr-4:retAddr], uint32(funcAddr-retAddr))
	}
}

func (ISA) AlignFunc(text *gen.Text) {
	alignFunc(text)
}

func alignFunc(text *gen.Text) {
	n := (FuncAlignment - text.Pos()) & (FuncAlignment - 1)
	buf := text.Extend(int(n))
	for i := range buf {
		buf[i] = PaddingByte
	}
}

func (ISA) OpAddImmToStackPtr(text *gen.Text, offset int32) {
	if offset != 0 {
		add.opImm(text, abi.I64, RegStackPtr, offset)
	}
}

func (ISA) OpAddToStackPtr(text *gen.Text, source regs.R) {
	add.opFromReg(text, abi.I64, RegStackPtr, source)
}

// OpMoveIntImm may update CPU's condition flags.
func (ISA) OpMoveIntImm(text *gen.Text, reg regs.R, value uint64) {
	opMoveIntImm(text, reg, int64(value))
}

func opMoveIntImm(text *gen.Text, reg regs.R, value int64) {
	if value == 0 {
		xor.opFromReg(text, abi.I32, reg, reg)
	} else {
		movImm64.op(text, abi.I64, reg, value)
	}
}

func (ISA) OpInit(text *gen.Text) {
	if text.Pos() == 0 || text.Pos() > FuncAlignment {
		panic("inconsistency")
	}
	alignFunc(text)
	add.opImm(text, abi.I64, RegStackLimit, gen.StackReserve)

	var notResume links.L

	test.opFromReg(text, abi.I64, RegResult, RegResult)
	je.rel8.opStub(text)
	notResume.AddSite(text.Pos())
	ret.op(text) // simulate return from snapshot function call

	notResume.Addr = text.Pos()
	updateLocalBranches(text, &notResume)
}

func (ISA) OpInitCall(text *gen.Text) (retAddr int32) {
	// no alignment since initial calls are always generated before execution
	callRel.opMissingFunc(text)
	return text.Pos()
}

func (ISA) OpEnterImportFunc(text *gen.Text, absAddr uint64, variadic bool, argCount, sigIndex int) {
	if variadic {
		opMoveIntImm(text, RegImportArgCount, int64(argCount))
		opMoveIntImm(text, RegImportSigIndex, int64(sigIndex))
	}
	opMoveIntImm(text, RegResult, int64(absAddr))
	jmp.opReg(text, RegResult)
	// Void import functions must make sure that they don't return any damaging
	// information in result register (including the absolute jump target).
}

// OpBranchIndirect32 must not allocate registers.  The supplied register is
// trashed.
func (ISA) OpBranchIndirect32(text *gen.Text, reg regs.R, regZeroExt bool) {
	if !regZeroExt {
		mov.opFromReg(text, abi.I32, reg, reg)
	}

	add.opFromReg(text, abi.I64, reg, RegTextBase)
	jmp.opReg(text, reg)
}

func (ISA) OpCall(text *gen.Text, addr int32) (retAddr int32) {
	if addr == 0 {
		// address slot must be aligned
		if relPos := (text.Pos() + callRel.size()) & 3; relPos > 0 {
			padSize := 4 - relPos
			text.PutBytes(nopSequences[padSize-1])
		}
		callRel.opMissingFunc(text)
	} else {
		callRel.op(text, addr)
	}
	return text.Pos()
}

// OpClearIntResultReg may update CPU's condition flags.
func (ISA) OpClearIntResultReg(text *gen.Text) {
	xor.opFromReg(text, abi.I32, RegResult, RegResult)
}

func (ISA) OpReturn(text *gen.Text) {
	ret.op(text)
}

func (ISA) OpEnterExitTrapHandler(text *gen.Text) {
	shlImm.op(text, abi.I64, RegResult, 32) // exit text at top, trap id (0) at bottom
	movMMX.opToReg(text, abi.I64, RegScratch, RegTrapHandlerMMX)
	jmp.opReg(text, RegScratch)
}

// OpMoveReg must not allocate registers.
func (ISA) OpMoveReg(text *gen.Text, t abi.Type, targetReg, sourceReg regs.R) {
	if targetReg == sourceReg {
		panic("target and source registers are the same")
	}

	switch t.Category() {
	case abi.Int:
		mov.opFromReg(text, t, targetReg, sourceReg)

	case abi.Float:
		movapSSE.opFromReg(text, t, targetReg, sourceReg)

	default:
		panic(t)
	}
}

// OpShiftRightLogical32Bits must not allocate registers.
func (ISA) OpShiftRightLogical32Bits(text *gen.Text, subject regs.R) {
	shrImm.op(text, abi.I64, subject, 32)
}

// OpStoreStackReg must not allocate registers.
func (ISA) OpStoreStackReg(text *gen.Text, t abi.Type, offset int32, reg regs.R) {
	opStoreStackReg(text, t, offset, reg)
}

// opStoreStackReg has same restrictions as OpStoreStackReg.
func opStoreStackReg(text *gen.Text, t abi.Type, offset int32, reg regs.R) {
	switch t.Category() {
	case abi.Int:
		mov.opToStack(text, t, reg, offset)

	case abi.Float:
		movsSSE.opToStack(text, t, reg, offset)

	default:
		panic(t)
	}
}

// OpCopyStack must not allocate registers.
func (ISA) OpCopyStack(text *gen.Text, targetOffset, sourceOffset int32) {
	mov.opFromStack(text, abi.I64, RegScratch, sourceOffset)
	mov.opToStack(text, abi.I64, RegScratch, targetOffset)
}

// OpSwap must not allocate registers, or update CPU's condition flags.
func (ISA) OpSwap(text *gen.Text, cat gen.RegCategory, a, b regs.R) {
	if cat == gen.RegCategoryInt {
		xchg.opFromReg(text, abi.I64, a, b)
	} else {
		movSSE.opFromReg(text, abi.F64, RegScratch, a)
		movSSE.opFromReg(text, abi.F64, a, b)
		movSSE.opFromReg(text, abi.F64, b, RegScratch)
	}
}

// OpEnterTrapHandler must not generate over 16 bytes of text.
func (ISA) OpEnterTrapHandler(text *gen.Text, id trap.Id) {
	mov.opImm(text, abi.I32, RegResult, int32(id)) // automatic zero-extension
	movMMX.opToReg(text, abi.I64, RegScratch, RegTrapHandlerMMX)
	jmp.opReg(text, RegScratch)
}

func (ISA) OpBranch(text *gen.Text, addr int32) int32 {
	jmpRel.op(text, addr)
	return text.Pos()
}

// OpBranchIfOutOfBounds must not allocate registers.  indexReg will be
// zero-extended.
func (ISA) OpBranchIfOutOfBounds(text *gen.Text, indexReg regs.R, upperBound, addr int32) int32 {
	opCompareBounds(text, indexReg, upperBound)
	jle.op(text, addr) // TODO: is this the correct comparison?
	return text.Pos()
}

func opCompareBounds(text *gen.Text, indexReg regs.R, upperBound int32) {
	movImm.opImm(text, abi.I32, RegScratch, upperBound)
	test.opFromReg(text, abi.I32, indexReg, indexReg)
	cmovl.opFromReg(text, abi.I32, indexReg, RegScratch) // negative index -> upper bound
	cmp.opFromReg(text, abi.I32, RegScratch, indexReg)
}

// updateLocalBranches modifies 8-bit relocations of Jmp and Jcc instructions.
func updateLocalBranches(text *gen.Text, l *links.L) {
	labelAddr := l.FinalAddr()
	for _, retAddr := range l.Sites {
		updateLocalAddr(text, retAddr, labelAddr-retAddr)
	}
}

func updateLocalAddr(text *gen.Text, addr, value int32) {
	if value < -0x80 || value >= 0x80 {
		panic(value)
	}
	text.Bytes()[addr-1] = uint8(value)
}

func (ISA) OpEnterFunc(text *gen.Text, code gen.Coder) {
	var skip links.L

	test.opFromReg(text, abi.I64, RegSuspendFlag, RegSuspendFlag)
	je.rel8.opStub(text)
	skip.AddSite(text.Pos())

	code.OpTrapCall(trap.Suspended)

	skip.Addr = text.Pos()
	updateLocalBranches(text, &skip)
}

// OpCallIndirect using table index located in result register.
func (ISA) OpCallIndirect(text *gen.Text, code gen.Coder, tableLen, sigIndex int32) int32 {
	var outOfBounds links.L
	var checksOut links.L

	opCompareBounds(text, RegResult, tableLen)
	jle.rel8.opStub(text)
	outOfBounds.AddSite(text.Pos())

	mov.opFromAddr(text, abi.I64, RegResult, 3, RegResult, code.RODataAddr()+gen.ROTableAddr)
	mov.opFromReg(text, abi.I32, RegScratch, RegResult) // zero-extended function address
	shrImm.op(text, abi.I64, RegResult, 32)             // signature index
	cmp.opImm(text, abi.I32, RegResult, sigIndex)
	je.rel8.opStub(text)
	checksOut.AddSite(text.Pos())

	code.OpTrapCall(trap.IndirectCallSignature)

	outOfBounds.Addr = text.Pos()
	updateLocalBranches(text, &outOfBounds)

	code.OpTrapCall(trap.IndirectCallIndex)

	checksOut.Addr = text.Pos()
	updateLocalBranches(text, &checksOut)

	add.opFromReg(text, abi.I64, RegScratch, RegTextBase)
	call.opReg(text, RegScratch)
	return text.Pos()
}

// OpLoadROIntIndex32ScaleDisp must not allocate registers.
func (ISA) OpLoadROIntIndex32ScaleDisp(text *gen.Text, code gen.Coder, t abi.Type, reg regs.R, regZeroExt bool, scale uint8, addr int32) (resultZeroExt bool) {
	if !regZeroExt {
		mov.opFromReg(text, abi.I32, reg, reg)
	}

	mov.opFromAddr(text, t, reg, scale, reg, code.RODataAddr()+addr)
	resultZeroExt = true
	return
}

// OpSetGlobal must not update CPU's condition flags.
func (ISA) OpSetGlobal(text *gen.Text, code gen.Coder, offset int32, x values.Operand) {
	var reg regs.R

	if x.Storage.IsReg() {
		reg = x.Reg()
		code.Discard(x)
	} else {
		opMove(text, code, RegScratch, x, true)
		reg = RegScratch
	}

	if x.Type.Category() == abi.Int {
		mov.opToIndirect(text, x.Type, reg, 0, NoIndex, RegMemoryBase, offset)
	} else {
		movSSE.opToIndirect(text, x.Type, reg, 0, NoIndex, RegMemoryBase, offset)
	}
}

// OpMove must not update CPU's condition flags if preserveFlags is set.
func (ISA) OpMove(text *gen.Text, code gen.Coder, targetReg regs.R, x values.Operand, preserveFlags bool) (zeroExt bool) {
	return opMove(text, code, targetReg, x, preserveFlags)
}

// opMove has same restrictions as OpMove.  Additional ISA restriction: opMove
// must not blindly rely on RegScratch or RegResult in this function because we
// may be moving to one of them.
func opMove(text *gen.Text, code gen.Coder, targetReg regs.R, x values.Operand, preserveFlags bool) (zeroExt bool) {
	switch x.Type.Category() {
	case abi.Int:
		switch x.Storage {
		case values.Imm:
			if value := x.ImmValue(); value == 0 && !preserveFlags {
				xor.opFromReg(text, abi.I32, targetReg, targetReg)
			} else {
				movImm64.op(text, x.Type, targetReg, value)
			}
			zeroExt = true

		case values.VarMem:
			mov.opFromStack(text, x.Type, targetReg, x.VarMemOffset())
			zeroExt = true

		case values.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				mov.opFromReg(text, x.Type, targetReg, sourceReg)
				zeroExt = true
			}

		case values.TempReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				mov.opFromReg(text, x.Type, targetReg, sourceReg)
				zeroExt = true
			} else if targetReg == RegResult {
				zeroExt = x.RegZeroExt()
			} else {
				panic("moving temporary integer register to itself")
			}

		case values.Stack:
			pop.op(text, targetReg)

		case values.ConditionFlags:
			if x.Type != abi.I32 {
				panic(x)
			}

			var end links.L

			cond := x.Condition()
			setcc := conditionInsns[cond].setcc

			switch {
			case cond >= values.MinUnorderedOrCondition:
				movImm.opImm(text, x.Type, targetReg, 1) // true
				jp.rel8.opStub(text)                     // if unordered, else
				end.AddSite(text.Pos())                  //
				setcc.opReg(text, targetReg)             // cond

			case cond >= values.MinOrderedAndCondition:
				movImm.opImm(text, x.Type, targetReg, 0) // false
				jp.rel8.opStub(text)                     // if unordered, else
				end.AddSite(text.Pos())                  //
				setcc.opReg(text, targetReg)             // cond

			default:
				setcc.opReg(text, targetReg)
				movzx8.opFromReg(text, x.Type, targetReg, targetReg)
			}

			end.Addr = text.Pos()
			updateLocalBranches(text, &end)

			zeroExt = true

		default:
			panic(x)
		}

	case abi.Float:
		switch x.Storage {
		case values.Imm:
			if value := x.ImmValue(); value == 0 {
				pxorSSE.opFromReg(text, x.Type, targetReg, targetReg)
			} else {
				movImm64.op(text, x.Type, RegScratch, value) // integer scratch register
				movSSE.opFromReg(text, x.Type, targetReg, RegScratch)
			}

		case values.VarMem:
			movsSSE.opFromStack(text, x.Type, targetReg, x.VarMemOffset())

		case values.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				movapSSE.opFromReg(text, x.Type, targetReg, sourceReg)
			}

		case values.TempReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				movapSSE.opFromReg(text, x.Type, targetReg, sourceReg)
			} else if targetReg != RegResult {
				panic("moving temporary float register to itself")
			}

		case values.Stack:
			popFloatOp(text, x.Type, targetReg)

		default:
			panic(x)
		}

	default:
		panic(x)
	}

	code.Consumed(x)

	return
}

// OpPush must not allocate registers, and must not update CPU's condition
// flags unless the operand is the condition flags.
func (ISA) OpPush(text *gen.Text, code gen.Coder, x values.Operand) {
	var reg regs.R

	switch {
	case x.Storage.IsReg():
		reg = x.Reg()

	case x.Storage == values.Imm:
		value := x.ImmValue()

		switch {
		case value >= -0x80 && value < 0x80:
			pushImm8.op8(text, int8(value))
			return

		case value >= -0x80000000 && value < 0x80000000:
			pushImm32.op32(text, int32(value))
			return
		}

		fallthrough

	default:
		reg = RegScratch
		opMove(text, code, reg, x, true)
	}

	switch x.Type.Category() {
	case abi.Int:
		push.op(text, reg)

	case abi.Float:
		pushFloatOp(text, x.Type, reg)

	default:
		panic(x)
	}

	if x.Storage == values.TempReg {
		code.FreeReg(x.Type, reg)
	}
}

// OpStoreStack must not allocate registers.
func (ISA) OpStoreStack(text *gen.Text, code gen.Coder, offset int32, x values.Operand) {
	var reg regs.R

	if x.Storage.IsReg() {
		reg = x.Reg()
	} else {
		reg = RegScratch
		opMove(text, code, reg, x, true)
	}

	opStoreStackReg(text, x.Type, offset, reg)

	if x.Storage == values.TempReg {
		code.FreeReg(x.Type, reg)
	}
}

func (ISA) OpBranchIf(text *gen.Text, code gen.Coder, x values.Operand, yes bool, addr int32) (sites []int32) {
	var cond values.Condition

	if x.Storage == values.ConditionFlags {
		cond = x.Condition()
	} else {
		reg, _, own := opBorrowMaybeScratchReg(text, code, x, false)
		if own {
			defer code.FreeReg(abi.I32, reg)
		}

		test.opFromReg(text, abi.I32, reg, reg)
		cond = values.Ne
	}

	if !yes {
		cond = values.InvertedConditions[cond]
	}

	var end links.L

	switch {
	case cond >= values.MinUnorderedOrCondition:
		jp.op(text, addr)
		sites = append(sites, text.Pos())

	case cond >= values.MinOrderedAndCondition:
		jp.rel8.opStub(text)
		end.AddSite(text.Pos())
	}

	conditionInsns[cond].jcc.op(text, addr)
	sites = append(sites, text.Pos())

	end.Addr = text.Pos()
	updateLocalBranches(text, &end)
	return
}

func (ISA) OpTrapIfStackExhausted(text *gen.Text, code gen.Coder) (stackCheckAddr int32) {
	var checked links.L

	lea.opFromStack(text, abi.I64, RegScratch, -0x80000000) // reserve 32-bit displacement
	stackCheckAddr = text.Pos()

	cmp.opFromReg(text, abi.I64, RegScratch, RegStackLimit)

	jge.rel8.opStub(text)
	checked.AddSite(text.Pos())

	code.OpTrapCall(trap.CallStackExhausted)

	checked.Addr = text.Pos()
	updateLocalBranches(text, &checked)
	return
}

// opBorrowMaybeScratchReg returns either the register of the given operand, or
// the reserved scratch register with the value of the operand.
func opBorrowMaybeScratchReg(text *gen.Text, code gen.Coder, x values.Operand, preserveFlags bool) (reg regs.R, zeroExt, own bool) {
	if x.Storage.IsReg() {
		reg = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		reg = RegScratch
		zeroExt = opMove(text, code, reg, x, preserveFlags)
	}
	own = (x.Storage == values.TempReg)
	return
}

func opBorrowMaybeScratchRegOperand(text *gen.Text, code gen.Coder, x values.Operand, preserveFlags bool) values.Operand {
	reg, _, own := opBorrowMaybeScratchReg(text, code, x, preserveFlags)
	return values.RegOperand(own, x.Type, reg)
}

// OpGetGlobal must not update CPU's condition flags.
func (ISA) OpGetGlobal(text *gen.Text, code gen.RegCoder, t abi.Type, offset int32) values.Operand {
	reg, ok := code.TryAllocReg(t)
	if !ok {
		reg = RegResult
	}

	if t.Category() == abi.Int {
		mov.opFromIndirect(text, t, reg, 0, NoIndex, RegMemoryBase, offset)
	} else {
		movSSE.opFromIndirect(text, t, reg, 0, NoIndex, RegMemoryBase, offset)
	}

	return values.TempRegOperand(t, reg, true)
}

func (ISA) OpSelect(text *gen.Text, code gen.RegCoder, a, b, condOperand values.Operand) values.Operand {
	defer code.Consumed(condOperand)

	var cond values.Condition

	switch condOperand.Storage {
	case values.VarMem:
		cmp.opImmToStack(text, abi.I32, condOperand.VarMemOffset(), 0)
		cond = values.Ne

	case values.VarReg, values.TempReg:
		reg := condOperand.Reg()
		test.opFromReg(text, abi.I32, reg, reg)
		cond = values.Ne

	case values.Stack:
		add.opImm(text, abi.I64, RegStackPtr, 8) // do before cmp to avoid overwriting flags
		cmp.opImmToStack(text, abi.I32, -8, 0)
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
	targetReg, _ := opMaybeResultReg(text, code, b, true)

	switch t.Category() {
	case abi.Int:
		cmov := conditionInsns[cond].cmov

		switch a.Storage {
		case values.VarMem:
			cmov.opFromStack(text, t, targetReg, a.VarMemOffset())

		default:
			aReg, _, own := opBorrowMaybeScratchReg(text, code, a, true)
			if own {
				defer code.FreeReg(t, aReg)
			}

			cmov.opFromReg(text, t, targetReg, aReg)
		}

	case abi.Float:
		var moveIt links.L
		var end links.L

		cond = values.InvertedConditions[cond]
		notCondJump := conditionInsns[cond].jcc

		switch {
		case cond >= values.MinUnorderedOrCondition:
			jp.rel8.opStub(text) // move it if unordered
			moveIt.AddSite(text.Pos())

			notCondJump.rel8.opStub(text) // break if not cond
			end.AddSite(text.Pos())

		case cond >= values.MinOrderedAndCondition:
			jp.rel8.opStub(text) // break if unordered
			end.AddSite(text.Pos())

			notCondJump.rel8.opStub(text) // break if not cond
			end.AddSite(text.Pos())

		default:
			notCondJump.rel8.opStub(text) // break if not cond
			end.AddSite(text.Pos())
		}

		moveIt.Addr = text.Pos()
		updateLocalBranches(text, &moveIt)

		opMove(text, code, targetReg, a, false)

		end.Addr = text.Pos()
		updateLocalBranches(text, &end)

	default:
		panic(t)
	}

	// cmov zero-extends the target unconditionally
	return values.TempRegOperand(t, targetReg, true)
}

// opBorrowMaybeResultReg returns either the register of the given operand, or
// the reserved result register with the value of the operand.
func opBorrowMaybeResultReg(text *gen.Text, code gen.RegCoder, x values.Operand, preserveFlags bool) (reg regs.R, zeroExt, own bool) {
	if x.Storage == values.VarReg {
		reg = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		reg, zeroExt = opMaybeResultReg(text, code, x, preserveFlags)
		own = (reg != RegResult)
	}
	return
}

// opMaybeResultReg returns either the register of the given operand, or the
// reserved result register with the value of the operand.  The caller has
// exclusive ownership of the register.
func opMaybeResultReg(text *gen.Text, code gen.RegCoder, x values.Operand, preserveFlags bool) (reg regs.R, zeroExt bool) {
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
			opMove(text, code, reg, x, preserveFlags)
			zeroExt = true
		}
	}
	return
}

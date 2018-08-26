// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/gen/val"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/trap"
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
	val.Eq:            {je, sete, cmove},
	val.Ne:            {jne, setne, cmovne},
	val.GeS:           {jge, setge, cmovge},
	val.GtS:           {jg, setg, cmovg},
	val.GeU:           {jae, setae, cmovae},
	val.GtU:           {ja, seta, cmova},
	val.LeS:           {jle, setle, cmovle},
	val.LtS:           {jl, setl, cmovl},
	val.LeU:           {jbe, setbe, cmovbe},
	val.LtU:           {jb, setb, cmovb},
	val.OrderedAndEq:  {je, sete, cmove},
	val.OrderedAndNe:  {jne, setne, cmovne},
	val.OrderedAndGe:  {jae, setae, cmovae},
	val.OrderedAndGt:  {ja, seta, cmova},
	val.OrderedAndLe:  {jbe, setbe, cmovbe},
	val.OrderedAndLt:  {jb, setb, cmovb},
	val.UnorderedOrEq: {je, sete, cmove},
	val.UnorderedOrNe: {jne, setne, cmovne},
	val.UnorderedOrGe: {jae, setae, cmovae},
	val.UnorderedOrGt: {ja, seta, cmova},
	val.UnorderedOrLe: {jbe, setbe, cmovbe},
	val.UnorderedOrLt: {jb, setb, cmovb},
}

type MacroAssembler struct{}

// AddStackPtrImm must not allocate registers.
func (MacroAssembler) AddStackPtrImm(m *module.M, offset int32) {
	if offset != 0 {
		add.opImm(&m.Text, abi.I64, RegStackPtr, offset)
	}
}

// AddStackPtrUpper32 must not allocate registers.
func (MacroAssembler) AddStackPtrUpper32(m *module.M, r reg.R) {
	mov.opFromReg(&m.Text, abi.I64, RegScratch, r)
	shrImm.op(&m.Text, abi.I64, RegScratch, 32)
	add.opFromReg(&m.Text, abi.I64, RegStackPtr, RegScratch)
}

func (MacroAssembler) Branch(m *module.M, addr int32) int32 {
	jmpRel.op(&m.Text, addr)
	return m.Text.Addr
}

// BranchIndirect must not allocate registers.  The supplied register is
// trashed.
func (MacroAssembler) BranchIndirect(m *module.M, r reg.R, isZeroExt bool) {
	if !isZeroExt {
		mov.opFromReg(&m.Text, abi.I32, r, r)
	}
	add.opFromReg(&m.Text, abi.I64, r, RegTextBase)
	jmp.opReg(&m.Text, r)
}

func (MacroAssembler) BranchIf(f *gen.Func, x val.Operand, yes bool, addr int32) (sites []int32) {
	var cond val.Condition

	if x.Storage == val.ConditionFlags {
		cond = x.Condition()
	} else {
		r, _, own := opBorrowMaybeScratchReg(f, x, false)
		if own {
			defer f.Regs.Free(abi.I32, r)
		}

		test.opFromReg(&f.Text, abi.I32, r, r)
		cond = val.Ne
	}

	if !yes {
		cond = val.InvertedConditions[cond]
	}

	var end link.L

	switch {
	case cond >= val.MinUnorderedOrCondition:
		jp.op(&f.Text, addr)
		sites = append(sites, f.Text.Addr)

	case cond >= val.MinOrderedAndCondition:
		jp.rel8.opStub(&f.Text)
		end.AddSite(f.Text.Addr)
	}

	conditionInsns[cond].jcc.op(&f.Text, addr)
	sites = append(sites, f.Text.Addr)

	end.Addr = f.Text.Addr
	updateLocalBranches(f.M, &end)
	return
}

// BranchIfOutOfBounds must not allocate registers.  indexReg will be
// zero-extended.
func (MacroAssembler) BranchIfOutOfBounds(m *module.M, indexReg reg.R, upperBound, addr int32) int32 {
	opCompareBounds(m, indexReg, upperBound)
	jle.op(&m.Text, addr) // TODO: is this the correct comparison?
	return m.Text.Addr
}

// opCompareBounds zero-extends the indexReg.
func opCompareBounds(m *module.M, indexReg reg.R, upperBound int32) {
	movImm.opImm(&m.Text, abi.I32, RegScratch, upperBound)
	test.opFromReg(&m.Text, abi.I32, indexReg, indexReg)
	cmovl.opFromReg(&m.Text, abi.I32, indexReg, RegScratch) // negative index -> upper bound
	cmp.opFromReg(&m.Text, abi.I32, RegScratch, indexReg)
}

func (MacroAssembler) Call(m *module.M, addr int32) (retAddr int32) {
	callRel.op(&m.Text, addr)
	return m.Text.Addr
}

func (MacroAssembler) CallMissing(m *module.M) (retAddr int32) {
	// Position of the jump target (part of the call instruction) must be
	// aligned in memory.
	if relPos := (m.Text.Addr + callRel.size()) & 3; relPos > 0 {
		padSize := 4 - relPos
		m.Text.PutBytes(nopSequences[padSize-1])
	}
	callRel.opMissingFunc(&m.Text)
	return m.Text.Addr
}

// CallIndirect using table index located in result register.
func (MacroAssembler) CallIndirect(f *gen.Func, tableLen, sigIndex int32) int32 {
	var outOfBounds link.L
	var checksOut link.L

	opCompareBounds(f.M, RegResult, tableLen)
	jle.rel8.opStub(&f.Text)
	outOfBounds.AddSite(f.Text.Addr)

	mov.opFromAddr(&f.Text, abi.I64, RegResult, 3, RegResult, f.RODataAddr+rodata.TableAddr)
	mov.opFromReg(&f.Text, abi.I32, RegScratch, RegResult) // zero-extended function address
	shrImm.op(&f.Text, abi.I64, RegResult, 32)             // signature index
	cmp.opImm(&f.Text, abi.I32, RegResult, sigIndex)
	je.rel8.opStub(&f.Text)
	checksOut.AddSite(f.Text.Addr)

	opTrap(f, trap.IndirectCallSignature)

	outOfBounds.Addr = f.Text.Addr
	updateLocalBranches(f.M, &outOfBounds)

	opTrap(f, trap.IndirectCallIndex)

	checksOut.Addr = f.Text.Addr
	updateLocalBranches(f.M, &checksOut)

	add.opFromReg(&f.Text, abi.I64, RegScratch, RegTextBase)
	call.opReg(&f.Text, RegScratch)
	return f.Text.Addr
}

// ClearIntResultReg may update CPU's condition flags.
func (MacroAssembler) ClearIntResultReg(m *module.M) {
	xor.opFromReg(&m.Text, abi.I32, RegResult, RegResult)
}

// CopyStack must not allocate registers.
func (MacroAssembler) CopyStack(m *module.M, targetOffset, sourceOffset int32) {
	mov.opFromStack(&m.Text, abi.I64, RegScratch, sourceOffset)
	mov.opToStack(&m.Text, abi.I64, RegScratch, targetOffset)
}

func (MacroAssembler) Exit(m *module.M) {
	shlImm.op(&m.Text, abi.I64, RegResult, 32) // exit text at top, trap id (0) at bottom
	movMMX.opToReg(&m.Text, abi.I64, RegScratch, RegTrapHandlerMMX)
	jmp.opReg(&m.Text, RegScratch)
}

// GetGlobal must not update CPU's condition flags.
func (MacroAssembler) GetGlobal(m *module.M, t abi.Type, target reg.R, offset int32) (zeroExt bool) {
	if t.Category() == abi.Int {
		mov.opFromIndirect(&m.Text, t, target, 0, NoIndex, RegMemoryBase, offset)
	} else {
		movSSE.opFromIndirect(&m.Text, t, target, 0, NoIndex, RegMemoryBase, offset)
	}
	return true
}

// SetGlobal must not update CPU's condition flags.
func (MacroAssembler) SetGlobal(f *gen.Func, offset int32, x val.Operand) {
	var r reg.R

	if x.Storage.IsReg() {
		r = x.Reg()
		if x.Storage == val.TempReg {
			f.Regs.Free(x.Type, r)
		}
	} else {
		opMove(f, RegScratch, x, true)
		r = RegScratch
	}

	if x.Type.Category() == abi.Int {
		mov.opToIndirect(&f.Text, x.Type, r, 0, NoIndex, RegMemoryBase, offset)
	} else {
		movSSE.opToIndirect(&f.Text, x.Type, r, 0, NoIndex, RegMemoryBase, offset)
	}
}

func (MacroAssembler) Init(m *module.M) {
	if m.Text.Addr == 0 || m.Text.Addr > FuncAlignment {
		panic("inconsistency")
	}
	alignFunc(m)
	add.opImm(&m.Text, abi.I64, RegStackLimit, obj.StackReserve)

	var notResume link.L

	test.opFromReg(&m.Text, abi.I64, RegResult, RegResult)
	je.rel8.opStub(&m.Text)
	notResume.AddSite(m.Text.Addr)
	ret.op(&m.Text) // simulate return from snapshot function call

	notResume.Addr = m.Text.Addr
	updateLocalBranches(m, &notResume)
}

func (MacroAssembler) JumpToImportFunc(m *module.M, addr uint64, variadic bool, argCount, sigIndex int) {
	if variadic {
		opMoveIntImm(m, RegImportArgCount, int64(argCount))
		opMoveIntImm(m, RegImportSigIndex, int64(sigIndex))
	}
	opMoveIntImm(m, RegResult, int64(addr))
	jmp.opReg(&m.Text, RegResult)
	// Void import functions must make sure that they don't return any damaging
	// information in result register (including the absolute jump target).
}

// JumpToTrapHandler must not generate over 16 bytes of code.
func (MacroAssembler) JumpToTrapHandler(m *module.M, id trap.Id) {
	mov.opImm(&m.Text, abi.I32, RegResult, int32(id)) // automatic zero-extension
	movMMX.opToReg(&m.Text, abi.I64, RegScratch, RegTrapHandlerMMX)
	jmp.opReg(&m.Text, RegScratch)
}

// LoadIntROData must not allocate registers.  The register is both the index
// (source) and the target register.  The index must have been zero-extended.
func (MacroAssembler) LoadIntROData(f *gen.Func, t abi.Type, r reg.R, scale uint8, addr int32) {
	mov.opFromAddr(&f.Text, t, r, scale, r, f.RODataAddr+addr)
}

// Move must not update CPU's condition flags if preserveFlags is set.
func (MacroAssembler) Move(f *gen.Func, target reg.R, x val.Operand, preserveFlags bool) (zeroExt bool) {
	return opMove(f, target, x, preserveFlags)
}

// opMove has same restrictions as OpMove.  Additional ISA restriction: opMove
// must not blindly rely on RegScratch or RegResult in this function because we
// may be moving to one of them.
func opMove(f *gen.Func, targetReg reg.R, x val.Operand, preserveFlags bool) (zeroExt bool) {
	switch x.Type.Category() {
	case abi.Int:
		switch x.Storage {
		case val.Imm:
			if value := x.ImmValue(); value == 0 && !preserveFlags {
				xor.opFromReg(&f.Text, abi.I32, targetReg, targetReg)
			} else {
				movImm64.op(&f.Text, x.Type, targetReg, value)
			}
			zeroExt = true

		case val.VarMem:
			mov.opFromStack(&f.Text, x.Type, targetReg, x.VarMemOffset())
			zeroExt = true

		case val.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				mov.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
				zeroExt = true
			}

		case val.TempReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				mov.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
				zeroExt = true
			} else if targetReg == RegResult {
				zeroExt = x.RegZeroExt()
			} else {
				panic("moving temporary integer register to itself")
			}

		case val.Stack:
			pop.op(&f.Text, targetReg)

		case val.ConditionFlags:
			if x.Type != abi.I32 {
				panic(x)
			}

			var end link.L

			cond := x.Condition()
			setcc := conditionInsns[cond].setcc

			switch {
			case cond >= val.MinUnorderedOrCondition:
				movImm.opImm(&f.Text, x.Type, targetReg, 1) // true
				jp.rel8.opStub(&f.Text)                     // if unordered, else
				end.AddSite(f.Text.Addr)                    //
				setcc.opReg(&f.Text, targetReg)             // cond

			case cond >= val.MinOrderedAndCondition:
				movImm.opImm(&f.Text, x.Type, targetReg, 0) // false
				jp.rel8.opStub(&f.Text)                     // if unordered, else
				end.AddSite(f.Text.Addr)                    //
				setcc.opReg(&f.Text, targetReg)             // cond

			default:
				setcc.opReg(&f.Text, targetReg)
				movzx8.opFromReg(&f.Text, x.Type, targetReg, targetReg)
			}

			end.Addr = f.Text.Addr
			updateLocalBranches(f.M, &end)

			zeroExt = true

		default:
			panic(x)
		}

	case abi.Float:
		switch x.Storage {
		case val.Imm:
			if value := x.ImmValue(); value == 0 {
				pxorSSE.opFromReg(&f.Text, x.Type, targetReg, targetReg)
			} else {
				movImm64.op(&f.Text, x.Type, RegScratch, value) // integer scratch register
				movSSE.opFromReg(&f.Text, x.Type, targetReg, RegScratch)
			}

		case val.VarMem:
			movsSSE.opFromStack(&f.Text, x.Type, targetReg, x.VarMemOffset())

		case val.VarReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				movapSSE.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
			}

		case val.TempReg:
			if sourceReg := x.Reg(); sourceReg != targetReg {
				movapSSE.opFromReg(&f.Text, x.Type, targetReg, sourceReg)
			} else if targetReg != RegResult {
				panic("moving temporary float register to itself")
			}

		case val.Stack:
			popFloatOp(f.M, x.Type, targetReg)

		default:
			panic(x)
		}

	default:
		panic(x)
	}

	f.Consumed(x)

	return
}

// MoveIntImm may update CPU's condition flags.
func (MacroAssembler) MoveIntImm(m *module.M, r reg.R, value uint64) {
	opMoveIntImm(m, r, int64(value))
}

func opMoveIntImm(m *module.M, r reg.R, value int64) {
	if value == 0 {
		xor.opFromReg(&m.Text, abi.I32, r, r)
	} else {
		movImm64.op(&m.Text, abi.I64, r, value)
	}
}

// MoveReg must not allocate registers.
func (MacroAssembler) MoveReg(m *module.M, t abi.Type, targetReg, sourceReg reg.R) {
	if targetReg == sourceReg {
		panic("target and source registers are the same")
	}

	switch t.Category() {
	case abi.Int:
		mov.opFromReg(&m.Text, t, targetReg, sourceReg)

	case abi.Float:
		movapSSE.opFromReg(&m.Text, t, targetReg, sourceReg)

	default:
		panic(t)
	}
}

// MoveI32Reg must not allocate registers or update CPU's condition flags.
// It must zero-extend.
func (MacroAssembler) MoveI32Reg(m *module.M, target, source reg.R) {
	mov.opFromReg(&m.Text, abi.I32, target, source)
}

// Push must not allocate registers, and must not update CPU's condition
// flags unless the operand is the condition flags.
func (MacroAssembler) Push(f *gen.Func, x val.Operand) {
	var r reg.R

	switch {
	case x.Storage.IsReg():
		r = x.Reg()

	case x.Storage == val.Imm:
		value := x.ImmValue()

		switch {
		case value >= -0x80 && value < 0x80:
			pushImm8.op8(&f.Text, int8(value))
			return

		case value >= -0x80000000 && value < 0x80000000:
			pushImm32.op32(&f.Text, int32(value))
			return
		}

		fallthrough

	default:
		r = RegScratch
		opMove(f, r, x, true)
	}

	switch x.Type.Category() {
	case abi.Int:
		push.op(&f.Text, r)

	case abi.Float:
		pushFloatOp(f.M, x.Type, r)

	default:
		panic(x)
	}

	if x.Storage == val.TempReg {
		f.Regs.Free(x.Type, r)
	}
}

func (MacroAssembler) Return(m *module.M) {
	ret.op(&m.Text)
}

func (MacroAssembler) Select(f *gen.Func, a, b, condOperand val.Operand) val.Operand {
	defer f.Consumed(condOperand)

	var cond val.Condition

	switch condOperand.Storage {
	case val.VarMem:
		cmp.opImmToStack(&f.Text, abi.I32, condOperand.VarMemOffset(), 0)
		cond = val.Ne

	case val.VarReg, val.TempReg:
		r := condOperand.Reg()
		test.opFromReg(&f.Text, abi.I32, r, r)
		cond = val.Ne

	case val.Stack:
		add.opImm(&f.Text, abi.I64, RegStackPtr, obj.Word) // do before cmp to avoid overwriting flags
		cmp.opImmToStack(&f.Text, abi.I32, -obj.Word, 0)
		cond = val.Ne

	case val.ConditionFlags:
		cond = condOperand.Condition()

	case val.Imm:
		if condOperand.ImmValue() != 0 {
			f.Consumed(b)
			return a
		} else {
			f.Consumed(a)
			return b
		}

	default:
		panic(condOperand)
	}

	t := a.Type
	targetReg, _ := opMaybeResultReg(f, b, true)

	switch t.Category() {
	case abi.Int:
		cmov := conditionInsns[cond].cmov

		switch a.Storage {
		case val.VarMem:
			cmov.opFromStack(&f.Text, t, targetReg, a.VarMemOffset())

		default:
			aReg, _, own := opBorrowMaybeScratchReg(f, a, true)
			if own {
				defer f.Regs.Free(t, aReg)
			}

			cmov.opFromReg(&f.Text, t, targetReg, aReg)
		}

	case abi.Float:
		var moveIt link.L
		var end link.L

		cond = val.InvertedConditions[cond]
		notCondJump := conditionInsns[cond].jcc

		switch {
		case cond >= val.MinUnorderedOrCondition:
			jp.rel8.opStub(&f.Text) // move it if unordered
			moveIt.AddSite(f.Text.Addr)

			notCondJump.rel8.opStub(&f.Text) // break if not cond
			end.AddSite(f.Text.Addr)

		case cond >= val.MinOrderedAndCondition:
			jp.rel8.opStub(&f.Text) // break if unordered
			end.AddSite(f.Text.Addr)

			notCondJump.rel8.opStub(&f.Text) // break if not cond
			end.AddSite(f.Text.Addr)

		default:
			notCondJump.rel8.opStub(&f.Text) // break if not cond
			end.AddSite(f.Text.Addr)
		}

		moveIt.Addr = f.Text.Addr
		updateLocalBranches(f.M, &moveIt)

		opMove(f, targetReg, a, false)

		end.Addr = f.Text.Addr
		updateLocalBranches(f.M, &end)

	default:
		panic(t)
	}

	// cmov zero-extends the target unconditionally
	return val.TempRegOperand(t, targetReg, true)
}

// StoreStack must not allocate registers.
func (MacroAssembler) StoreStack(f *gen.Func, offset int32, x val.Operand) {
	var r reg.R

	if x.Storage.IsReg() {
		r = x.Reg()
	} else {
		r = RegScratch
		opMove(f, r, x, true)
	}

	opStoreStackReg(f.M, x.Type, offset, r)

	if x.Storage == val.TempReg {
		f.Regs.Free(x.Type, r)
	}
}

// StoreStackReg must not allocate registers.
func (MacroAssembler) StoreStackReg(m *module.M, t abi.Type, offset int32, r reg.R) {
	opStoreStackReg(m, t, offset, r)
}

// opStoreStackReg has same restrictions as OpStoreStackReg.
func opStoreStackReg(m *module.M, t abi.Type, offset int32, r reg.R) {
	switch t.Category() {
	case abi.Int:
		mov.opToStack(&m.Text, t, r, offset)

	case abi.Float:
		movsSSE.opToStack(&m.Text, t, r, offset)

	default:
		panic(t)
	}
}

// Swap must not allocate registers, or update CPU's condition flags.
func (MacroAssembler) Swap(m *module.M, cat abi.Category, a, b reg.R) {
	if cat == abi.Int {
		xchg.opFromReg(&m.Text, abi.I64, a, b)
	} else {
		movSSE.opFromReg(&m.Text, abi.F64, RegScratch, a)
		movSSE.opFromReg(&m.Text, abi.F64, a, b)
		movSSE.opFromReg(&m.Text, abi.F64, b, RegScratch)
	}
}

func (MacroAssembler) Trap(f *gen.Func, id trap.Id) {
	opTrap(f, id)
}

func opTrap(f *gen.Func, id trap.Id) {
	f.InitTrapTrampoline(id)
	callRel.op(&f.Text, f.TrapLinks[id].Addr)
	f.MapCallAddr(f.Text.Addr)
}

func (MacroAssembler) TrapIfStackExhausted(f *gen.Func) (stackCheckAddr int32) {
	var checked link.L

	lea.opFromStack(&f.Text, abi.I64, RegScratch, -0x80000000) // reserve 32-bit displacement
	stackCheckAddr = f.Text.Addr

	cmp.opFromReg(&f.Text, abi.I64, RegScratch, RegStackLimit)

	jge.rel8.opStub(&f.Text)
	checked.AddSite(f.Text.Addr)

	opTrap(f, trap.CallStackExhausted)

	checked.Addr = f.Text.Addr
	updateLocalBranches(f.M, &checked)
	return
}

func (MacroAssembler) TrapIfSuspended(f *gen.Func) {
	var skip link.L

	test.opFromReg(&f.Text, abi.I64, RegSuspendFlag, RegSuspendFlag)
	je.rel8.opStub(&f.Text)
	skip.AddSite(f.Text.Addr)

	opTrap(f, trap.Suspended)

	skip.Addr = f.Text.Addr
	updateLocalBranches(f.M, &skip)
}

// opBorrowMaybeScratchReg returns either the register of the given operand, or
// the reserved scratch register with the value of the operand.
func opBorrowMaybeScratchReg(f *gen.Func, x val.Operand, preserveFlags bool) (r reg.R, zeroExt, own bool) {
	if x.Storage.IsReg() {
		r = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		r = RegScratch
		zeroExt = opMove(f, r, x, preserveFlags)
	}
	own = (x.Storage == val.TempReg)
	return
}

func opBorrowMaybeScratchRegOperand(f *gen.Func, x val.Operand, preserveFlags bool) val.Operand {
	r, _, own := opBorrowMaybeScratchReg(f, x, preserveFlags)
	return val.RegOperand(own, x.Type, r)
}

// opBorrowMaybeResultReg returns either the register of the given operand, or
// the reserved result register with the value of the operand.
func opBorrowMaybeResultReg(f *gen.Func, x val.Operand, preserveFlags bool) (r reg.R, zeroExt, own bool) {
	if x.Storage == val.VarReg {
		r = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		r, zeroExt = opMaybeResultReg(f, x, preserveFlags)
		own = (r != RegResult)
	}
	return
}

// opMaybeResultReg returns either the register of the given operand, or the
// reserved result register with the value of the operand.  The caller has
// exclusive ownership of the register.
func opMaybeResultReg(f *gen.Func, x val.Operand, preserveFlags bool) (r reg.R, zeroExt bool) {
	if x.Storage == val.TempReg {
		r = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		var ok bool

		r, ok = f.Regs.Alloc(x.Type)
		if !ok {
			r = RegResult
		}

		if x.Storage != val.Nowhere {
			opMove(f, r, x, preserveFlags)
			zeroExt = true
		}
	}
	return
}

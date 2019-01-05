// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/pkg/errors"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/gen/storage"
	abi "github.com/tsavola/wag/internal/isa/x86/abi"
	"github.com/tsavola/wag/internal/isa/x86/in"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

const (
	FuncAlignment = 16

	NopByte = 0x90
	PadByte = 0xcc // INT3 instruction
)

var conditionInsns = [22]in.CCInsn{
	condition.Eq:            in.InsnEq,
	condition.Ne:            in.InsnNe,
	condition.GeS:           in.InsnGeS,
	condition.GtS:           in.InsnGtS,
	condition.GeU:           in.InsnGeU,
	condition.GtU:           in.InsnGtU,
	condition.LeS:           in.InsnLeS,
	condition.LtS:           in.InsnLtS,
	condition.LeU:           in.InsnLeU,
	condition.LtU:           in.InsnLtU,
	condition.OrderedAndEq:  in.InsnEq,
	condition.OrderedAndNe:  in.InsnNe,
	condition.OrderedAndGe:  in.InsnGeU,
	condition.OrderedAndGt:  in.InsnGtU,
	condition.OrderedAndLe:  in.InsnLeU,
	condition.OrderedAndLt:  in.InsnLtU,
	condition.UnorderedOrEq: in.InsnEq,
	condition.UnorderedOrNe: in.InsnNe,
	condition.UnorderedOrGe: in.InsnGeU,
	condition.UnorderedOrGt: in.InsnGtU,
	condition.UnorderedOrLe: in.InsnLeU,
	condition.UnorderedOrLt: in.InsnLtU,
}

var asm MacroAssembler

type MacroAssembler struct{}

func (MacroAssembler) AlignData(p *gen.Prog, alignment int) {
	pad(p, PadByte, (alignment-int(p.Text.Addr))&(alignment-1))
}

func (MacroAssembler) AlignFunc(p *gen.Prog) {
	pad(p, PadByte, (FuncAlignment-int(p.Text.Addr))&(FuncAlignment-1))
}

func (MacroAssembler) PadUntil(p *gen.Prog, addr int32) {
	pad(p, PadByte, int(addr)-int(p.Text.Addr))
}

func pad(p *gen.Prog, filler byte, length int) {
	gap := p.Text.Extend(length)
	for i := range gap {
		gap[i] = filler
	}
}

func (MacroAssembler) AddToStackPtrUpper32(f *gen.Func, r reg.R) {
	in.SARi.RegImm8(&f.Text, wa.I64, r, 32) // sign-extension
	in.ADD.RegReg(&f.Text, wa.I64, RegStackPtr, r)
	f.Regs.Free(wa.I64, r)
}

func (MacroAssembler) DropStackValues(p *gen.Prog, n int) {
	in.LEA.RegStackDisp(&p.Text, wa.I64, RegStackPtr, int32(n*obj.Word))
}

func dropStableValue(f *gen.Func, x operand.O) {
	switch x.Storage {
	case storage.Stack:
		in.LEA.RegStackDisp8(&f.Text, wa.I64, RegStackPtr, obj.Word)
		f.StackValueConsumed()

	case storage.Reg:
		f.Regs.Free(x.Type, x.Reg())
	}
}

func (MacroAssembler) Branch(p *gen.Prog, addr int32) {
	in.JMPcd.Addr32(&p.Text, addr)
}

func (MacroAssembler) BranchStub(p *gen.Prog) int32 {
	in.JMPcd.Stub32(&p.Text)
	return p.Text.Addr
}

func (MacroAssembler) BranchIndirect(f *gen.Func, addr reg.R) {
	in.MOV.RegReg(&f.Text, wa.I32, RegScratch, addr)
	f.Regs.Free(wa.I64, addr)
	in.ADD.RegReg(&f.Text, wa.I64, RegScratch, RegTextBase)
	in.JMPcd.Addr32(&f.Text, abi.TextAddrRetpoline)
}

func (MacroAssembler) BranchIf(f *gen.Func, x operand.O, labelAddr int32) (sites []int32) {
	// TODO: optimize
	sites = asm.BranchIfStub(f, x, true, false)
	if labelAddr != 0 {
		linker.UpdateFarBranches(f.Text.Bytes(), &link.L{Sites: sites, Addr: labelAddr})
	}
	return
}

func (MacroAssembler) BranchIfStub(f *gen.Func, x operand.O, yes, near bool) (sites []int32) {
	var cond condition.C

	if x.Storage == storage.Flags {
		cond = x.FlagsCond()
	} else {
		r, _ := getScratchReg(f, x)
		in.TEST.RegReg(&f.Text, wa.I32, r, r)
		cond = condition.Ne
		f.Regs.Free(wa.I32, r)
	}

	if !yes {
		cond = condition.Inverted[cond]
	}

	var endJumps []int32

	switch {
	case cond >= condition.MinUnorderedOrCondition:
		in.JPc.Stub(&f.Text, near)
		sites = append(sites, f.Text.Addr)

	case cond >= condition.MinOrderedAndCondition:
		in.JPcb.Stub8(&f.Text)
		endJumps = append(endJumps, f.Text.Addr)
	}

	conditionInsns[cond].JccOpcodeC().Stub(&f.Text, near)
	sites = append(sites, f.Text.Addr)

	linker.UpdateNearBranches(f.Text.Bytes(), endJumps)
	return
}

func (MacroAssembler) BranchIfOutOfBounds(p *gen.Prog, indexReg reg.R, upperBound, addr int32) {
	compareBounds(p, indexReg, upperBound)
	in.JLEc.Addr(&p.Text, addr)
}

func (MacroAssembler) BranchIfOutOfBoundsStub(p *gen.Prog, indexReg reg.R, upperBound int32) int32 {
	compareBounds(p, indexReg, upperBound)
	in.JLEc.AddrStub(&p.Text)
	return p.Text.Addr
}

// compareBounds zero-extends indexReg.
func compareBounds(p *gen.Prog, indexReg reg.R, upperBound int32) {
	in.MOVi.RegImm32(&p.Text, wa.I32, RegScratch, upperBound)
	in.TEST.RegReg(&p.Text, wa.I32, indexReg, indexReg)
	in.CMOVL.RegReg(&p.Text, wa.I32, indexReg, RegScratch) // negative index -> upper bound
	in.CMP.RegReg(&p.Text, wa.I32, RegScratch, indexReg)
}

func (MacroAssembler) Call(p *gen.Prog, addr int32) (retAddr int32) {
	in.CALLcd.Addr32(&p.Text, addr)
	return p.Text.Addr
}

func (MacroAssembler) CallMissing(p *gen.Prog) (retAddr int32) {
	in.CALLcd.MissingFunction(&p.Text)
	return p.Text.Addr
}

func (MacroAssembler) CallIndirect(f *gen.Func, sigIndex int32, funcIndexReg reg.R) int32 {
	compareBounds(&f.Prog, funcIndexReg, int32(len(f.Module.TableFuncs))) // zero-extension
	in.JLEcb.Stub8(&f.Text)
	outOfBoundsJump := f.Text.Addr

	in.MOV.RegMemIndexDisp(&f.Text, wa.I64, RegResult, in.BaseText, funcIndexReg, in.Scale3, rodata.TableAddr)
	f.Regs.Free(wa.I64, funcIndexReg)
	in.MOV.RegReg(&f.Text, wa.I32, RegScratch, RegResult) // zero-extended function address
	in.SHRi.RegImm8(&f.Text, wa.I64, RegResult, 32)       // signature index
	in.CMPi.RegImm(&f.Text, wa.I32, RegResult, sigIndex)
	in.JEcb.Stub8(&f.Text)
	okJump := f.Text.Addr

	asm.Trap(f, trap.IndirectCallSignatureMismatch)

	linker.UpdateNearBranch(f.Text.Bytes(), outOfBoundsJump)

	asm.Trap(f, trap.IndirectCallIndexOutOfBounds)

	linker.UpdateNearBranch(f.Text.Bytes(), okJump)

	in.ADD.RegReg(&f.Text, wa.I64, RegScratch, RegTextBase)
	in.CALLcd.Addr32(&f.Text, abi.TextAddrRetpoline)
	return f.Text.Addr
}

func (MacroAssembler) ClearIntResultReg(p *gen.Prog) {
	in.XOR.RegReg(&p.Text, wa.I32, RegResult, RegResult)
}

func (MacroAssembler) LoadGlobal(p *gen.Prog, t wa.Type, target reg.R, offset int32) (zeroExtended bool) {
	if t.Category() == wa.Int {
		in.MOV.RegMemDisp(&p.Text, t, target, in.BaseMemory, offset)
	} else {
		in.MOVDQ.RegMemDisp(&p.Text, t, target, in.BaseMemory, offset)
	}
	return true
}

func (MacroAssembler) StoreGlobal(f *gen.Func, offset int32, x operand.O) {
	var r reg.R

	if x.Storage == storage.Reg {
		r = x.Reg()
		f.Regs.Free(x.Type, r)
	} else {
		r = RegScratch
		asm.Move(f, r, x)
	}

	if x.Type.Category() == wa.Int {
		in.MOVmr.RegMemDisp(&f.Text, x.Type, r, in.BaseMemory, offset)
	} else {
		in.MOVDQmr.RegMemDisp(&f.Text, x.Type, r, in.BaseMemory, offset)
	}
}

func (MacroAssembler) Resume(p *gen.Prog) {
	in.XOR.RegReg(&p.Text, wa.I32, RegZero, RegZero)
	in.RET.Simple(&p.Text) // return from trap handler or import function call
}

func (MacroAssembler) Init(p *gen.Prog) {
	reinit(p)
}

func (MacroAssembler) InitCallEntry(p *gen.Prog) (retAddr int32) {
	pad(p, NopByte, (FuncAlignment-int(p.Text.Addr))&(FuncAlignment-1))

	// Entry routine

	reinit(p)

	in.XOR.RegReg(&p.Text, wa.I32, RegResult, RegResult) // result if no entry func

	in.POP.Reg(&p.Text, in.OneSize, RegScratch) // entry func text addr
	in.TEST.RegReg(&p.Text, wa.I32, RegScratch, RegScratch)
	in.JEcb.Stub8(&p.Text)
	nullJump := p.Text.Addr

	in.ADD.RegReg(&p.Text, wa.I64, RegScratch, RegTextBase)
	in.CALLcd.Addr32(&p.Text, abi.TextAddrRetpoline)
	retAddr = p.Text.Addr

	linker.UpdateNearBranch(p.Text.Bytes(), nullJump)

	// Exit

	in.SHLi.RegImm8(&p.Text, wa.I64, RegResult, 32) // exit text at top, trap id (0) at bottom
	in.MOV.RegMemDisp(&p.Text, wa.I64, RegScratch, in.BaseText, gen.VectorOffsetTrapHandler)
	in.JMPcd.Addr32(&p.Text, abi.TextAddrRetpoline)

	// Retpoline (https://support.google.com/faqs/answer/7625886)

	asm.AlignFunc(p)
	if p.Text.Addr != abi.TextAddrRetpoline {
		panic("x86: hardcoded retpoline address needs to be adjusted")
	}

	in.CALLcd.Addr32(&p.Text, abi.TextAddrRetpolineSetup)

	captureSpecAddr := p.Text.Addr
	in.PAUSE.Simple(&p.Text)
	in.JMPcb.Addr8(&p.Text, captureSpecAddr)

	asm.AlignFunc(p)
	if p.Text.Addr != abi.TextAddrRetpolineSetup {
		panic("x86: hardcoded retpoline setup address needs to be adjusted")
	}

	asm.StoreStackReg(p, wa.I64, 0, RegScratch)
	in.XOR.RegReg(&p.Text, wa.I32, RegScratch, RegScratch)
	in.RET.Simple(&p.Text)

	return
}

func reinit(p *gen.Prog) {
	in.XOR.RegReg(&p.Text, wa.I32, RegZero, RegZero)
}

func (MacroAssembler) JumpToImportFunc(p *gen.Prog, vecIndex int, variadic bool, argCount, sigIndex int) {
	if variadic {
		in.MOV64i.RegImm64(&p.Text, RegImportVariadic, (int64(argCount)<<32)|int64(sigIndex))
	}
	in.MOV.RegMemIndexDisp(&p.Text, wa.I64, RegScratch, in.BaseText, RegZero, in.Scale0, int32(vecIndex*8))
	in.JMPcd.Addr32(&p.Text, abi.TextAddrRetpoline)
}

func (MacroAssembler) JumpToTrapHandler(p *gen.Prog, id trap.ID) {
	in.MOVi.RegImm32(&p.Text, wa.I32, RegResult, int32(id)) // automatic zero-extension
	in.MOV.RegMemDisp(&p.Text, wa.I64, RegScratch, in.BaseText, gen.VectorOffsetTrapHandler)
	in.JMPcd.Addr32(&p.Text, abi.TextAddrRetpoline)
}

func (MacroAssembler) LoadIntStubNear(f *gen.Func, indexType wa.Type, r reg.R) (insnAddr int32) {
	// 32-bit displacement as placeholder
	in.MOV.RegMemIndexDisp(&f.Text, indexType, r, in.BaseText, r, in.TypeScale(indexType), 0x7fffffff)
	return f.Text.Addr
}

func (MacroAssembler) Move(f *gen.Func, target reg.R, x operand.O) (zeroExtended bool) {
	switch x.Type.Category() {
	case wa.Int:
		switch x.Storage {
		case storage.Stack:
			in.POP.Reg(&f.Text, in.OneSize, target)
			f.StackValueConsumed()

		case storage.Imm:
			switch value := x.ImmValue(); {
			case value == 0:
				in.MOV.RegReg(&f.Text, wa.I32, target, RegZero)
			case uint64(value+0x80000000) <= 0xffffffff:
				in.MOVi.RegImm32(&f.Text, x.Type, target, int32(value))
			default:
				in.MOV64i.RegImm64(&f.Text, target, value)
			}
			zeroExtended = true

		case storage.Reg:
			if source := x.Reg(); source != target {
				in.MOV.RegReg(&f.Text, x.Type, target, source)
				f.Regs.Free(x.Type, source)
				zeroExtended = true
			} else {
				if target != RegResult {
					panic(errors.New("x86: register moved to itself"))
				}
			}

		case storage.Flags:
			setBool(&f.Prog, x.FlagsCond())
			if target != RegScratch {
				in.MOV.RegReg(&f.Text, wa.I32, target, RegScratch)
			}
			zeroExtended = true
		}

	case wa.Float:
		switch x.Storage {
		case storage.Stack:
			in.MOVDQ.RegStack(&f.Text, x.Type, target)
			in.ADDi.RegImm8(&f.Text, wa.I64, RegStackPtr, obj.Word)
			f.StackValueConsumed()

		case storage.Imm:
			if value := x.ImmValue(); value == 0 {
				in.PXOR.RegReg(&f.Text, in.OneSize, target, target)
			} else {
				in.MOV64i.RegImm64(&f.Text, RegScratch, value) // integer scratch register
				in.MOVDQ.RegReg(&f.Text, x.Type, target, RegScratch)
			}

		case storage.Reg:
			if source := x.Reg(); source != target {
				in.MOVAPSD.RegReg(&f.Text, x.Type, target, source)
				f.Regs.Free(x.Type, source)
			} else {
				if target != RegResult {
					panic(errors.New("x86: register moved to itself"))
				}
			}
		}
	}

	return
}

func (MacroAssembler) MoveReg(p *gen.Prog, t wa.Type, target, source reg.R) {
	switch t.Category() {
	case wa.Int:
		in.MOV.RegReg(&p.Text, t, target, source)

	case wa.Float:
		in.MOVAPSD.RegReg(&p.Text, t, target, source)
	}
}

func (MacroAssembler) PushImm(p *gen.Prog, value int64) {
	switch {
	case value == 0:
		in.PUSHo.RegZero(&p.Text)

	case uint64(value+0x80000000) <= 0xffffffff:
		in.PUSHi.Imm(&p.Text, int32(value))

	default:
		in.MOV64i.RegImm64(&p.Text, RegScratch, value)
		in.PUSHo.RegScratch(&p.Text)
	}
}

func (MacroAssembler) PushReg(p *gen.Prog, t wa.Type, r reg.R) {
	switch t.Category() {
	case wa.Int:
		in.PUSH.Reg(&p.Text, in.OneSize, r)

	case wa.Float:
		in.SUBi.RegImm8(&p.Text, wa.I64, RegStackPtr, obj.Word)
		in.MOVDQmr.RegStack(&p.Text, t, r)
	}
}

func (MacroAssembler) PushCond(p *gen.Prog, cond condition.C) {
	setBool(p, cond)
	in.PUSHo.RegScratch(&p.Text)
}

func (MacroAssembler) PushZeros(p *gen.Prog, n int) {
	if n <= 9 {
		for i := 0; i < n; i++ {
			in.PUSHo.RegZero(&p.Text)
		}
	} else {
		in.MOVi.RegImm32(&p.Text, wa.I32, RegCount, int32(n)) // 6 bytes
		loopAddr := p.Text.Addr
		in.PUSHo.RegZero(&p.Text)          // 1 byte
		in.LOOPcb.Addr8(&p.Text, loopAddr) // 2 bytes
	}
}

func (MacroAssembler) Return(p *gen.Prog, numStackValues int) {
	if numStackValues != 0 {
		asm.DropStackValues(p, numStackValues)
	}
	in.RET.Simple(&p.Text)
}

func (MacroAssembler) SetupStackFrame(f *gen.Func) (stackCheckAddr int32) {
	in.LEA.RegStackStub32(&f.Text, wa.I64, RegScratch)
	stackCheckAddr = f.Text.Addr

	in.CMP.RegReg(&f.Text, wa.I64, RegScratch, RegStackLimit)
	in.JGEcb.Rel8(&f.Text, in.CALLcd.Size())                             // Skip next instruction.
	in.CALLcd.Addr32(&f.Text, f.TrapLinks[trap.CallStackExhausted].Addr) // Handler checks suspension.
	f.MapCallAddr(f.Text.Addr)
	return
}

func (MacroAssembler) SetBool(p *gen.Prog, target reg.R, cond condition.C) {
	setBool(p, cond)
	in.MOV.RegReg(&p.Text, wa.I32, target, RegScratch)
}

// setBool sets the scratch register.  (SETcc instruction's register encoding
// is tricky.)
func setBool(p *gen.Prog, cond condition.C) {
	var endJumps []int32

	switch {
	case cond >= condition.MinUnorderedOrCondition:
		in.MOVi.RegImm32(&p.Text, wa.I32, RegScratch, 1) // true
		in.JPcb.Stub8(&p.Text)                           // if unordered, else
		endJumps = append(endJumps, p.Text.Addr)

	case cond >= condition.MinOrderedAndCondition:
		in.MOV.RegReg(&p.Text, wa.I32, RegScratch, RegZero) // false
		in.JPcb.Stub8(&p.Text)                              // if unordered, else
		endJumps = append(endJumps, p.Text.Addr)

	default:
		in.MOV.RegReg(&p.Text, wa.I32, RegScratch, RegZero)
	}

	conditionInsns[cond].SetccOpcode().OneSizeReg(&p.Text, RegScratch)

	linker.UpdateNearBranches(p.Text.Bytes(), endJumps)
}

func (MacroAssembler) LoadStack(p *gen.Prog, t wa.Type, target reg.R, offset int32) {
	switch t.Category() {
	case wa.Int:
		in.MOV.RegStackDisp(&p.Text, t, target, offset)

	case wa.Float:
		in.MOVDQ.RegStackDisp(&p.Text, t, target, offset)
	}
}

func (MacroAssembler) StoreStack(f *gen.Func, offset int32, x operand.O) {
	r, _ := getScratchReg(f, x)
	asm.StoreStackReg(&f.Prog, x.Type, offset, r)
	f.Regs.Free(x.Type, r)
}

func (MacroAssembler) StoreStackImm(p *gen.Prog, t wa.Type, offset int32, value int64) {
	switch {
	case value == 0:
		in.MOVmr.RegStackDisp(&p.Text, wa.I64, RegZero, offset)

	case t.Size() == 4:
		in.MOVi.StackDispImm32(&p.Text, wa.I32, offset, int32(value))

	default:
		in.MOV64i.RegImm64(&p.Text, RegScratch, value)
		in.MOVmr.RegStackDisp(&p.Text, wa.I64, RegScratch, offset)
	}
}

func (MacroAssembler) StoreStackReg(p *gen.Prog, t wa.Type, offset int32, r reg.R) {
	switch t.Category() {
	case wa.Int:
		in.MOVmr.RegStackDisp(&p.Text, t, r, offset)

	case wa.Float:
		in.MOVDQmr.RegStackDisp(&p.Text, t, r, offset)
	}
}

func (MacroAssembler) Trap(f *gen.Func, id trap.ID) {
	in.CALLcd.Addr32(&f.Text, f.TrapLinks[id].Addr)
	f.MapCallAddr(f.Text.Addr)
}

func (MacroAssembler) TrapIfLoopSuspended(f *gen.Func) {
	in.TEST8i.OneSizeRegImm(&f.Text, RegSuspendBit, 1)
	in.JEcb.Rel8(&f.Text, in.CALLcd.Size()) // Skip next instruction if bit is zero (no trap).
	in.CALLcd.Addr32(&f.Text, f.TrapLinks[trap.Suspended].Addr)
	f.MapCallAddr(f.Text.Addr)
}

func (MacroAssembler) TrapIfLoopSuspendedSaveInt(f *gen.Func, saveReg reg.R) {
	in.TEST8i.OneSizeRegImm(&f.Text, RegSuspendBit, 1)
	in.JEcb.Stub8(&f.Text) // Skip if bit is zero (no trap).
	skipJump := f.Text.Addr

	in.PUSH.Reg(&f.Text, in.OneSize, saveReg)
	in.CALLcd.Addr32(&f.Text, f.TrapLinks[trap.Suspended].Addr)
	f.MapCallAddr(f.Text.Addr)
	in.POP.Reg(&f.Text, in.OneSize, saveReg)

	linker.UpdateNearBranch(f.Text.Bytes(), skipJump)
}

func (MacroAssembler) TrapIfLoopSuspendedElse(f *gen.Func, elseAddr int32) {
	in.TEST8i.OneSizeRegImm(&f.Text, RegSuspendBit, 1)
	in.JEcd.Addr32(&f.Text, elseAddr) // Branch to else if bit is zero (no trap).

	asm.Trap(f, trap.Suspended)
}

func (MacroAssembler) ZeroExtendResultReg(p *gen.Prog) {
	in.MOV.RegReg(&p.Text, wa.I32, RegResult, RegResult)
}

// getScratchReg returns either the operand's existing register, or the
// operand's value in RegScratch.
func getScratchReg(f *gen.Func, x operand.O) (r reg.R, zeroExtended bool) {
	if x.Storage == storage.Reg {
		r = x.Reg()
	} else {
		r = RegScratch
		zeroExtended = asm.Move(f, r, x)
	}
	return
}

// allocResultReg may allocate registers.  It returns either the operand's
// existing register, or the operand's value in allocated register or
// RegResult.
func allocResultReg(f *gen.Func, x operand.O) (r reg.R, zeroExtended bool) {
	if x.Storage == storage.Reg {
		r = x.Reg()
	} else {
		r = f.Regs.AllocResult(x.Type)
		zeroExtended = asm.Move(f, r, x)
	}
	return
}

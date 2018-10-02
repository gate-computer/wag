// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/x86/in"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

const (
	NopByte = 0x90
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

// MacroAssembler methods by default MUST NOT update condition flags, use
// RegResult or allocate registers.
//
// Methods which return an operand (and can are allowed to do things) may
// return either an allocated register or RegResult.
//
// Some methods which can use RegResult or update condition flags may need to
// still handle them as input operands.
type MacroAssembler struct{}

var asm MacroAssembler

// AddToStackPtrUpper32 may update condition flags.  It takes ownership of the
// register.
func (MacroAssembler) AddToStackPtrUpper32(f *gen.Func, r reg.R) {
	in.SARi.RegImm8(&f.Text, wa.I64, r, 32) // sign-extension
	in.ADD.RegReg(&f.Text, wa.I64, RegStackPtr, r)
	f.Regs.Free(wa.I64, r)
}

// DropStackValues has default restrictions.  The caller will take care of
// updating the virtual stack pointer.
func (MacroAssembler) DropStackValues(p *gen.Prog, n int) {
	if n != 0 {
		in.LEA.RegStackDisp(&p.Text, wa.I64, RegStackPtr, int32(n*obj.Word))
	}
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

// Branch may use RegResult and update condition flags.
func (MacroAssembler) Branch(p *gen.Prog, addr int32) int32 {
	if addr != 0 {
		in.JMPcd.Addr32(&p.Text, addr)
	} else {
		in.JMPcd.Stub32(&p.Text)
	}
	return p.Text.Addr
}

// BranchIndirect may use RegResult and update condition flags.  It takes
// ownership of address register, which has already been zero-extended.
func (MacroAssembler) BranchIndirect(f *gen.Func, addr reg.R) {
	in.ADD.RegReg(&f.Text, wa.I64, addr, RegTextBase)
	in.JMP.Reg(&f.Text, in.OneSize, addr)
	f.Regs.Free(wa.I64, addr)
}

// BranchIfStub may use RegResult and update condition flags.
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

	var end link.L

	switch {
	case cond >= condition.MinUnorderedOrCondition:
		in.JPc.Stub(&f.Text, near)
		sites = append(sites, f.Text.Addr)

	case cond >= condition.MinOrderedAndCondition:
		in.JPcb.Stub8(&f.Text)
		end.AddSite(f.Text.Addr)
	}

	conditionInsns[cond].JccOpcodeC().Stub(&f.Text, near)
	sites = append(sites, f.Text.Addr)

	end.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &end)
	return
}

// BranchIfOutOfBounds may use RegResult and update condition flags.  It MUST
// zero-extend the index register.
func (MacroAssembler) BranchIfOutOfBounds(p *gen.Prog, indexReg reg.R, upperBound, addr int32) int32 {
	compareBounds(p, indexReg, upperBound)
	in.JLEc.Addr(&p.Text, addr)
	return p.Text.Addr
}

// compareBounds zero-extends indexReg.
func compareBounds(p *gen.Prog, indexReg reg.R, upperBound int32) {
	in.MOVi.RegImm32(&p.Text, wa.I32, RegScratch, upperBound)
	in.TEST.RegReg(&p.Text, wa.I32, indexReg, indexReg)
	in.CMOVL.RegReg(&p.Text, wa.I32, indexReg, RegScratch) // negative index -> upper bound
	in.CMP.RegReg(&p.Text, wa.I32, RegScratch, indexReg)
}

// Call may use RegResult and update condition flags.
func (MacroAssembler) Call(p *gen.Prog, addr int32) (retAddr int32) {
	in.CALLcd.Addr32(&p.Text, addr)
	return p.Text.Addr
}

// CallMissing may use RegResult and update condition flags.
func (MacroAssembler) CallMissing(p *gen.Prog) (retAddr int32) {
	in.CALLcd.MissingFunction(&p.Text)
	return p.Text.Addr
}

// CallIndirect may use RegResult and update condition flags.  It takes
// ownership of funcIndexReg.
func (MacroAssembler) CallIndirect(f *gen.Func, sigIndex int32, funcIndexReg reg.R) int32 {
	var outOfBounds link.L
	var checksOut link.L

	compareBounds(&f.Prog, funcIndexReg, int32(len(f.Module.TableFuncs))) // zero-extension
	in.JLEcb.Stub8(&f.Text)
	outOfBounds.AddSite(f.Text.Addr)

	in.MOV.RegMemIndexDisp(&f.Text, wa.I64, RegResult, in.BaseText, funcIndexReg, in.Scale3, rodata.TableAddr)
	f.Regs.Free(wa.I64, funcIndexReg)
	in.MOV.RegReg(&f.Text, wa.I32, RegScratch, RegResult) // zero-extended function address
	in.SHRi.RegImm8(&f.Text, wa.I64, RegResult, 32)       // signature index
	in.CMPi.RegImm(&f.Text, wa.I32, RegResult, sigIndex)
	in.JEcb.Stub8(&f.Text)
	checksOut.AddSite(f.Text.Addr)

	asm.Trap(f, trap.IndirectCallSignature)

	outOfBounds.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &outOfBounds)

	asm.Trap(f, trap.IndirectCallIndex)

	checksOut.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &checksOut)

	in.ADD.RegReg(&f.Text, wa.I64, RegScratch, RegTextBase)
	in.CALL.Reg(&f.Text, in.OneSize, RegScratch)
	return f.Text.Addr
}

// ClearIntResultReg may use RegResult and update condition flags.
func (MacroAssembler) ClearIntResultReg(p *gen.Prog) {
	in.MOV.RegReg(&p.Text, wa.I32, RegResult, RegZero)
}

// Exit may use RegResult and update condition flags.
func (MacroAssembler) Exit(p *gen.Prog) {
	in.SHLi.RegImm8(&p.Text, wa.I64, RegResult, 32) // exit text at top, trap id (0) at bottom
	in.MOV.RegMemIndexDisp(&p.Text, wa.I64, RegScratch, in.BaseText, RegZero, in.Scale0, -obj.Word)
	in.JMP.Reg(&p.Text, in.OneSize, RegScratch)
}

// LoadGlobal has default restrictions.
func (MacroAssembler) LoadGlobal(p *gen.Prog, t wa.Type, target reg.R, offset int32) (zeroExt bool) {
	if t.Category() == wa.Int {
		in.MOV.RegMemDisp(&p.Text, t, target, in.BaseMemory, offset)
	} else {
		in.MOVDQ.RegMemDisp(&p.Text, t, target, in.BaseMemory, offset)
	}
	return true
}

// StoreGlobal has default restrictions.
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

// Resume may update condition flags.  It MUST NOT generate over 16 bytes of
// code.
func (MacroAssembler) Resume(p *gen.Prog) {
	isa.AlignFunc(p)
	in.XOR.RegReg(&p.Text, wa.I32, RegZero, RegZero)
	in.RET.Simple(&p.Text) // return from trap handler or import function call
}

// Init may use RegResult and update condition flags.
func (MacroAssembler) Init(p *gen.Prog) {
	isa.AlignFunc(p)
	reinit(p)
}

// InitCallEntry may use RegResult and update condition flags.
func (MacroAssembler) InitCallEntry(p *gen.Prog) (retAddr int32) {
	pad(p, NopByte, (FuncAlignment-int(p.Text.Addr))&(FuncAlignment-1))
	reinit(p)

	var null link.L

	in.MOV.RegReg(&p.Text, wa.I32, RegResult, RegZero) // result if no entry func

	in.POP.Reg(&p.Text, in.OneSize, RegScratch) // entry func text addr
	in.TEST.RegReg(&p.Text, wa.I32, RegScratch, RegScratch)
	in.JEcb.Stub8(&p.Text)
	null.AddSite(p.Text.Addr)

	in.ADD.RegReg(&p.Text, wa.I64, RegScratch, RegTextBase)
	in.CALL.Reg(&p.Text, in.OneSize, RegScratch)
	retAddr = p.Text.Addr

	null.Addr = p.Text.Addr
	isa.UpdateNearBranches(p.Text.Bytes(), &null)
	return
}

func reinit(p *gen.Prog) {
	in.XOR.RegReg(&p.Text, wa.I32, RegZero, RegZero)
}

// JumpToImportFunc may use RegResult and update condition flags.
//
// Void functions must make sure that they don't return any sensitive
// information in RAX.
func (MacroAssembler) JumpToImportFunc(p *gen.Prog, vecIndex int, variadic bool, argCount, sigIndex int) {
	if variadic {
		in.MOV64i.RegImm64(&p.Text, RegImportVariadic, (int64(argCount)<<32)|int64(sigIndex))
	}
	in.MOV.RegMemIndexDisp(&p.Text, wa.I64, RegScratch, in.BaseText, RegZero, in.Scale0, int32(vecIndex*8))
	in.JMP.Reg(&p.Text, in.OneSize, RegScratch)
}

// JumpToTrapHandler may use RegResult and update condition flags.  It MUST NOT
// generate over 16 bytes of code.
func (MacroAssembler) JumpToTrapHandler(p *gen.Prog, id trap.Id) {
	in.MOVi.RegImm32(&p.Text, wa.I32, RegResult, int32(id)) // automatic zero-extension
	in.MOV.RegMemIndexDisp(&p.Text, wa.I64, RegScratch, in.BaseText, RegZero, in.Scale0, -obj.Word)
	in.JMP.Reg(&p.Text, in.OneSize, RegScratch)
}

// LoadIntStubNear may update condition flags.  The register passed as argument
// is both the index (source) and the target register.  The index has been
// zero-extended.
func (MacroAssembler) LoadIntStubNear(f *gen.Func, indexType wa.Type, r reg.R) (insnAddr int32) {
	// 32-bit displacement as placeholder
	in.MOV.RegMemIndexDisp(&f.Text, indexType, r, in.BaseText, r, in.TypeScale(indexType), 0x7fffffff)
	return f.Text.Addr
}

// Move MUST NOT update condition flags unless the operand is the condition
// flags.  The source operand is consumed.
func (MacroAssembler) Move(f *gen.Func, target reg.R, x operand.O) (zeroExt bool) {
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
			zeroExt = true

		case storage.Reg:
			if source := x.Reg(); source != target {
				in.MOV.RegReg(&f.Text, x.Type, target, source)
				f.Regs.Free(x.Type, source)
				zeroExt = true
			} else {
				if target != RegResult {
					panic("register moved to itself")
				}
				zeroExt = x.RegZeroExt()
			}

		case storage.Flags:
			setBool(&f.Prog, x.FlagsCond())
			if target != RegScratch {
				in.MOV.RegReg(&f.Text, wa.I32, target, RegScratch)
			}
			zeroExt = true
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
					panic("register moved to itself")
				}
			}
		}
	}

	return
}

// MoveReg has default restrictions.  It MUST zero-extend the (integer) target
// register.
func (MacroAssembler) MoveReg(p *gen.Prog, t wa.Type, target, source reg.R) {
	switch t.Category() {
	case wa.Int:
		in.MOV.RegReg(&p.Text, t, target, source)

	case wa.Float:
		in.MOVAPSD.RegReg(&p.Text, t, target, source)
	}
}

// PushImm has default restrictions.
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

// PushReg has default restrictions.
func (MacroAssembler) PushReg(p *gen.Prog, t wa.Type, r reg.R) {
	switch t.Category() {
	case wa.Int:
		in.PUSH.Reg(&p.Text, in.OneSize, r)

	case wa.Float:
		in.SUBi.RegImm8(&p.Text, wa.I64, RegStackPtr, obj.Word)
		in.MOVDQmr.RegStack(&p.Text, t, r)
	}
}

// PushCond has default restrictions.
func (MacroAssembler) PushCond(p *gen.Prog, cond condition.C) {
	setBool(p, cond)
	in.PUSHo.RegScratch(&p.Text)
}

// PushZeros may use RegResult and update condition flags.
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

// Return may use RegResult and update condition flags.
func (MacroAssembler) Return(p *gen.Prog, numStackValues int) {
	asm.DropStackValues(p, numStackValues)
	in.RET.Simple(&p.Text)
}

// SetupStackFrame may use RegResult and update condition flags.
func (MacroAssembler) SetupStackFrame(f *gen.Func) (stackCheckAddr int32) {
	var checked link.L

	in.LEA.RegStackStub32(&f.Text, wa.I64, RegScratch)
	stackCheckAddr = f.Text.Addr

	in.CMP.RegReg(&f.Text, wa.I64, RegScratch, RegStackLimit)

	in.JGEcb.Stub8(&f.Text)
	checked.AddSite(f.Text.Addr)

	asm.Trap(f, trap.CallStackExhausted) // handler checks if it was actually suspension

	checked.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &checked)
	return
}

// SetBool has default restrictions.  It MUST zero-extend the target register.
func (MacroAssembler) SetBool(p *gen.Prog, target reg.R, cond condition.C) {
	setBool(p, cond)
	in.MOV.RegReg(&p.Text, wa.I32, target, RegScratch)
}

// setBool sets the scratch register.  (SETcc's register encoding is tricky.)
func setBool(p *gen.Prog, cond condition.C) {
	var end link.L

	switch {
	case cond >= condition.MinUnorderedOrCondition:
		in.MOVi.RegImm32(&p.Text, wa.I32, RegScratch, 1) // true
		in.JPcb.Stub8(&p.Text)                           // if unordered, else
		end.AddSite(p.Text.Addr)

	case cond >= condition.MinOrderedAndCondition:
		in.MOV.RegReg(&p.Text, wa.I32, RegScratch, RegZero) // false
		in.JPcb.Stub8(&p.Text)                              // if unordered, else
		end.AddSite(p.Text.Addr)

	default:
		in.MOV.RegReg(&p.Text, wa.I32, RegScratch, RegZero)
	}

	conditionInsns[cond].SetccOpcode().OneSizeReg(&p.Text, RegScratch)

	end.Addr = p.Text.Addr
	isa.UpdateNearBranches(p.Text.Bytes(), &end)
}

// LoadStack has default restrictions.  It MUST zero-extend the (integer)
// target register.
func (MacroAssembler) LoadStack(p *gen.Prog, t wa.Type, target reg.R, offset int32) {
	switch t.Category() {
	case wa.Int:
		in.MOV.RegStackDisp(&p.Text, t, target, offset)

	case wa.Float:
		in.MOVDQ.RegStackDisp(&p.Text, t, target, offset)
	}
}

// StoreStack has default restrictions.  The source operand is consumed.
func (MacroAssembler) StoreStack(f *gen.Func, offset int32, x operand.O) {
	r, _ := getScratchReg(f, x)
	asm.StoreStackReg(&f.Prog, x.Type, offset, r)
	f.Regs.Free(x.Type, r)
}

// StoreStackImm has default restrictions.
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

// StoreStackReg has default restrictions.
func (MacroAssembler) StoreStackReg(p *gen.Prog, t wa.Type, offset int32, r reg.R) {
	switch t.Category() {
	case wa.Int:
		in.MOVmr.RegStackDisp(&p.Text, t, r, offset)

	case wa.Float:
		in.MOVDQmr.RegStackDisp(&p.Text, t, r, offset)
	}
}

// Trap may use RegResult and update condition flags.
func (MacroAssembler) Trap(f *gen.Func, id trap.Id) {
	in.CALLcd.Addr32(&f.Text, f.TrapLinks[id].Addr)
	f.MapCallAddr(f.Text.Addr)
}

// TrapIfLoopSuspended may use RegResult and update condition flags.
func (MacroAssembler) TrapIfLoopSuspended(f *gen.Func) {
	var skip link.L

	in.TEST8i.OneSizeRegImm(&f.Text, RegSuspendBit, 1)
	in.JEcb.Stub8(&f.Text) // 0 -> skip, 1 -> trap
	skip.AddSite(f.Text.Addr)

	asm.Trap(f, trap.Suspended)

	skip.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &skip)
}

// TrapIfLoopSuspendedSaveInt may update condition flags.
func (MacroAssembler) TrapIfLoopSuspendedSaveInt(f *gen.Func, saveReg reg.R) {
	var skip link.L

	in.TEST8i.OneSizeRegImm(&f.Text, RegSuspendBit, 1)
	in.JEcb.Stub8(&f.Text) // 0 -> skip, 1 -> trap
	skip.AddSite(f.Text.Addr)

	in.PUSH.Reg(&f.Text, in.OneSize, saveReg)
	asm.Trap(f, trap.Suspended)
	in.POP.Reg(&f.Text, in.OneSize, saveReg)

	skip.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &skip)
}

// TrapIfLoopSuspendedElse may use RegResult and update condition flags.
func (MacroAssembler) TrapIfLoopSuspendedElse(f *gen.Func, elseAddr int32) {
	in.TEST8i.OneSizeRegImm(&f.Text, RegSuspendBit, 1)
	in.JEcd.Addr32(&f.Text, elseAddr) // 0 -> else, 1 -> trap

	asm.Trap(f, trap.Suspended)
}

// ZeroExtendResultReg may use RegResult and update condition flags.
func (MacroAssembler) ZeroExtendResultReg(p *gen.Prog) {
	in.MOV.RegReg(&p.Text, wa.I32, RegResult, RegResult)
}

// getScratchReg returns either the operand's existing register, or the
// operand's value in RegScratch.
func getScratchReg(f *gen.Func, x operand.O) (r reg.R, zeroExt bool) {
	if x.Storage == storage.Reg {
		r = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		r = RegScratch
		zeroExt = asm.Move(f, r, x)
	}
	return
}

// allocResultReg may allocate registers.  It returns either the operand's
// existing register, or the operand's value in allocated register or
// RegResult.
func allocResultReg(f *gen.Func, x operand.O) (r reg.R, zeroExt bool) {
	if x.Storage == storage.Reg {
		r = x.Reg()
		zeroExt = x.RegZeroExt()
	} else {
		r = f.Regs.AllocResult(x.Type)
		zeroExt = asm.Move(f, r, x)
	}
	return
}

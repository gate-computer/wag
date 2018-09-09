// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/x86/in"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/trap"
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
	in.SARi.RegImm8(&f.Text, abi.I64, r, 32) // sign-extension
	in.ADD.RegReg(&f.Text, abi.I64, RegStackPtr, r)
	f.Regs.Free(abi.I64, r)
}

// DropStackValues has default restrictions.  The caller will take care of
// updating the virtual stack pointer.
func (MacroAssembler) DropStackValues(m *module.M, n int) {
	if n != 0 {
		in.LEA.RegStackDisp(&m.Text, abi.I64, RegStackPtr, int32(n*obj.Word))
	}
}

func dropStableValue(f *gen.Func, x operand.O) {
	switch x.Storage {
	case storage.Stack:
		in.LEA.RegStackDisp8(&f.Text, abi.I64, RegStackPtr, obj.Word)
		f.StackValueConsumed()

	case storage.Reg:
		f.Regs.Free(x.Type, x.Reg())
	}
}

// Branch may use RegResult and update condition flags.
func (MacroAssembler) Branch(m *module.M, addr int32) int32 {
	if addr != 0 {
		in.JMPcd.Addr32(&m.Text, addr)
	} else {
		in.JMPcd.Stub32(&m.Text)
	}
	return m.Text.Addr
}

// BranchIndirect may use RegResult and update condition flags.  It takes
// ownership of address register, which has already been zero-extended.
func (MacroAssembler) BranchIndirect(f *gen.Func, addr reg.R) {
	in.ADD.RegReg(&f.Text, abi.I64, addr, RegTextBase)
	in.JMP.Reg(&f.Text, in.OneSize, addr)
	f.Regs.Free(abi.I64, addr)
}

// BranchIfStub may use RegResult and update condition flags.
func (MacroAssembler) BranchIfStub(f *gen.Func, x operand.O, yes, near bool) (sites []int32) {
	var cond condition.C

	if x.Storage == storage.Flags {
		cond = x.FlagsCond()
	} else {
		r, _ := getScratchReg(f, x)
		in.TEST.RegReg(&f.Text, abi.I32, r, r)
		cond = condition.Ne
		f.Regs.Free(abi.I32, r)
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
func (MacroAssembler) BranchIfOutOfBounds(m *module.M, indexReg reg.R, upperBound, addr int32) int32 {
	compareBounds(m, indexReg, upperBound)
	in.JLEc.Addr(&m.Text, addr)
	return m.Text.Addr
}

// compareBounds zero-extends indexReg.
func compareBounds(m *module.M, indexReg reg.R, upperBound int32) {
	in.MOVi.RegImm32(&m.Text, abi.I32, RegScratch, upperBound)
	in.TEST.RegReg(&m.Text, abi.I32, indexReg, indexReg)
	in.CMOVL.RegReg(&m.Text, abi.I32, indexReg, RegScratch) // negative index -> upper bound
	in.CMP.RegReg(&m.Text, abi.I32, RegScratch, indexReg)
}

// Call may use RegResult and update condition flags.
func (MacroAssembler) Call(m *module.M, addr int32) (retAddr int32) {
	in.CALLcd.Addr32(&m.Text, addr)
	return m.Text.Addr
}

// CallMissing may use RegResult and update condition flags.
func (MacroAssembler) CallMissing(m *module.M) (retAddr int32) {
	in.CALLcd.MissingFunction(&m.Text)
	return m.Text.Addr
}

// CallIndirect may use RegResult and update condition flags.  It takes
// ownership of funcIndexReg.
func (MacroAssembler) CallIndirect(f *gen.Func, sigIndex int32, funcIndexReg reg.R) int32 {
	var outOfBounds link.L
	var checksOut link.L

	compareBounds(f.M, funcIndexReg, int32(len(f.TableFuncs))) // zero-extension
	in.JLEcb.Stub8(&f.Text)
	outOfBounds.AddSite(f.Text.Addr)

	in.MOV.RegMemIndexDisp(&f.Text, abi.I64, RegResult, in.BaseZero, funcIndexReg, in.Scale3, f.RODataAddr+rodata.TableAddr)
	f.Regs.Free(abi.I64, funcIndexReg)
	in.MOV.RegReg(&f.Text, abi.I32, RegScratch, RegResult) // zero-extended function address
	in.SHRi.RegImm8(&f.Text, abi.I64, RegResult, 32)       // signature index
	in.CMPi.RegImm(&f.Text, abi.I32, RegResult, sigIndex)
	in.JEcb.Stub8(&f.Text)
	checksOut.AddSite(f.Text.Addr)

	asm.Trap(f, trap.IndirectCallSignature)

	outOfBounds.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &outOfBounds)

	asm.Trap(f, trap.IndirectCallIndex)

	checksOut.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &checksOut)

	in.ADD.RegReg(&f.Text, abi.I64, RegScratch, RegTextBase)
	in.CALL.Reg(&f.Text, in.OneSize, RegScratch)
	return f.Text.Addr
}

// ClearIntResultReg may use RegResult and update condition flags.
func (MacroAssembler) ClearIntResultReg(m *module.M) {
	in.MOV.RegReg(&m.Text, abi.I32, RegResult, RegZero)
}

// Exit may use RegResult and update condition flags.
func (MacroAssembler) Exit(m *module.M) {
	in.SHLi.RegImm8(&m.Text, abi.I64, RegResult, 32) // exit text at top, trap id (0) at bottom
	in.MOVDQmrMMX.RegReg(&m.Text, abi.I64, RegTrapHandlerMMX, RegScratch)
	in.JMP.Reg(&m.Text, in.OneSize, RegScratch)
}

// LoadGlobal has default restrictions.
func (MacroAssembler) LoadGlobal(m *module.M, t abi.Type, target reg.R, offset int32) (zeroExt bool) {
	if t.Category() == abi.Int {
		in.MOV.RegMemDisp(&m.Text, t, target, in.BaseMemory, offset)
	} else {
		in.MOVDQ.RegMemDisp(&m.Text, t, target, in.BaseMemory, offset)
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

	if x.Type.Category() == abi.Int {
		in.MOVmr.RegMemDisp(&f.Text, x.Type, r, in.BaseMemory, offset)
	} else {
		in.MOVDQmr.RegMemDisp(&f.Text, x.Type, r, in.BaseMemory, offset)
	}
}

// Init may use RegResult and update condition flags.
func (MacroAssembler) Init(m *module.M) {
	if m.Text.Addr == 0 || m.Text.Addr > FuncAlignment {
		panic("inconsistency")
	}
	alignFunc(m)
	in.XOR.RegReg(&m.Text, abi.I64, RegZero, RegZero)
	in.ADDi.RegImm8(&m.Text, abi.I64, RegStackLimit, obj.Word*2) // call + stack check trap

	var notResume link.L

	in.TEST.RegReg(&m.Text, abi.I64, RegResult, RegResult)
	in.JEcb.Stub8(&m.Text)
	notResume.AddSite(m.Text.Addr)
	in.RET.Simple(&m.Text) // simulate return from snapshot function call

	notResume.Addr = m.Text.Addr
	isa.UpdateNearBranches(m.Text.Bytes(), &notResume)
}

// JumpToImportFunc may use RegResult and update condition flags.
//
// Import function implementations must make sure that RDX is zero when they
// return.  Void functions must also make sure that they don't return any
// sensitive information in RAX.
func (MacroAssembler) JumpToImportFunc(m *module.M, addr uint64, variadic bool, argCount, sigIndex int) {
	if variadic {
		in.MOV64i.RegImm64(&m.Text, RegImportVariadic, (int64(argCount)<<32)|int64(sigIndex))
	}
	in.MOV64i.RegImm64(&m.Text, RegScratch, int64(addr))
	in.JMP.Reg(&m.Text, in.OneSize, RegScratch)
}

// JumpToTrapHandler may use RegResult and update condition flags.  It MUST NOT
// generate over 16 bytes of code.
func (MacroAssembler) JumpToTrapHandler(m *module.M, id trap.Id) {
	in.MOVi.RegImm32(&m.Text, abi.I32, RegResult, int32(id)) // automatic zero-extension
	in.MOVDQmrMMX.RegReg(&m.Text, abi.I64, RegTrapHandlerMMX, RegScratch)
	in.JMP.Reg(&m.Text, in.OneSize, RegScratch)
}

// LoadIntROData may update condition flags.  The register passed as argument
// is both the index (source) and the target register.  The index has been
// zero-extended.
func (MacroAssembler) LoadIntROData(f *gen.Func, indexType abi.Type, r reg.R, addr int32) {
	in.MOV.RegMemIndexDisp(&f.Text, indexType, r, in.BaseZero, r, in.TypeScale(indexType), f.RODataAddr+addr)
}

// Move MUST NOT update condition flags unless the operand is the condition
// flags.  The source operand is consumed.
func (MacroAssembler) Move(f *gen.Func, target reg.R, x operand.O) (zeroExt bool) {
	switch x.Type.Category() {
	case abi.Int:
		switch x.Storage {
		case storage.Stack:
			in.POP.Reg(&f.Text, in.OneSize, target)
			f.StackValueConsumed()

		case storage.Imm:
			switch value := x.ImmValue(); {
			case value == 0:
				in.MOV.RegReg(&f.Text, abi.I32, target, RegZero)
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
			setBool(f.M, x.FlagsCond())
			if target != RegScratch {
				in.MOV.RegReg(&f.Text, abi.I32, target, RegScratch)
			}
			zeroExt = true
		}

	case abi.Float:
		switch x.Storage {
		case storage.Stack:
			in.MOVDQ.RegStack(&f.Text, x.Type, target)
			in.ADDi.RegImm8(&f.Text, abi.I64, RegStackPtr, obj.Word)
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
func (MacroAssembler) MoveReg(m *module.M, t abi.Type, target, source reg.R) {
	switch t.Category() {
	case abi.Int:
		in.MOV.RegReg(&m.Text, t, target, source)

	case abi.Float:
		in.MOVAPSD.RegReg(&m.Text, t, target, source)
	}
}

// PushImm has default restrictions.
func (MacroAssembler) PushImm(m *module.M, value int64) {
	switch {
	case value == 0:
		in.PUSHo.RegZero(&m.Text)

	case uint64(value+0x80000000) <= 0xffffffff:
		in.PUSHi.Imm(&m.Text, int32(value))

	default:
		in.MOV64i.RegImm64(&m.Text, RegScratch, value)
		in.PUSHo.RegScratch(&m.Text)
	}
}

// PushReg has default restrictions.
func (MacroAssembler) PushReg(m *module.M, t abi.Type, r reg.R) {
	switch t.Category() {
	case abi.Int:
		in.PUSH.Reg(&m.Text, in.OneSize, r)

	case abi.Float:
		in.SUBi.RegImm8(&m.Text, abi.I64, RegStackPtr, obj.Word)
		in.MOVDQmr.RegStack(&m.Text, t, r)
	}
}

// PushCond has default restrictions.
func (MacroAssembler) PushCond(m *module.M, cond condition.C) {
	setBool(m, cond)
	in.PUSHo.RegScratch(&m.Text)
}

// PushZeros may use RegResult and update condition flags.
func (MacroAssembler) PushZeros(m *module.M, n int) {
	if n <= 9 {
		for i := 0; i < n; i++ {
			in.PUSHo.RegZero(&m.Text)
		}
	} else {
		in.MOVi.RegImm32(&m.Text, abi.I32, RegCount, int32(n)) // 6 bytes
		loopAddr := m.Text.Addr
		in.PUSHo.RegZero(&m.Text)          // 1 byte
		in.LOOPcb.Addr8(&m.Text, loopAddr) // 2 bytes
	}
}

// Return may use RegResult and update condition flags.
func (MacroAssembler) Return(m *module.M, numStackValues int) {
	asm.DropStackValues(m, numStackValues)
	in.RET.Simple(&m.Text)
}

// SetupStackFrame may use RegResult and update condition flags.
func (MacroAssembler) SetupStackFrame(f *gen.Func) (stackCheckAddr int32) {
	var checked link.L

	in.LEA.RegStackStub32(&f.Text, abi.I64, RegScratch)
	stackCheckAddr = f.Text.Addr

	in.CMP.RegReg(&f.Text, abi.I64, RegScratch, RegStackLimit)

	in.JGEcb.Stub8(&f.Text)
	checked.AddSite(f.Text.Addr)

	asm.Trap(f, trap.CallStackExhausted) // handler checks if it was actually suspension

	checked.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &checked)
	return
}

// SetBool has default restrictions.  It MUST zero-extend the target register.
func (MacroAssembler) SetBool(m *module.M, target reg.R, cond condition.C) {
	setBool(m, cond)
	in.MOV.RegReg(&m.Text, abi.I32, target, RegScratch)
}

// setBool sets the scratch register.  (SETcc's register encoding is tricky.)
func setBool(m *module.M, cond condition.C) {
	var end link.L

	switch {
	case cond >= condition.MinUnorderedOrCondition:
		in.MOVi.RegImm32(&m.Text, abi.I32, RegScratch, 1) // true
		in.JPcb.Stub8(&m.Text)                            // if unordered, else
		end.AddSite(m.Text.Addr)

	case cond >= condition.MinOrderedAndCondition:
		in.MOV.RegReg(&m.Text, abi.I32, RegScratch, RegZero) // false
		in.JPcb.Stub8(&m.Text)                               // if unordered, else
		end.AddSite(m.Text.Addr)

	default:
		in.MOV.RegReg(&m.Text, abi.I32, RegScratch, RegZero)
	}

	conditionInsns[cond].SetccOpcode().OneSizeReg(&m.Text, RegScratch)

	end.Addr = m.Text.Addr
	isa.UpdateNearBranches(m.Text.Bytes(), &end)
}

// LoadStack has default restrictions.  It MUST zero-extend the (integer)
// target register.
func (MacroAssembler) LoadStack(m *module.M, t abi.Type, target reg.R, offset int32) {
	switch t.Category() {
	case abi.Int:
		in.MOV.RegStackDisp(&m.Text, t, target, offset)

	case abi.Float:
		in.MOVDQ.RegStackDisp(&m.Text, t, target, offset)
	}
}

// StoreStack has default restrictions.  The source operand is consumed.
func (MacroAssembler) StoreStack(f *gen.Func, offset int32, x operand.O) {
	r, _ := getScratchReg(f, x)
	asm.StoreStackReg(f.M, x.Type, offset, r)
	f.Regs.Free(x.Type, r)
}

// StoreStackImm has default restrictions.
func (MacroAssembler) StoreStackImm(m *module.M, t abi.Type, offset int32, value int64) {
	switch {
	case value == 0:
		in.MOVmr.RegStackDisp(&m.Text, abi.I64, RegZero, offset)

	case t.Size() == abi.Size32:
		in.MOVi.StackDispImm32(&m.Text, abi.I32, offset, int32(value))

	case t.Size() == abi.Size64:
		in.MOV64i.RegImm64(&m.Text, RegScratch, value)
		in.MOVmr.RegStackDisp(&m.Text, abi.I64, RegScratch, offset)
	}
}

// StoreStackReg has default restrictions.
func (MacroAssembler) StoreStackReg(m *module.M, t abi.Type, offset int32, r reg.R) {
	switch t.Category() {
	case abi.Int:
		in.MOVmr.RegStackDisp(&m.Text, t, r, offset)

	case abi.Float:
		in.MOVDQmr.RegStackDisp(&m.Text, t, r, offset)
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
func (MacroAssembler) ZeroExtendResultReg(m *module.M) {
	in.MOV.RegReg(&m.Text, abi.I32, RegResult, RegResult)
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

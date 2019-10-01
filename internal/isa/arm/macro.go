// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
	"errors"
	"fmt"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/condition"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/rodata"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/arm/in"
	"github.com/tsavola/wag/internal/obj"
	"github.com/tsavola/wag/object/abi"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

const (
	NopWord = 0xd503201f
	PadWord = 0xd4200000 // BRK #0 instruction
)

var conditions = [10]in.Cond{
	condition.Eq:  in.EQ,
	condition.Ne:  in.NE,
	condition.GeS: in.GE,
	condition.GtS: in.GT,
	condition.GeU: in.HS,
	condition.GtU: in.HI,
	condition.LeS: in.LE,
	condition.LtS: in.LT,
	condition.LeU: in.LS,
	condition.LtU: in.LO,
	// TODO: float conditions
}

var asm MacroAssembler

type MacroAssembler struct{}

func (MacroAssembler) AlignData(*gen.Prog, int) {}
func (MacroAssembler) AlignFunc(*gen.Prog)      {}

func (MacroAssembler) PadUntil(p *gen.Prog, addr int32) {
	padUntil(p, PadWord, addr)
}

func padUntil(p *gen.Prog, filler uint32, addr int32) {
	for p.Text.Addr < addr {
		p.Text.PutUint32(filler)
	}
}

func (MacroAssembler) AddToStackPtrUpper32(f *gen.Func, r reg.R) {
	f.Text.PutUint32(in.ADDs.RdRnI6RmS2(RegFakeSP, RegFakeSP, 32, r, in.ASR, wa.I64))
	f.Regs.Free(wa.I64, r)
}

func (MacroAssembler) DropStackValues(p *gen.Prog, n int) {
	offset := uint32(n * 8)
	if offset > 4095 {
		panic(n) // TODO
	}
	p.Text.PutUint32(in.ADDi.RdRnI12S2(RegFakeSP, RegFakeSP, offset, 0, wa.I64))
}

func (MacroAssembler) Branch(p *gen.Prog, addr int32) {
	p.Text.PutUint32(in.B.I26(in.Int26((addr - p.Text.Addr) / 4)))
}

func (MacroAssembler) BranchStub(p *gen.Prog) int32 {
	p.Text.PutUint32(in.B.I26(0)) // Infinite loop as placeholder.
	return p.Text.Addr
}

func (MacroAssembler) BranchIndirect(f *gen.Func, addr reg.R) {
	var o output

	o.uint32(in.ADDe.RdRnI3ExtRm(RegScratch, RegTextBase, 0, in.UXTW, addr, wa.I64))
	o.uint32(in.BR.Rn(RegScratch))
	o.copy(f.Text.Extend(o.size()))

	f.Regs.Free(wa.I64, addr)
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
	var o output
	var cond condition.C

	if x.Storage == storage.Flags {
		cond = x.FlagsCond()
	} else {
		r, _ := getScratchReg(f, x)
		// TODO: use test-and-branch instruction if possible
		o.uint32(in.ANDSs.RdRnI6RmS2(RegDiscard, r, 0, r, 0, wa.I32))
		cond = condition.Ne
		f.Regs.Free(wa.I32, r)
	}

	if !yes {
		cond = condition.Inverted[cond]
	}

	switch {
	case cond >= condition.MinUnorderedOrCondition:
		TODO(cond)

	case cond >= condition.MinOrderedAndCondition:
		TODO(cond)
	}

	o.uint32(in.Bc.CondI19(conditions[cond], 0)) // Infinite loop as placeholder.
	sites = append(sites, o.addr(&f.Text))

	o.copy(f.Text.Extend(o.size()))
	return
}

func (MacroAssembler) BranchIfOutOfBounds(p *gen.Prog, indexReg reg.R, upperBound, addr int32) {
	o := compareBounds(indexReg, upperBound)
	o.uint32(in.B.I26(in.Int26((addr - o.addr(&p.Text)) / 4)))
	o.copy(p.Text.Extend(o.size()))
}

func (MacroAssembler) BranchIfOutOfBoundsStub(p *gen.Prog, indexReg reg.R, upperBound int32) int32 {
	o := compareBounds(indexReg, upperBound)
	o.uint32(in.B.I26(0)) // Infinite loop as placeholder.
	o.copy(p.Text.Extend(o.size()))

	return p.Text.Addr
}

// compareBounds may use RegScratch.
func compareBounds(indexReg reg.R, upperBound int32) (o output) {
	o.uint32(in.TBNZ.RtI14Bit(indexReg, 3, 31)) // Jump to end if index is negative.

	switch n := uint32(upperBound); {
	case n <= 2047:
		o.uint32(in.SUBSi.RdRnI12S2(RegDiscard, indexReg, n, 0, wa.I32))

	default:
		moveUintImm32(&o, RegScratch, n)
		o.uint32(in.SUBSe.RdRnI3ExtRm(RegDiscard, indexReg, 0, in.UXTW, RegScratch, wa.I32))
	}

	o.uint32(in.Bc.CondI19(in.LT, 2)) // Skip next instruction.
	return
}

func (MacroAssembler) Call(p *gen.Prog, addr int32) (retAddr int32) {
	offset := -p.Text.Addr // NoFunction trap as placeholder.
	if addr != 0 {
		offset = addr - p.Text.Addr
	}
	p.Text.PutUint32(in.BL.I26(in.Int26(offset / 4)))
	return p.Text.Addr
}

func (MacroAssembler) CallMissing(p *gen.Prog, atomic bool) (retAddr int32) {
	p.Text.PutUint32(in.BL.I26(in.Int26(-p.Text.Addr / 4)))
	return p.Text.Addr
}

func (MacroAssembler) CallIndirect(f *gen.Func, sigIndex int32, r reg.R) int32 {
	o := compareBounds(r, int32(len(f.Module.TableFuncs)))
	putTrapInsn(&o, f, trap.IndirectCallIndexOutOfBounds)

	o.uint32(in.ADDi.RdRnI12S2(RegScratch, RegTextBase, rodata.TableAddr, 0, wa.I64))
	o.uint32(in.LDRr.RtRnSOptionRm(r, RegScratch, in.Scaled, in.UXTW, r, wa.I64))
	moveUintImm32(&o, RegScratch, uint32(sigIndex))
	o.uint32(in.SUBSs.RdRnI6RmS2(RegDiscard, RegScratch, 32, r, in.LSR, wa.I64))
	o.uint32(in.Bc.CondI19(in.EQ, 2)) // Skip trap instruction.
	putTrapInsn(&o, f, trap.IndirectCallSignatureMismatch)

	o.uint32(in.ADDe.RdRnI3ExtRm(RegScratch, RegTextBase, 0, in.UXTW, r, wa.I64))
	o.uint32(in.BLR.Rn(RegScratch))
	o.copy(f.Text.Extend(o.size()))

	f.Regs.Free(wa.I64, r)

	return f.Text.Addr
}

func (MacroAssembler) ClearIntResultReg(p *gen.Prog) {
	p.Text.PutUint32(in.MOVZ.RdI16Hw(RegResult, 0, 0, wa.I64))
}

func (MacroAssembler) LoadGlobal(p *gen.Prog, t wa.Type, target reg.R, offset int32) (zeroExt bool) {
	if offset < -256 {
		panic(errors.New("arm: program has too many globals"))
	}

	if t.Category() == wa.Int {
		p.Text.PutUint32(in.LDUR.RtRnI9(target, RegMemoryBase, in.Int9(offset), t))
		return false // TODO: yes, no?
	} else {
		return TODO(t).(bool)
	}
}

func (MacroAssembler) StoreGlobal(f *gen.Func, offset int32, x operand.O) {
	if offset < -256 {
		panic(errors.New("arm: program has too many globals"))
	}

	if x.Type.Category() == wa.Int {
		r, _ := getScratchReg(f, x)
		f.Text.PutUint32(in.STUR.RtRnI9(r, RegMemoryBase, in.Int9(offset), x.Type))
		f.Regs.Free(x.Type, r)
	} else {
		TODO(x.Type)
	}
}

func (MacroAssembler) Resume(p *gen.Prog) {
	padUntil(p, PadWord, abi.TextAddrResume)
	p.Text.PutUint32(in.RET.Rn(RegLink)) // Return from trap handler or import function call.
}

func (MacroAssembler) Init(p *gen.Prog) {
	padUntil(p, PadWord, abi.TextAddrStart)
	p.Text.PutUint32(NopWord)
}

func (MacroAssembler) InitCallEntry(p *gen.Prog) (retAddr int32) {
	padUntil(p, NopWord, abi.TextAddrEnter)

	// Entry routine

	p.Text.PutUint32(in.MOVZ.RdI16Hw(RegResult, 0, 0, wa.I64)) // Result if no entry func.

	p.Text.PutUint32(in.PopIntReg(RegScratch))
	p.Text.PutUint32(in.CBZ.RtI19(RegScratch, 3, wa.I32)) // Skip 2 next instructions.
	p.Text.PutUint32(in.ADDe.RdRnI3ExtRm(RegScratch, RegTextBase, 0, in.UXTW, RegScratch, wa.I64))
	p.Text.PutUint32(in.BLR.Rn(RegScratch))
	retAddr = p.Text.Addr

	// Exit

	p.Text.PutUint32(in.LogicalShiftLeft(RegResult, RegResult, 32, wa.I64))
	p.Text.PutUint32(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(gen.VectorOffsetTrapHandler), wa.I64))
	p.Text.PutUint32(in.BR.Rn(RegScratch))

	return
}

func (MacroAssembler) CallImportVector(p *gen.Prog, index int, variadic bool, argCount, sigIndex int) {
	var o output

	if variadic {
		o.uint32(in.MOVZ.RdI16Hw(RegImportVariadic, uint32(sigIndex), 0, wa.I64))
		o.uint32(in.MOVK.RdI16Hw(RegImportVariadic, uint32(argCount), 2, wa.I64))
	}

	switch {
	case index >= -32:
		o.uint32(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(int32(index*8)), wa.I64))

	case index >= -4096:
		o.uint32(in.SUBi.RdRnI12S2(RegScratch, RegTextBase, 8, 1, wa.I64))           // 8 << 12
		o.uint32(in.LDR.RdRnI12(RegScratch, RegScratch, uint32(4096+index), wa.I64)) // Scaled by 8.

	default:
		panic(fmt.Errorf("arm: import function index is out of range: %d", index))
	}

	o.uint32(in.BLR.Rn(RegScratch))

	o.copy(p.Text.Extend(o.size()))
}

func (MacroAssembler) JumpToTrapHandler(p *gen.Prog, id trap.ID) {
	jumpToTrapHandler(p, id)
}

func (MacroAssembler) JumpToStackTrapHandler(p *gen.Prog) {
	p.Text.PutUint32(in.SUBi.RdRnI12S2(RegLink, RegLink, 5*4, 0, wa.I64)) // See SetupStackFrame.
	jumpToTrapHandler(p, trap.CallStackExhausted)
}

func jumpToTrapHandler(p *gen.Prog, id trap.ID) {
	var o output

	o.uint32(in.MOVZ.RdI16Hw(RegResult, uint32(id), 0, wa.I64))
	o.uint32(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(gen.VectorOffsetTrapHandler), wa.I64))
	o.uint32(in.BR.Rn(RegScratch))
	o.copy(p.Text.Extend(o.size()))
}

func (MacroAssembler) LoadIntStubNear(f *gen.Func, indexType wa.Type, r reg.R) (addr int32) {
	var o output

	o.uint32(in.BRK.I16(0)) // Placeholder for start of table calculation (ADR into RegScratch).
	addr = o.addr(&f.Text)
	o.uint32(in.LDRr.RtRnSOptionRm(r, RegScratch, in.Scaled, in.SizeZeroExt(indexType), r, indexType))
	o.copy(f.Text.Extend(o.size()))
	return
}

func (MacroAssembler) Move(f *gen.Func, target reg.R, x operand.O) (zeroExt bool) {
	switch t := x.Type; t.Category() {
	case wa.Int:
		switch x.Storage {
		case storage.Imm:
			moveIntImm(&f.Text, target, x.ImmValue())
			zeroExt = true

		case storage.Stack:
			f.Text.PutUint32(in.PopIntReg(target))
			f.StackValueConsumed()

		case storage.Reg:
			if source := x.Reg(); target != source {
				f.Text.PutUint32(in.ORRs.RdRnI6RmS2(target, RegZero, 0, source, 0, t))
				f.Regs.Free(t, source)
				zeroExt = true
			} else {
				if target != RegResult {
					panic("register moved to itself")
				}
			}

		case storage.Flags:
			asm.SetBool(&f.Prog, target, x.FlagsCond())
			zeroExt = true

		default:
			panic(x.Storage)
		}

	default:
		panic(t.Category()) // TODO
	}

	return
}

func (MacroAssembler) MoveReg(p *gen.Prog, t wa.Type, target, source reg.R) {
	switch t.Category() {
	case wa.Int:
		p.Text.PutUint32(in.ORRs.RdRnI6RmS2(target, RegZero, 0, source, 0, t))

	default:
		TODO(t)
	}
}

func (MacroAssembler) PushImm(p *gen.Prog, value int64) {
	if value == 0 {
		p.Text.PutUint32(in.PushIntReg(RegZero))
	} else {
		moveIntImm(&p.Text, RegScratch, value)
		p.Text.PutUint32(in.PushIntReg(RegScratch))
	}
}

func (MacroAssembler) PushReg(p *gen.Prog, t wa.Type, r reg.R) {
	switch t.Category() {
	case wa.Int:
		p.Text.PutUint32(in.PushIntReg(r))

	default:
		TODO(t)
	}
}

func (MacroAssembler) PushCond(p *gen.Prog, cond condition.C) {
	TODO(cond)
}

func (MacroAssembler) PushZeros(p *gen.Prog, n int) {
	for i := 0; i < n; i++ {
		p.Text.PutUint32(in.PushIntReg(RegZero))
	}
}

func (MacroAssembler) Return(p *gen.Prog, numStackValues int) {
	var o output

	if numStackValues != 0 {
		offset := uint32(numStackValues * 8)
		if offset > 4095 {
			panic(numStackValues) // TODO
		}
		o.uint32(in.ADDi.RdRnI12S2(RegFakeSP, RegFakeSP, offset, 0, wa.I64))
	}
	o.uint32(in.LDRpost.RtRnI9(RegLink, RegFakeSP, obj.Word, wa.I64))
	o.uint32(in.RET.Rn(RegLink))
	o.copy(p.Text.Extend(o.size()))
}

func (MacroAssembler) SetupStackFrame(f *gen.Func) (stackCheckAddr int32) {
	f.MapCallAddr(f.Text.Addr) // Resume address.

	// If the following instructions are changed, JumpToStackTrapHandler must
	// be changed to match the instruction sequence size.

	var o output

	o.uint32(in.PushIntReg(RegLink))

	o.uint32(in.BRK.I16(0)) // Placeholder for ADD (target is RegScratch).
	stackCheckAddr = o.addr(&f.Text)

	// sp - scratch*16
	// sp - (limit + alloc)
	o.uint32(in.SUBSs.RdRnI6RmS2(RegDiscard, RegFakeSP, 4, RegScratch, in.LSL, wa.I64))
	o.uint32(in.Bc.CondI19(in.GE, 2)) // Skip trap instruction.
	putUnmappedTrapInsn(&o, f, trap.CallStackExhausted)

	o.copy(f.Text.Extend(o.size()))
	return
}

func (MacroAssembler) SetBool(p *gen.Prog, target reg.R, cond condition.C) {
	switch {
	case cond >= condition.MinUnorderedOrCondition:
		panic(cond) // TODO

	case cond >= condition.MinOrderedAndCondition:
		panic(cond) // TODO
	}

	inverse := condition.Inverted[cond]
	p.Text.PutUint32(in.CSINC.RdRnCondRm(target, RegZero, conditions[inverse], RegZero, wa.I64))
}

func (MacroAssembler) LoadStack(p *gen.Prog, t wa.Type, target reg.R, offset int32) {
	index := uint32(offset) / uint32(t.Size())

	switch t.Category() {
	case wa.Int:
		p.Text.PutUint32(in.LDR.RdRnI12(target, RegFakeSP, index, t))

	case wa.Float:
		TODO(t)
	}
}

func (MacroAssembler) StoreStack(f *gen.Func, offset int32, x operand.O) {
	r, _ := getScratchReg(f, x)
	asm.StoreStackReg(&f.Prog, x.Type, offset, r)
	f.Regs.Free(x.Type, r)
}

func (MacroAssembler) StoreStackImm(p *gen.Prog, t wa.Type, offset int32, value int64) {
	index := uint32(offset) / uint32(t.Size())
	r := RegZero

	if value != 0 {
		r = RegScratch
		moveIntImm(&p.Text, r, value)
	}

	p.Text.PutUint32(in.STR.RdRnI12(r, RegFakeSP, index, t))
}

func (MacroAssembler) StoreStackReg(p *gen.Prog, t wa.Type, offset int32, r reg.R) {
	index := uint32(offset) / uint32(t.Size())

	switch t.Category() {
	case wa.Int:
		p.Text.PutUint32(in.STR.RdRnI12(r, RegFakeSP, index, t))

	case wa.Float:
		TODO(t)
	}
}

func (MacroAssembler) Trap(f *gen.Func, id trap.ID) {
	var o output

	putTrapInsn(&o, f, id)
	o.copy(f.Text.Extend(o.size()))
}

// putTrapInsn must generate exactly one instruction.
func putTrapInsn(o *output, f *gen.Func, id trap.ID) {
	putUnmappedTrapInsn(o, f, id)
	f.MapTrapAddr(o.addr(&f.Text))
}

// putUnmappedTrapInsn must generate exactly one instruction.
func putUnmappedTrapInsn(o *output, f *gen.Func, id trap.ID) {
	o.uint32(in.BL.I26(in.Int26((f.TrapLinks[id].Addr - o.addr(&f.Text)) / 4)))
}

func (MacroAssembler) TrapIfLoopSuspended(f *gen.Func) {
	var o output

	o.uint32(in.TBZ.RtI14Bit(RegSuspendBit, 2, 0)) // Skip trap instruction.
	putUnmappedTrapInsn(&o, f, trap.Suspended)
	o.copy(f.Text.Extend(o.size()))

	f.MapCallAddr(f.Text.Addr) // Resume address.
}

func (MacroAssembler) TrapIfLoopSuspendedSaveInt(f *gen.Func, saveReg reg.R) {
	var o output

	o.uint32(in.TBZ.RtI14Bit(RegSuspendBit, 4, 0)) // Skip until end.
	o.uint32(in.PushIntReg(saveReg))
	putUnmappedTrapInsn(&o, f, trap.Suspended)
	f.MapCallAddr(o.addr(&f.Text)) // Resume address.
	o.uint32(in.PopIntReg(saveReg))
	o.copy(f.Text.Extend(o.size()))
}

func (MacroAssembler) TrapIfLoopSuspendedElse(f *gen.Func, elseAddr int32) {
	var o output

	switch offset := (elseAddr - f.Text.Addr) / 4; {
	case offset >= -8192:
		o.uint32(in.TBZ.RtI14Bit(RegSuspendBit, in.Int14(offset), 0))

	default:
		// Instead of branching to else, assume that the same effect can be
		// achieved by skipping the trap.
		o.uint32(in.TBZ.RtI14Bit(RegSuspendBit, 2, 0))
	}

	putUnmappedTrapInsn(&o, f, trap.Suspended)
	o.copy(f.Text.Extend(o.size()))

	f.MapCallAddr(f.Text.Addr) // Resume address.
}

func (MacroAssembler) ZeroExtendResultReg(p *gen.Prog) {
	p.Text.PutUint32(in.UBFM.RdRnI6sI6r(RegResult, RegResult, 31, 0, wa.I64))
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

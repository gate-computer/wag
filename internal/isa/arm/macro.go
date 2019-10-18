// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package arm

import (
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
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

const (
	NopWord = 0xd503201f
	PadWord = 0xd4200000 // BRK #0 instruction
)

var conditions = [22]in.Cond{
	condition.Eq:            in.EQ,
	condition.Ne:            in.NE,
	condition.GeS:           in.GE,
	condition.GtS:           in.GT,
	condition.GeU:           in.HS,
	condition.GtU:           in.HI,
	condition.LeS:           in.LE,
	condition.LtS:           in.LT,
	condition.LeU:           in.LS,
	condition.LtU:           in.LO,
	condition.OrderedAndEq:  in.EQ,
	condition.OrderedAndNe:  in.NE, // Order must be checked separately.
	condition.OrderedAndGe:  in.GE,
	condition.OrderedAndGt:  in.GT,
	condition.OrderedAndLe:  in.LS,
	condition.OrderedAndLt:  in.LO,
	condition.UnorderedOrEq: in.EQ, // Disorder must be checked separately.
	condition.UnorderedOrNe: in.NE,
	condition.UnorderedOrGe: in.HS,
	condition.UnorderedOrGt: in.HI,
	condition.UnorderedOrLe: in.LE,
	condition.UnorderedOrLt: in.LT,
}

var asm MacroAssembler

type MacroAssembler struct{}

func (MacroAssembler) AlignData(*gen.Prog, int) {}
func (MacroAssembler) AlignFunc(*gen.Prog)      {}

func (MacroAssembler) PadUntil(p *gen.Prog, addr int32) {
	var o outbuf

	for i := p.Text.Addr; i < addr; i += 4 {
		o.insn(PadWord)
	}
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) AddToStackPtrUpper32(f *gen.Func, r reg.R) {
	f.Text.PutUint32(in.ADDs.RdRnI6RmS2(RegFakeSP, RegFakeSP, 32, r, in.ASR, wa.Size64))
	f.Regs.Free(wa.I64, r)
}

func (MacroAssembler) DropStackValues(p *gen.Prog, n int) {
	offset := uint32(n * 8)
	if offset > 4095 {
		panic(n) // TODO
	}
	p.Text.PutUint32(in.ADDi.RdRnI12S2(RegFakeSP, RegFakeSP, offset, 0, wa.Size64))
}

func (MacroAssembler) Branch(p *gen.Prog, addr int32) {
	p.Text.PutUint32(in.B.I26(in.Int26((addr - p.Text.Addr) / 4)))
}

func (MacroAssembler) BranchStub(p *gen.Prog) int32 {
	p.Text.PutUint32(in.B.I26(0)) // Infinite loop as placeholder.
	return p.Text.Addr
}

func (MacroAssembler) BranchIndirect(f *gen.Func, addr reg.R) {
	var o outbuf

	o.insn(in.ADDe.RdRnI3ExtRm(RegScratch, RegTextBase, 0, in.UXTW, addr, wa.Size64))
	o.insn(in.BR.Rn(RegScratch))
	o.copy(f.Text.Extend(o.size))

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
	var o outbuf

	cond := x.FlagsCond() // Default case (value unspecified until storage checked).

	if x.Storage != storage.Flags {
		r := o.getScratchReg(f, x)
		// TODO: use test-and-branch instruction if possible
		o.insn(in.ANDSs.RdRnI6RmS2(RegDiscard, r, 0, r, 0, wa.Size32))
		cond = condition.Ne
		f.Regs.Free(wa.I32, r)
	}

	if !yes {
		cond = condition.Inverted[cond]
	}

	switch cond {
	case condition.OrderedAndEq:
		o.insn(in.Bc.CondI19(in.VS, 2)) // Skip next branch if unordered.

	case condition.UnorderedOrEq:
		o.insn(in.Bc.CondI19(in.VS, 0)) // Infinite loop as placeholder.
		sites = append(sites, o.addr(&f.Text))
	}

	o.insn(in.Bc.CondI19(conditions[cond], 0)) // Infinite loop as placeholder.
	sites = append(sites, o.addr(&f.Text))

	o.copy(f.Text.Extend(o.size))
	return
}

func (MacroAssembler) BranchIfOutOfBounds(p *gen.Prog, indexReg reg.R, upperBound, addr int32) {
	var o outbuf

	o.compareBounds(indexReg, upperBound)
	o.insn(in.B.I26(in.Int26((addr - o.addr(&p.Text)) / 4)))
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) BranchIfOutOfBoundsStub(p *gen.Prog, indexReg reg.R, upperBound int32) int32 {
	var o outbuf

	o.compareBounds(indexReg, upperBound)
	o.insn(in.B.I26(0)) // Infinite loop as placeholder.
	o.copy(p.Text.Extend(o.size))

	return p.Text.Addr
}

// compareBounds may use RegScratch.
func (o *outbuf) compareBounds(indexReg reg.R, upperBound int32) {
	o.insn(in.TBNZ.RtI14Bit(indexReg, 3, 31)) // Jump to end if index is negative.

	switch n := uint32(upperBound); {
	case n <= 2047:
		o.insn(in.SUBSi.RdRnI12S2(RegDiscard, indexReg, n, 0, wa.Size32))

	default:
		o.moveUintImm32(RegScratch, n)
		o.insn(in.SUBSe.RdRnI3ExtRm(RegDiscard, indexReg, 0, in.UXTW, RegScratch, wa.Size32))
	}

	o.insn(in.Bc.CondI19(in.LT, 2)) // Skip next instruction.
}

func (MacroAssembler) Call(p *gen.Prog, addr int32) {
	offset := -p.Text.Addr // NoFunction trap as placeholder.
	if addr != 0 {
		offset = addr - p.Text.Addr
	}
	p.Text.PutUint32(in.BL.I26(in.Int26(offset / 4)))
}

func (MacroAssembler) CallMissing(p *gen.Prog, atomic bool) {
	p.Text.PutUint32(in.BL.I26(in.Int26(-p.Text.Addr / 4)))
}

func (MacroAssembler) CallIndirect(f *gen.Func, sigIndex int32, r reg.R) {
	var o outbuf

	o.compareBounds(r, int32(len(f.Module.TableFuncs)))
	o.trap(f, trap.IndirectCallIndexOutOfBounds)

	o.insn(in.ADDi.RdRnI12S2(RegScratch, RegTextBase, rodata.TableAddr, 0, wa.Size64))
	o.insn(in.LDRr.RtRnSOptionRm(r, RegScratch, in.Scaled, in.UXTW, r, wa.I64))
	o.moveUintImm32(RegScratch, uint32(sigIndex))
	o.insn(in.SUBSs.RdRnI6RmS2(RegDiscard, RegScratch, 32, r, in.LSR, wa.Size64))
	o.insn(in.Bc.CondI19(in.EQ, 2)) // Skip trap instruction.
	o.trap(f, trap.IndirectCallSignatureMismatch)

	o.insn(in.ADDe.RdRnI3ExtRm(RegScratch, RegTextBase, 0, in.UXTW, r, wa.Size64))
	o.insn(in.BLR.Rn(RegScratch))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(wa.I64, r)
}

func (MacroAssembler) ClearIntResultReg(p *gen.Prog) {
	p.Text.PutUint32(in.MOVZ.RdI16Hw(RegResult, 0, 0, wa.Size64))
}

func (MacroAssembler) LoadGlobal(p *gen.Prog, t wa.Type, target reg.R, offset int32) (zeroExt bool) {
	// compile.maxGlobals ensures that offset is never below -256.
	p.Text.PutUint32(in.LDUR.RtRnI9(target, RegMemoryBase, in.Int9(offset), t))
	return false // TODO: yes, no?
}

func (MacroAssembler) StoreGlobal(f *gen.Func, offset int32, x operand.O) {
	var o outbuf

	r := o.getScratchReg(f, x)

	// compile.maxGlobals ensures that offset is never below -256.
	o.insn(in.STUR.RtRnI9(r, RegMemoryBase, in.Int9(offset), x.Type))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(x.Type, r)
}

func (MacroAssembler) Resume(p *gen.Prog) {
	p.Text.PutUint32(in.RET.Rn(RegLink)) // Return from trap handler or import function call.
}

func (MacroAssembler) Enter(p *gen.Prog) {
	var o outbuf

	// Start function

	o.insn(in.PopReg(RegScratch, wa.I32))
	o.insn(in.CBZ.RtI19(RegScratch, 3, wa.Size32)) // Skip 2 next instructions.
	o.insn(in.ADDe.RdRnI3ExtRm(RegScratch, RegTextBase, 0, in.UXTW, RegScratch, wa.Size64))
	o.insn(in.BLR.Rn(RegScratch))
	p.Map.PutCallSite(uint32(o.addr(&p.Text)), obj.Word) // Depth includes entry address.

	// Entry function

	o.insn(in.MOVZ.RdI16Hw(RegResult, 0, 0, wa.Size64)) // Result if no entry func.

	o.insn(in.PopReg(RegScratch, wa.I32))
	o.insn(in.CBZ.RtI19(RegScratch, 3, wa.Size32)) // Skip 2 next instructions.
	o.insn(in.ADDe.RdRnI3ExtRm(RegScratch, RegTextBase, 0, in.UXTW, RegScratch, wa.Size64))
	o.insn(in.BLR.Rn(RegScratch))
	p.Map.PutCallSite(uint32(o.addr(&p.Text)), 0) // No function addresses remain on stack.

	// Exit

	o.insn(in.LogicalShiftLeft(RegResult, RegResult, 32, wa.Size64))
	o.insn(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(gen.VectorOffsetTrapHandler), wa.I64))
	o.insn(in.BR.Rn(RegScratch))
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) CallImportVector(p *gen.Prog, index int, variadic bool, argCount, sigIndex int) {
	var o outbuf

	if variadic {
		o.insn(in.MOVZ.RdI16Hw(RegImportVariadic, uint32(sigIndex), 0, wa.Size64))
		o.insn(in.MOVK.RdI16Hw(RegImportVariadic, uint32(argCount), 2, wa.Size64))
	}

	switch {
	case index >= -32:
		o.insn(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(int32(index*8)), wa.I64))

	case index >= -4096:
		o.insn(in.SUBi.RdRnI12S2(RegScratch, RegTextBase, 8, 1, wa.Size64))        // 8 << 12
		o.insn(in.LDR.RdRnI12(RegScratch, RegScratch, uint32(4096+index), wa.I64)) // Scaled by 8.

	default:
		panic(fmt.Errorf("arm: import function index is out of range: %d", index))
	}

	o.insn(in.BLR.Rn(RegScratch))
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) JumpToTrapHandler(p *gen.Prog, id trap.ID) {
	var o outbuf

	o.jumpToTrapHandler(p, id)
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) JumpToStackTrapHandler(p *gen.Prog) {
	var o outbuf

	o.insn(in.SUBi.RdRnI12S2(RegLink, RegLink, 5*4, 0, wa.Size64)) // See SetupStackFrame.
	o.jumpToTrapHandler(p, trap.CallStackExhausted)
	o.copy(p.Text.Extend(o.size))
}

func (o *outbuf) jumpToTrapHandler(p *gen.Prog, id trap.ID) {
	o.insn(in.MOVZ.RdI16Hw(RegResult, uint32(id), 0, wa.Size64))
	o.insn(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(gen.VectorOffsetTrapHandler), wa.I64))
	o.insn(in.BR.Rn(RegScratch))
}

func (MacroAssembler) LoadIntStubNear(f *gen.Func, indexType wa.Type, r reg.R) (addr int32) {
	var o outbuf

	o.insn(in.BRK.I16(0)) // Placeholder for start of table calculation (ADR into RegScratch).
	addr = o.addr(&f.Text)

	o.insn(in.LDRr.RtRnSOptionRm(r, RegScratch, in.Scaled, in.SizeZeroExt(indexType.Size()), r, indexType))
	o.copy(f.Text.Extend(o.size))
	return
}

func (MacroAssembler) Move(f *gen.Func, target reg.R, x operand.O) (zeroExt bool) {
	var o outbuf

	zeroExt = o.move(f, target, x)
	o.copy(f.Text.Extend(o.size))
	return
}

func (o *outbuf) move(f *gen.Func, target reg.R, x operand.O) (zeroExt bool) {
	switch x.Storage {
	case storage.Imm:
		if x.Type.Category() == wa.Int {
			o.moveIntImm(target, x.ImmValue())
		} else {
			o.moveIntImm(RegScratch, x.ImmValue())
			o.insn(in.FMOVfromg.RdRn(target, RegScratch, x.Size(), x.Size()))
		}

	case storage.Stack:
		o.insn(in.PopReg(target, x.Type))
		f.StackValueConsumed()

	case storage.Reg:
		if source := x.Reg(); target != source {
			var insn uint32

			if x.Type.Category() == wa.Int {
				insn = in.ORRs.RdRnI6RmS2(target, RegZero, 0, source, 0, x.Size())
				zeroExt = true
			} else {
				insn = in.FMOV.RdRn(target, source, x.Size())
			}
			o.insn(insn)

			f.Regs.Free(x.Type, source)
		} else {
			if target != RegResult {
				panic("register moved to itself")
			}
		}

	case storage.Flags:
		o.setBool(target, x.FlagsCond())
		zeroExt = true
	}

	return
}

func (MacroAssembler) MoveReg(p *gen.Prog, t wa.Type, target, source reg.R) {
	var insn uint32

	if t.Category() == wa.Int {
		insn = in.ORRs.RdRnI6RmS2(target, RegZero, 0, source, 0, t.Size())
	} else {
		insn = in.FMOV.RdRn(target, source, t.Size())
	}
	p.Text.PutUint32(insn)
}

func (MacroAssembler) PushImm(p *gen.Prog, value int64) {
	var o outbuf

	r := RegZero
	if value != 0 {
		r = RegScratch
		o.moveIntImm(r, value)
	}
	o.insn(in.PushReg(r, wa.I64))
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) PushReg(p *gen.Prog, t wa.Type, r reg.R) {
	p.Text.PutUint32(in.PushReg(r, t))
}

func (MacroAssembler) PushCond(p *gen.Prog, cond condition.C) {
	var o outbuf

	o.setBool(RegScratch, cond)
	o.insn(in.PushReg(RegScratch, wa.I32))
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) PushZeros(p *gen.Prog, n int) {
	// TODO: use outbuf if few entries; generate a loop if many entries
	for i := 0; i < n; i++ {
		p.Text.PutUint32(in.PushReg(RegZero, wa.I64))
	}
}

func (MacroAssembler) Return(p *gen.Prog, numStackValues int) {
	var o outbuf

	if numStackValues != 0 {
		offset := uint32(numStackValues * 8)
		if offset > 4095 {
			panic(numStackValues) // TODO
		}
		o.insn(in.ADDi.RdRnI12S2(RegFakeSP, RegFakeSP, offset, 0, wa.Size64))
	}
	o.insn(in.LDRpost.RtRnI9(RegLink, RegFakeSP, obj.Word, wa.I64))
	o.insn(in.RET.Rn(RegLink))
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) SetupStackFrame(f *gen.Func) (stackCheckAddr int32) {
	f.MapCallAddr(f.Text.Addr) // Resume address.

	// If the following instructions are changed, JumpToStackTrapHandler must
	// be changed to match the instruction sequence size.

	var o outbuf

	o.insn(in.PushReg(RegLink, wa.I64))

	o.insn(in.BRK.I16(0)) // Placeholder for ADD (target is RegScratch).
	stackCheckAddr = o.addr(&f.Text)

	// sp - scratch*16
	// sp - (limit + alloc)
	o.insn(in.SUBSs.RdRnI6RmS2(RegDiscard, RegFakeSP, 4, RegScratch, in.LSL, wa.Size64))
	o.insn(in.Bc.CondI19(in.GE, 2)) // Skip trap instruction.
	o.unmappedTrap(f, trap.CallStackExhausted)
	o.copy(f.Text.Extend(o.size))
	return
}

func (MacroAssembler) SetBool(p *gen.Prog, target reg.R, cond condition.C) {
	var o outbuf

	o.setBool(target, cond)
	o.copy(p.Text.Extend(o.size))
}

func (o *outbuf) setBool(target reg.R, cond condition.C) {
	switch cond {
	case condition.OrderedAndEq:
		o.insn(in.MOVZ.RdI16Hw(target, 0, 0, wa.Size64)) // Default result is 0.
		o.insn(in.Bc.CondI19(in.VS, 2))                  // Skip CSINC if unordered.

	case condition.UnorderedOrEq:
		o.insn(in.MOVZ.RdI16Hw(target, 1, 0, wa.Size64)) // Default result is 1.
		o.insn(in.Bc.CondI19(in.VS, 2))                  // Skip CSINC if unordered.
	}

	cond = condition.Inverted[cond]
	o.insn(in.CSINC.RdRnCondRm(target, RegZero, conditions[cond], RegZero, wa.Size64))
}

func (MacroAssembler) LoadStack(p *gen.Prog, t wa.Type, target reg.R, offset int32) {
	index := uint32(offset) / uint32(t.Size())
	p.Text.PutUint32(in.LDR.RdRnI12(target, RegFakeSP, index, t))
}

func (MacroAssembler) StoreStack(f *gen.Func, offset int32, x operand.O) {
	var o outbuf

	r := o.getScratchReg(f, x)
	o.insn(in.STR.RdRnI12(r, RegFakeSP, uint32(offset)/uint32(x.Size()), x.Type))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(x.Type, r)
}

func (MacroAssembler) StoreStackImm(p *gen.Prog, t wa.Type, offset int32, value int64) {
	var o outbuf

	r := RegZero
	if value != 0 {
		r = RegScratch
		o.moveIntImm(r, value)
	}
	o.insn(in.STR.RdRnI12(r, RegFakeSP, uint32(offset)/8, wa.I64))
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) StoreStackReg(p *gen.Prog, t wa.Type, offset int32, r reg.R) {
	p.Text.PutUint32(in.STR.RdRnI12(r, RegFakeSP, uint32(offset)/uint32(t.Size()), t))
}

func (MacroAssembler) Trap(f *gen.Func, id trap.ID) {
	var o outbuf

	o.trap(f, id)
	o.copy(f.Text.Extend(o.size))
}

// trap must generate exactly one instruction.
func (o *outbuf) trap(f *gen.Func, id trap.ID) {
	o.unmappedTrap(f, id)
	f.MapTrapAddr(o.addr(&f.Text))
}

// unmappedTrap must generate exactly one instruction.
func (o *outbuf) unmappedTrap(f *gen.Func, id trap.ID) {
	o.insn(in.BL.I26(in.Int26((f.TrapLinks[id].Addr - o.addr(&f.Text)) / 4)))
}

func (MacroAssembler) TrapIfLoopSuspended(f *gen.Func) {
	var o outbuf

	o.insn(in.TBZ.RtI14Bit(RegSuspendBit, 2, 0)) // Skip trap instruction.
	o.unmappedTrap(f, trap.Suspended)
	o.copy(f.Text.Extend(o.size))

	f.MapCallAddr(f.Text.Addr) // Resume address.
}

func (MacroAssembler) TrapIfLoopSuspendedSaveInt(f *gen.Func, saveReg reg.R) {
	var o outbuf

	o.insn(in.TBZ.RtI14Bit(RegSuspendBit, 4, 0)) // Skip until end.
	o.insn(in.PushReg(saveReg, wa.I64))
	o.unmappedTrap(f, trap.Suspended)
	f.MapCallAddr(o.addr(&f.Text)) // Resume address.
	o.insn(in.PopReg(saveReg, wa.I64))
	o.copy(f.Text.Extend(o.size))
}

func (MacroAssembler) TrapIfLoopSuspendedElse(f *gen.Func, elseAddr int32) {
	var o outbuf

	switch offset := (elseAddr - f.Text.Addr) / 4; {
	case offset >= -8192:
		o.insn(in.TBZ.RtI14Bit(RegSuspendBit, in.Int14(offset), 0))

	default:
		// Instead of branching to else, assume that the same effect can be
		// achieved by skipping the trap.
		o.insn(in.TBZ.RtI14Bit(RegSuspendBit, 2, 0))
	}

	o.unmappedTrap(f, trap.Suspended)
	o.copy(f.Text.Extend(o.size))

	f.MapCallAddr(f.Text.Addr) // Resume address.
}

func (MacroAssembler) ZeroExtendResultReg(p *gen.Prog) {
	p.Text.PutUint32(in.UBFM.RdRnI6sI6r(RegResult, RegResult, 31, 0, wa.Size64))
}

// getScratchReg returns either the operand's existing register, or the
// operand's value in RegScratch.
func (o *outbuf) getScratchReg(f *gen.Func, x operand.O) reg.R {
	if x.Storage == storage.Reg {
		return x.Reg()
	} else {
		o.move(f, RegScratch, x)
		return RegScratch
	}
}

// allocResultReg may allocate registers.  It returns either the operand's
// existing register, or the operand's value in allocated register or
// RegResult.
func (o *outbuf) allocResultReg(f *gen.Func, x operand.O) reg.R {
	if x.Storage == storage.Reg {
		return x.Reg()
	} else {
		r := f.Regs.AllocResult(x.Type)
		o.move(f, r, x)
		return r
	}
}

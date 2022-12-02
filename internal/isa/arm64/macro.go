// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (arm64 || wagarm64) && !wagamd64
// +build arm64 wagarm64
// +build !wagamd64

package arm64

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/gen/link"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/rodata"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/isa/arm64/in"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
	"import.name/pan"
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
	var o outbuf

	o.dropStackValues(n)
	o.copy(p.Text.Extend(o.size))
}

func (o *outbuf) dropStackValues(n int) {
	if n < 4096/obj.Word {
		o.insn(in.ADDi.RdRnI12S2(RegFakeSP, RegFakeSP, uint32(n*obj.Word), 0, wa.Size64))
	} else {
		o.insn(in.MOVZ.RdI16Hw(RegScratch, 0, uint32(n), wa.Size64))
		o.insn(in.ADDs.RdRnI6RmS2(RegFakeSP, RegFakeSP, 3, RegScratch, in.LSL, wa.Size64))
	}
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
	switch n := uint32(upperBound); {
	case n <= 2047:
		o.insn(in.TBNZ.RtI14Bit(indexReg, 3, 31)) // Jump to end if index is negative.
		o.insn(in.SUBSi.RdRnI12S2(RegDiscard, indexReg, n, 0, wa.Size32))

	default:
		// TODO: optimize (make the move sequence conditional)
		o.moveUintImm32(RegScratch, n)
		o.insn(in.TBNZ.RtI14Bit(indexReg, 3, 31)) // Jump to end if index is negative.
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
	return true
}

func (MacroAssembler) StoreGlobal(f *gen.Func, offset int32, x operand.O) {
	var o outbuf

	r := o.getScratchReg(f, x)

	// compile.maxGlobals ensures that offset is never below -256.
	o.insn(in.STUR.RtRnI9(r, RegMemoryBase, in.Int9(offset), x.Type))
	o.copy(f.Text.Extend(o.size))

	f.Regs.Free(x.Type, r)
}

func (o *outbuf) initRoutinePrologue() {
	o.insn(in.LDUR.RtRnI9(RegMemoryBase, RegTextBase, in.Int9(gen.VectorOffsetMemoryAddr), wa.I64))
}

func (MacroAssembler) Exit(p *gen.Prog) {
	asm.TrapHandler(p, trap.Exit)
}

func (MacroAssembler) Resume(p *gen.Prog) {
	var o outbuf

	o.initRoutinePrologue()
	o.insn(in.RET.Rn(RegLink)) // Return from trap handler or import function call.
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) Enter(p *gen.Prog) {
	var o outbuf

	o.initRoutinePrologue()

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

	o.insn(in.BL.I26(in.Int26((p.TrapLinks[trap.Exit].Addr - o.addr(&p.Text)) / 4)))
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) CallImportVector(f *gen.Func, index int) {
	var o outbuf

	numParams := f.NumExtra - 2
	offset := numParams + 1 + f.NumLocals + f.StackDepth // 1 for link address.
	if offset >= 4096/obj.Word {
		panic(offset)
	}
	o.insn(in.ADDi.RdRnI12S2(RegRestartSP, RegFakeSP, uint32(offset*obj.Word), 0, wa.Size64))

	switch {
	case index >= -32:
		o.insn(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(int32(index*8)), wa.I64))

	case index >= -4096:
		o.insn(in.SUBi.RdRnI12S2(RegScratch, RegTextBase, 8, 1, wa.Size64))        // 8 << 12
		o.insn(in.LDR.RdRnI12(RegScratch, RegScratch, uint32(4096+index), wa.I64)) // Scaled by 8.

	default:
		pan.Panic(module.Errorf("import function index is out of range: %d", index))
	}

	o.insn(in.BLR.Rn(RegScratch))
	o.copy(f.Text.Extend(o.size))
}

func (MacroAssembler) TrapHandler(p *gen.Prog, id trap.ID) {
	var o outbuf

	o.trapHandler(p, id)
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) TrapHandlerRewindNoFunction(p *gen.Prog) {
	var o outbuf

	o.insn(in.SUBi.RdRnI12S2(RegLink, RegLink, 4, 0, wa.Size64))
	o.trapHandler(p, trap.NoFunction)
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) TrapHandlerRewindCallStackExhausted(p *gen.Prog) {
	var o outbuf

	o.insn(in.SUBi.RdRnI12S2(RegLink, RegLink, 4*4, 0, wa.Size64)) // See SetupStackFrame.
	o.trapHandler(p, trap.CallStackExhausted)
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) TrapHandlerRewindSuspended(p *gen.Prog, index int) {
	var o outbuf

	o.insn(in.SUBi.RdRnI12S2(RegLink, RegLink, 2*4, 0, wa.Size64)) // See BranchSuspend.
	o.trapHandler(p, trap.Suspended)
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) TrapHandlerTruncOverflow(p *gen.Prog, trapIndex int) {
	panic(trapIndex)
}

func (o *outbuf) trapHandler(p *gen.Prog, id trap.ID) {
	o.trapHandlerPrologue(p, id)
	o.insn(in.BR.Rn(RegScratch))
}

// trapHandlerPrologue doesn't update condition flags.
func (o *outbuf) trapHandlerPrologue(p *gen.Prog, id trap.ID) {
	o.insn(in.MOVZ.RdI16Hw(RegTrap, uint32(id), 0, wa.Size64))
	o.insn(in.LDUR.RtRnI9(RegScratch, RegTextBase, in.Int9(gen.VectorOffsetTrapHandler), wa.I64))
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
		o.dropStackValues(numStackValues)
	}
	o.insn(in.LDRpost.RtRnI9(RegLink, RegFakeSP, obj.Word, wa.I64))
	o.insn(in.RET.Rn(RegLink))
	o.copy(p.Text.Extend(o.size))
}

func (MacroAssembler) SetupStackFrame(f *gen.Func) (stackCheckAddr int32) {
	var o outbuf

	o.insn(in.PushReg(RegLink, wa.I64))

	f.MapCallAddr(o.addr(&f.Text)) // Resume address.
	restartAddr := o.addr(&f.Text)

	// If the following (NumExtra == 0) instructions are changed,
	// TrapHandlerRewindCallStackExhausted must be changed to match the
	// instruction sequence size.

	o.insn(in.BRK.I16(0)) // Placeholder for ADD (target is RegScratch).
	stackCheckAddr = o.addr(&f.Text)

	if f.NumExtra == 0 {
		// sp - scratch*16
		// sp - (limit + alloc)
		o.insn(in.SUBSs.RdRnI6RmS2(RegDiscard, RegFakeSP, 4, RegScratch, in.LSL, wa.Size64))
		o.insn(in.Bc.CondI19(in.GE, 2)) // Skip next instruction.
		o.unmappedTrap(f, f.TrapLinks[trap.CallStackExhausted])
	} else {
		// Get resume address by setting link register and rewinding it until
		// start of function.

		o.insn(in.BL.I26(1)) // Next instruction.
		o.insn(in.SUBi.RdRnI12S2(RegLink, RegLink, in.Uint12(uint64(o.addr(&f.Text)-restartAddr)), 0, wa.Size64))

		// The return address is in link register.  Inline the trap trampoline;
		// the branch will be matched with a return sequence which pops the
		// restart address.

		// sp - scratch*16
		// sp - (limit + alloc)
		o.insn(in.SUBSs.RdRnI6RmS2(RegDiscard, RegFakeSP, 4, RegScratch, in.LSL, wa.Size64))
		o.trapHandlerPrologue(&f.Prog, trap.CallStackExhausted)
		o.insn(in.Bc.CondI19(in.GE, 2)) // Skip next instruction.
		o.insn(in.BR.Rn(RegScratch))

		// Push the return address on stack to facilitate resume in rt calls.
		// Duplicate arguments for mutation, and push (dummy) link address.

		o.insn(in.PushReg(RegLink, wa.I64)) // Restart address.

		numParams := f.NumExtra - 2

		if numParams > 0 {
			copyOffset := (1 + 1 + numParams) - 1 // Restart address, link address, and params.

			o.moveIntImm(RegScratch, int64(numParams))

			o.insn(in.LDR.RdRnI12(RegResult, RegFakeSP, uint32(copyOffset), wa.I64))
			o.insn(in.PushReg(RegResult, wa.I64))
			o.insn(in.SUBSi.RdRnI12S2(RegScratch, RegScratch, 1, 0, wa.Size64))
			o.insn(in.Bc.CondI19(in.NE, in.Int19(-3))) // Loop.
		}

		o.insn(in.PushReg(RegZero, wa.I64)) // Dummy link address.
	}

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
	o.unmappedTrap(f, f.TrapLinks[id])
	f.MapCallAddr(o.addr(&f.Text))
}

// unmappedTrap must generate exactly one instruction.
func (o *outbuf) unmappedTrap(f *gen.Func, handler link.L) {
	o.insn(in.BL.I26(in.Int26((handler.Addr - o.addr(&f.Text)) / 4)))
}

func (MacroAssembler) SuspendSaveInt(f *gen.Func, saveReg reg.R) {
	var o outbuf

	o.insn(in.TBZ.RtI14Bit(RegStackLimit4, 4, 0)) // Skip until end.
	o.insn(in.PushReg(saveReg, wa.I64))
	o.trap(f, trap.Suspended)
	o.insn(in.PopReg(saveReg, wa.I64))
	o.copy(f.Text.Extend(o.size))
}

func (MacroAssembler) BranchSuspend(f *gen.Func, addr int32) {
	var o outbuf

	if offset := (addr - f.Text.Addr) / 4; offset >= -8192 && f.Text.Addr != f.LastCallAddr {
		f.MapCallAddr(f.Text.Addr) // Resume address.

		// If the following instructions are changed,
		// TrapHandlerRewindSuspended must be changed to match the instruction
		// sequence size.
		o.insn(in.TBZ.RtI14Bit(RegStackLimit4, in.Int14(offset), 0))
		o.unmappedTrap(f, f.TrapLinkRewindSuspended[0])
	} else {
		o.insn(in.TBZ.RtI14Bit(RegStackLimit4, 2, 0))
		o.trap(f, trap.Suspended)
		o.insn(in.B.I26(in.Int26((addr - o.addr(&f.Text)) / 4)))
	}

	o.copy(f.Text.Extend(o.size))
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

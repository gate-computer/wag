// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/condition"
	"gate.computer/wag/internal/gen/link"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/rodata"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/isa/x86/in"
	"gate.computer/wag/internal/isa/x86/nonabi"
	"gate.computer/wag/internal/obj"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
	errors "golang.org/x/xerrors"
)

const (
	FuncAlignment = 16

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

var suspendRewindOffsets = [2]int8{
	0: 8,  // See BranchSuspend; near jump.
	1: 12, // See BranchSuspend; far jump.
}

var asm MacroAssembler

type MacroAssembler struct{}

func (MacroAssembler) AlignData(p *gen.Prog, alignment int) {
	pad(p, (alignment-int(p.Text.Addr))&(alignment-1))
}

func (MacroAssembler) AlignFunc(p *gen.Prog) {
	pad(p, (FuncAlignment-int(p.Text.Addr))&(FuncAlignment-1))
}

func (MacroAssembler) PadUntil(p *gen.Prog, addr int32) {
	pad(p, int(addr)-int(p.Text.Addr))
}

func pad(p *gen.Prog, length int) {
	gap := p.Text.Extend(length)
	for i := range gap {
		gap[i] = PadByte
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

func (MacroAssembler) Branch(p *gen.Prog, addr int32) {
	in.JMPcd.Addr32(&p.Text, addr)
}

func (MacroAssembler) BranchStub(p *gen.Prog) int32 {
	return in.JMPcd.Stub32(&p.Text)
}

func (MacroAssembler) BranchIndirect(f *gen.Func, addr reg.R) {
	in.MOV.RegReg(&f.Text, wa.I32, RegScratch, addr)
	f.Regs.Free(wa.I64, addr)
	in.ADD.RegReg(&f.Text, wa.I64, RegScratch, RegTextBase)
	in.JMPcd.Addr32(&f.Text, nonabi.TextAddrRetpoline)
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
		sites = append(sites, in.JPc.Stub(&f.Text, near))

	case cond >= condition.MinOrderedAndCondition:
		endJumps = append(endJumps, in.JPcb.Stub8(&f.Text))
	}

	sites = append(sites, conditionInsns[cond].JccOpcodeC().Stub(&f.Text, near))

	linker.UpdateNearBranches(f.Text.Bytes(), endJumps)
	return
}

func (MacroAssembler) BranchIfOutOfBounds(p *gen.Prog, indexReg reg.R, upperBound, addr int32) {
	compareBounds(p, indexReg, upperBound)
	in.JLEc.Addr(&p.Text, addr)
}

func (MacroAssembler) BranchIfOutOfBoundsStub(p *gen.Prog, indexReg reg.R, upperBound int32) int32 {
	compareBounds(p, indexReg, upperBound)
	return in.JLEc.AddrStub(&p.Text)
}

// compareBounds zero-extends indexReg.
func compareBounds(p *gen.Prog, indexReg reg.R, upperBound int32) {
	in.MOVi.RegImm32(&p.Text, wa.I32, RegScratch, upperBound)
	in.TEST.RegReg(&p.Text, wa.I32, indexReg, indexReg)
	in.CMOVL.RegReg(&p.Text, wa.I32, indexReg, RegScratch) // negative index -> upper bound
	in.CMP.RegReg(&p.Text, wa.I32, RegScratch, indexReg)
}

func (MacroAssembler) Call(p *gen.Prog, addr int32) {
	in.CALLcd.Addr32(&p.Text, addr)
}

func (MacroAssembler) CallMissing(p *gen.Prog, atomic bool) {
	in.CALLcd.MissingFunction(&p.Text, atomic)
}

func (MacroAssembler) CallIndirect(f *gen.Func, sigIndex int32, funcIndexReg reg.R) {
	compareBounds(&f.Prog, funcIndexReg, int32(len(f.Module.TableFuncs))) // zero-extension
	outOfBoundsJump := in.JLEcb.Stub8(&f.Text)

	in.MOV.RegMemIndexDisp(&f.Text, wa.I64, RegResult, in.BaseText, funcIndexReg, in.Scale3, rodata.TableAddr)
	f.Regs.Free(wa.I64, funcIndexReg)
	in.MOV.RegReg(&f.Text, wa.I32, RegScratch, RegResult) // zero-extended function address
	in.SHRi.RegImm8(&f.Text, wa.I64, RegResult, 32)       // signature index
	in.CMPi.RegImm(&f.Text, wa.I32, RegResult, sigIndex)
	okJump := in.JEcb.Stub8(&f.Text)

	asm.Trap(f, trap.IndirectCallSignatureMismatch)

	linker.UpdateNearBranch(f.Text.Bytes(), outOfBoundsJump)

	asm.Trap(f, trap.IndirectCallIndexOutOfBounds)

	linker.UpdateNearBranch(f.Text.Bytes(), okJump)

	in.ADD.RegReg(&f.Text, wa.I64, RegScratch, RegTextBase)
	in.CALLcd.Addr32(&f.Text, nonabi.TextAddrRetpoline)
}

func (MacroAssembler) ClearIntResultReg(p *gen.Prog) {
	in.XOR.RegReg(&p.Text, wa.I32, RegResult, RegResult)
}

func (MacroAssembler) LoadGlobal(p *gen.Prog, t wa.Type, target reg.R, offset int32) (zeroExtended bool) {
	if t.Category() == wa.Int {
		in.MOV.RegMemDisp(&p.Text, t, target, in.BaseMemory, offset)
	} else {
		in.MOVx.RegMemDisp(&p.Text, t, target, in.BaseMemory, offset)
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
		in.MOVxmr.RegMemDisp(&f.Text, x.Type, r, in.BaseMemory, offset)
	}
}

func initRoutinePrologue(p *gen.Prog) {
	// Zero register zeroing conveniently sets the zero flag, which is required
	// by BranchSuspend.

	in.MOV.RegMemDisp(&p.Text, wa.I64, RegMemoryBase, in.BaseText, gen.VectorOffsetMemoryAddr)
	in.XOR.RegReg(&p.Text, wa.I32, RegZero, RegZero)
}

func (MacroAssembler) Resume(p *gen.Prog) {
	initRoutinePrologue(p)
	in.RET.Simple(&p.Text) // Return from trap handler or import function call.
}

func (MacroAssembler) Enter(p *gen.Prog) {
	initRoutinePrologue(p)

	// Start function

	in.POP.Reg(&p.Text, in.OneSize, RegScratch) // Start function address.
	in.TEST.RegReg(&p.Text, wa.I32, RegScratch, RegScratch)
	skipStart := in.JEcb.Stub8(&p.Text)

	in.ADD.RegReg(&p.Text, wa.I64, RegScratch, RegTextBase)
	in.CALLcd.Addr32(&p.Text, nonabi.TextAddrRetpoline)
	p.Map.PutCallSite(uint32(p.Text.Addr), obj.Word) // Depth includes entry address.

	linker.UpdateNearBranch(p.Text.Bytes(), skipStart)

	// Entry function

	in.XOR.RegReg(&p.Text, wa.I32, RegResult, RegResult) // Result if no entry function.

	in.POP.Reg(&p.Text, in.OneSize, RegScratch) // Entry function address.
	in.TEST.RegReg(&p.Text, wa.I32, RegScratch, RegScratch)
	skipEntry := in.JEcb.Stub8(&p.Text)

	in.ADD.RegReg(&p.Text, wa.I64, RegScratch, RegTextBase)
	in.CALLcd.Addr32(&p.Text, nonabi.TextAddrRetpoline)
	p.Map.PutCallSite(uint32(p.Text.Addr), 0) // No function addresses remain on stack.

	linker.UpdateNearBranch(p.Text.Bytes(), skipEntry)

	// Exit

	in.SHLi.RegImm8(&p.Text, wa.I64, RegResult, 32) // Result at top, trap id (0) at bottom.
	in.MOV.RegMemDisp(&p.Text, wa.I64, RegScratch, in.BaseText, gen.VectorOffsetTrapHandler)
	in.JMPcd.Addr32(&p.Text, nonabi.TextAddrRetpoline)

	// Retpoline (https://support.google.com/faqs/answer/7625886)

	asm.AlignFunc(p)
	if p.Text.Addr != nonabi.TextAddrRetpoline {
		panic("x86: hardcoded retpoline address needs to be adjusted")
	}

	in.CALLcd.Addr32(&p.Text, nonabi.TextAddrRetpolineSetup)

	captureSpecAddr := p.Text.Addr
	in.PAUSE.Simple(&p.Text)
	in.JMPcb.Addr8(&p.Text, captureSpecAddr)

	asm.AlignFunc(p)
	if p.Text.Addr != nonabi.TextAddrRetpolineSetup {
		panic("x86: hardcoded retpoline setup address needs to be adjusted")
	}

	asm.StoreStackReg(p, wa.I64, 0, RegScratch)
	in.XOR.RegReg(&p.Text, wa.I32, RegScratch, RegScratch)
	in.RET.Simple(&p.Text)
}

func (MacroAssembler) CallImportVector(p *gen.Prog, vecIndex int, variadic bool, argCount, sigIndex int) {
	if variadic {
		in.MOV64i.RegImm64(&p.Text, RegImportVariadic, (int64(argCount)<<32)|int64(sigIndex))
	}
	in.MOV.RegMemDisp(&p.Text, wa.I64, RegScratch, in.BaseText, int32(vecIndex*8))
	in.CALLcd.Addr32(&p.Text, nonabi.TextAddrRetpoline)
}

func (MacroAssembler) TrapHandler(p *gen.Prog, id trap.ID) {
	trapHandler(p, id)
}

func (MacroAssembler) TrapHandlerRewindCallStackExhausted(p *gen.Prog) {
	in.SUBi.StackImm8(&p.Text, wa.I64, 18) // See SetupStackFrame.
	trapHandler(p, trap.CallStackExhausted)
}

func (MacroAssembler) TrapHandlerRewindSuspended(p *gen.Prog, index int) {
	in.SUBi.StackImm8(&p.Text, wa.I64, suspendRewindOffsets[index])
	trapHandler(p, trap.Suspended)
}

func (MacroAssembler) TrapHandlerTruncOverflow(p *gen.Prog, trapIndex int) {
	var (
		floatIntType wa.Type
		fractionSize int8
		exponentMask int32
		goodBits     int32
	)

	switch trapIndex >> 1 {
	case int(wa.Size32 >> 3):
		floatIntType = wa.I32
		fractionSize = 23
		exponentMask = 0xff
		if trapIndex&1 == int(wa.Size32>>3) {
			goodBits = 0x19e // s=1 e=10011110
		} else { // 64-bit
			goodBits = 0x1be // s=1 e=10111110
		}

	case int(wa.Size64 >> 3):
		floatIntType = wa.I64
		fractionSize = 52
		exponentMask = 0x7ff
		if trapIndex&1 == int(wa.Size32>>3) {
			goodBits = 0xc1e // s=1 e=10000011110
		} else { // 64-bit
			goodBits = 0xc3e // s=1 e=10000111110
		}

	default:
		panic(trapIndex)
	}

	in.MOVxmr.RegReg(&p.Text, floatIntType, RegResult, RegScratch)   // int <- float
	in.RORi.RegImm8(&p.Text, floatIntType, RegScratch, fractionSize) // Exponent at bottom.

	in.CMPi.RegImm32(&p.Text, floatIntType, RegScratch, goodBits)
	jumpIfOutOfRange := in.JNEcb.Stub8(&p.Text)

	in.ANDi.RegImm32(&p.Text, wa.I32, RegScratch, exponentMask) // Exponent is all ones?
	in.CMPi.RegImm32(&p.Text, wa.I32, RegScratch, exponentMask)
	jumpIfInfNan := in.JEcb.Stub8(&p.Text)

	in.RET.Simple(&p.Text)

	linker.UpdateNearBranch(p.Text.Bytes(), jumpIfOutOfRange)
	linker.UpdateNearBranch(p.Text.Bytes(), jumpIfInfNan)

	trapHandler(p, trap.IntegerOverflow)
}

func trapHandler(p *gen.Prog, id trap.ID) {
	in.MOVi.RegImm32(&p.Text, wa.I32, RegResult, int32(id)) // automatic zero-extension
	in.MOV.RegMemDisp(&p.Text, wa.I64, RegScratch, in.BaseText, gen.VectorOffsetTrapHandler)
	in.JMPcd.Addr32(&p.Text, nonabi.TextAddrRetpoline)
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
			in.MOVx.RegStack(&f.Text, x.Type, target)
			in.ADDi.RegImm8(&f.Text, wa.I64, RegStackPtr, obj.Word)
			f.StackValueConsumed()

		case storage.Imm:
			if value := x.ImmValue(); value == 0 {
				in.PXOR.RegReg(&f.Text, in.OneSize, target, target)
			} else {
				in.MOV64i.RegImm64(&f.Text, RegScratch, value) // integer scratch register
				in.MOVx.RegReg(&f.Text, x.Type, target, RegScratch)
			}

		case storage.Reg:
			if source := x.Reg(); source != target {
				in.MOVAPx.RegReg(&f.Text, x.Type, target, source)
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
		in.MOVAPx.RegReg(&p.Text, t, target, source)
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
		in.MOVxmr.RegStack(&p.Text, t, r)
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
	f.MapCallAddr(f.Text.Addr) // Resume address.

	// If the following instructions are changed,
	// TrapHandlerRewindCallStackExhausted must be changed to match the
	// instruction sequence size.

	stackCheckAddr = in.LEA.RegStackStub32(&f.Text, wa.I64, RegScratch)

	in.CMP.RegReg(&f.Text, wa.I64, RegScratch, RegStackLimit)
	in.JGEcb.Rel8(&f.Text, in.CALLcd.Size())                             // Skip next instruction.
	in.CALLcd.Addr32(&f.Text, f.TrapLinks[trap.CallStackExhausted].Addr) // Handler checks suspension.
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
		in.MOVi.RegImm32(&p.Text, wa.I32, RegScratch, 1)    // true
		endJumps = append(endJumps, in.JPcb.Stub8(&p.Text)) // if unordered, else

	case cond >= condition.MinOrderedAndCondition:
		in.MOV.RegReg(&p.Text, wa.I32, RegScratch, RegZero) // false
		endJumps = append(endJumps, in.JPcb.Stub8(&p.Text)) // if unordered, else

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
		in.MOVx.RegStackDisp(&p.Text, t, target, offset)
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

	case t.Size() == wa.Size32:
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
		in.MOVxmr.RegStackDisp(&p.Text, t, r, offset)
	}
}

func (MacroAssembler) Trap(f *gen.Func, id trap.ID) {
	in.CALLcd.Addr32(&f.Text, f.TrapLinks[id].Addr)
	f.MapTrapAddr(f.Text.Addr)
}

func (MacroAssembler) Breakpoint(f *gen.Func) {
	in.CALLcd.Addr32(&f.Text, f.TrapLinks[trap.Breakpoint].Addr)
	f.MapCallAddr(f.Text.Addr) // Resume address.
}

func (MacroAssembler) SuspendSaveInt(f *gen.Func, saveReg reg.R) {
	in.TEST8.RegRegStackLimit(&f.Text)
	skipJump := in.JEcb.Stub8(&f.Text) // Skip if bit is zero (no trap).

	in.PUSH.Reg(&f.Text, in.OneSize, saveReg)
	in.CALLcd.Addr32(&f.Text, f.TrapLinks[trap.Suspended].Addr)
	f.MapCallAddr(f.Text.Addr) // Resume address.
	in.POP.Reg(&f.Text, in.OneSize, saveReg)

	linker.UpdateNearBranch(f.Text.Bytes(), skipJump)
}

func (MacroAssembler) BranchSuspend(f *gen.Func, addr int32) {
	// Don't include this first instruction in the rewind sequence to make sure
	// that call sites have distinct addresses.  Zero flag must be set by
	// Resume.
	in.TEST8.RegRegStackLimit(&f.Text)

	f.MapCallAddr(f.Text.Addr) // Resume address.

	// If the following instructions are changed, suspendRewindOffsets must be
	// changed to match the instruction sequence sizes.
	far := in.JEc.Addr(&f.Text, addr)
	i := 0
	if far {
		i = 1
	}
	in.CALLcd.Addr32(&f.Text, f.TrapLinkRewindSuspended[i].Addr)
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

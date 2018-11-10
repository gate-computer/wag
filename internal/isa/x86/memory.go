// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/internal/code"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/isa/prop"
	"github.com/tsavola/wag/internal/isa/x86/in"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wa"
)

type regMemDispInsn interface {
	RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base in.BaseReg, disp int32)
}
type memDispImmInsn interface {
	MemDispImm(text *code.Buf, t wa.Type, base in.BaseReg, disp int32, val int64)
}

type opLoadInt32S struct{}
type opLoadInt32U struct{}
type opStoreRegInt32 struct{}
type opStoreImm struct{}

func (opLoadInt32S) RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base in.BaseReg, disp int32) {
	in.MOVSXD.RegMemDisp(text, wa.I64, r, base, disp)
}
func (opLoadInt32U) RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base in.BaseReg, disp int32) {
	in.MOV.RegMemDisp(text, wa.I32, r, base, disp)
}
func (opStoreRegInt32) RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base in.BaseReg, disp int32) {
	in.MOVmr.RegMemDisp(text, wa.I32, r, base, disp)
}
func (opStoreImm) MemDispImm(text *code.Buf, t wa.Type, base in.BaseReg, disp int32, val int64) {
	switch {
	case val == 0:
		in.MOVmr.RegMemDisp(text, t, RegZero, base, disp)
	case uint64(val+0x80000000) <= 0xffffffff:
		in.MOV32i.MemDispImm(text, t, base, disp, val)
	default:
		in.MOV64i.RegImm64(text, RegResult, val)
		in.MOVmr.RegMemDisp(text, t, RegResult, base, disp)
	}
}

var loadInsns = [8]regMemDispInsn{
	prop.IndexIntLoad:    in.MOV,
	prop.IndexIntLoad8S:  in.MOVSX8,
	prop.IndexIntLoad8U:  in.MOVZX8,
	prop.IndexIntLoad16S: in.MOVSX16,
	prop.IndexIntLoad16U: in.MOVZX16,
	prop.IndexIntLoad32S: opLoadInt32S{},
	prop.IndexIntLoad32U: opLoadInt32U{},
	prop.IndexFloatLoad:  in.MOVSSD,
}

var storeRegInsns = [5]regMemDispInsn{
	prop.IndexIntStore:   in.MOVmr,
	prop.IndexIntStore8:  in.MOV8mr,
	prop.IndexIntStore16: in.MOV16mr,
	prop.IndexIntStore32: opStoreRegInt32{},
	prop.IndexFloatStore: in.MOVSSDmr,
}

var storeImmInsns = [5]memDispImmInsn{
	prop.IndexIntStore:   opStoreImm{},
	prop.IndexIntStore8:  in.MOV8i,
	prop.IndexIntStore16: in.MOV16i,
	prop.IndexIntStore32: in.MOV32i,
	prop.IndexFloatStore: opStoreImm{},
}

func (MacroAssembler) Load(f *gen.Func, props uint16, index operand.O, resultType wa.Type, align, offset uint32) operand.O {
	sizeReach := uint64(props >> 8)
	base, disp := checkAccess(f, sizeReach, index, offset)

	r := f.Regs.AllocResult(resultType)
	loadInsns[uint8(props&prop.LoadIndexMask)].RegMemDisp(&f.Text, resultType, r, base, disp)
	return operand.Reg(resultType, r)
}

func (MacroAssembler) Store(f *gen.Func, props uint16, index, x operand.O, align, offset uint32) {
	sizeReach := uint64(props >> 8)
	base, disp := checkAccess(f, sizeReach, index, offset)

	if x.Storage == storage.Imm {
		storeImmInsns[uint8(props)].MemDispImm(&f.Text, x.Type, base, disp, x.ImmValue())
	} else {
		valueReg, _ := allocResultReg(f, x)
		storeRegInsns[uint8(props)].RegMemDisp(&f.Text, x.Type, valueReg, base, disp)
		f.Regs.Free(x.Type, valueReg)
	}
}

// checkAccess returns RegMemoryBase or RegScratch as base.
func checkAccess(f *gen.Func, sizeReach uint64, index operand.O, offset uint32) (base in.BaseReg, disp int32) {
	reachOffset := uint64(offset) + sizeReach

	if reachOffset >= 0x80000000 {
		f.ValueBecameUnreachable(index)
		return invalidAccess(f)
	}

	switch index.Storage {
	case storage.Imm:
		value := uint64(index.ImmValue())

		if value >= 0x80000000 {
			return invalidAccess(f)
		}

		addr := value + uint64(offset)
		reachAddr := addr + sizeReach

		if reachAddr >= 0x80000000 {
			return invalidAccess(f)
		}

		if reachAddr < uint64(f.Module.MemoryLimitValues.Initial) {
			// Call site is not mapped, so this optimization is part of
			// portable ABI.
			base = in.BaseMemory
			disp = int32(addr)
			return
		}

		in.LEA.RegMemDisp(&f.Text, wa.I64, RegScratch, in.BaseMemory, int32(reachAddr))

	default:
		asm.Move(f, RegScratch, index) // unconditional 32-bit mask for fool-proofing

		if reachOffset == 0 {
			in.ADD.RegReg(&f.Text, wa.I64, RegScratch, RegMemoryBase)
		} else {
			in.LEA.RegMemIndexDisp(&f.Text, wa.I64, RegScratch, in.BaseMemory, RegScratch, in.Scale0, int32(reachOffset))
		}
	}

	var checked link.L

	in.CMP.RegReg(&f.Text, wa.I64, RegScratch, RegMemoryLimit)
	in.JLcb.Stub8(&f.Text)
	checked.AddSite(f.Text.Addr)

	asm.Trap(f, trap.MemoryOutOfBounds)

	checked.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &checked)

	base = in.BaseScratch
	disp = -int32(sizeReach)
	return
}

func invalidAccess(f *gen.Func) (base in.BaseReg, disp int32) {
	asm.Trap(f, trap.MemoryOutOfBounds)

	base = in.BaseZero
	disp = 0
	return
}

func (MacroAssembler) QueryMemorySize(f *gen.Func) operand.O {
	r := f.Regs.AllocResult(wa.I64)
	in.MOV.RegReg(&f.Text, wa.I64, r, RegMemoryLimit)
	in.SUB.RegReg(&f.Text, wa.I64, r, RegMemoryBase)
	in.SHRi.RegImm8(&f.Text, wa.I64, r, wa.PageBits)
	return operand.Reg(wa.I32, r)
}

func (MacroAssembler) GrowMemory(f *gen.Func, x operand.O) operand.O {
	var out link.L
	var fail link.L

	in.MOV.RegMemDisp(&f.Text, wa.I64, RegScratch, in.BaseText, gen.VectorOffsetGrowMemoryLimit)
	in.ADD.RegReg(&f.Text, wa.I64, RegScratch, RegMemoryBase)

	targetReg, zeroExtended := allocResultReg(f, x)
	if !zeroExtended {
		in.MOV.RegReg(&f.Text, wa.I32, targetReg, targetReg)
	}

	in.SHLi.RegImm8(&f.Text, wa.I64, targetReg, wa.PageBits)
	in.ADD.RegReg(&f.Text, wa.I64, targetReg, RegMemoryLimit) // new memory limit
	in.CMP.RegReg(&f.Text, wa.I64, targetReg, RegScratch)

	in.JGcb.Stub8(&f.Text)
	fail.AddSite(f.Text.Addr)

	in.MOV.RegReg(&f.Text, wa.I64, RegScratch, RegMemoryLimit)
	in.MOV.RegReg(&f.Text, wa.I64, RegMemoryLimit, targetReg)
	in.SUB.RegReg(&f.Text, wa.I64, RegScratch, RegMemoryBase)
	in.SHRi.RegImm8(&f.Text, wa.I64, RegScratch, wa.PageBits) // value on success
	in.MOV.RegReg(&f.Text, wa.I32, targetReg, RegScratch)

	in.JMPcb.Stub8(&f.Text)
	out.AddSite(f.Text.Addr)

	fail.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &fail)

	in.MOVi.RegImm32(&f.Text, wa.I32, targetReg, -1) // value on failure

	out.Addr = f.Text.Addr
	isa.UpdateNearBranches(f.Text.Bytes(), &out)

	return operand.Reg(wa.I32, targetReg)
}

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || wagamd64) && !wagarm64

package amd64

import (
	"gate.computer/wag/internal/code"
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/isa/amd64/in"
	"gate.computer/wag/internal/isa/amd64/nonabi"
	"gate.computer/wag/internal/isa/prop"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
)

type regMemDispInsn interface {
	RegMemDisp(text *code.Buf, t wa.Type, r reg.R, base in.BaseReg, disp int32)
}
type memDispImmInsn interface {
	MemDispImm(text *code.Buf, t wa.Type, base in.BaseReg, disp int32, val int64)
}

type (
	opLoadInt32S    struct{}
	opLoadInt32U    struct{}
	opStoreRegInt32 struct{}
	opStoreImm      struct{}
)

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
	prop.IndexFloatLoad:  in.MOVSx,
}

var storeRegInsns = [5]regMemDispInsn{
	prop.IndexIntStore:   in.MOVmr,
	prop.IndexIntStore8:  in.MOV8mr,
	prop.IndexIntStore16: in.MOV16mr,
	prop.IndexIntStore32: opStoreRegInt32{},
	prop.IndexFloatStore: in.MOVSxmr,
}

var storeImmInsns = [5]memDispImmInsn{
	prop.IndexIntStore:   opStoreImm{},
	prop.IndexIntStore8:  in.MOV8i,
	prop.IndexIntStore16: in.MOV16i,
	prop.IndexIntStore32: in.MOV32i,
	prop.IndexFloatStore: opStoreImm{},
}

func (MacroAssembler) Load(f *gen.Func, props uint64, index operand.O, resultType wa.Type, align, offset uint32) operand.O {
	base, disp := checkAccess(f, index, offset)

	r := f.Regs.AllocResult(resultType)
	loadInsns[props].RegMemDisp(&f.Text, resultType, r, base, disp)
	return operand.Reg(resultType, r)
}

func (MacroAssembler) Store(f *gen.Func, props uint64, index, x operand.O, align, offset uint32) {
	base, disp := checkAccess(f, index, offset)

	if x.Storage == storage.Imm {
		storeImmInsns[props].MemDispImm(&f.Text, x.Type, base, disp, x.ImmValue())
	} else {
		valueReg, _ := allocResultReg(f, x)
		storeRegInsns[props].RegMemDisp(&f.Text, x.Type, valueReg, base, disp)
		f.Regs.Free(x.Type, valueReg)
	}
}

// checkAccess returns RegMemoryBase or RegScratch as base.
func checkAccess(f *gen.Func, index operand.O, offset uint32) (base in.BaseReg, disp int32) {
	if offset >= 0x80000000 {
		f.ValueBecameUnreachable(index)
		return invalidAccess(f)
	}

	switch index.Storage {
	case storage.Imm:
		value := uint64(index.ImmValue())
		addr := value + uint64(offset)
		if value >= 0x80000000 || addr >= 0x80000000 {
			return invalidAccess(f)
		}

		base = in.BaseMemory
		disp = int32(addr)

	default:
		asm.Move(f, RegScratch, index) // Unconditional 32-bit mask.
		in.ADD.RegReg(&f.Text, wa.I64, RegScratch, RegMemoryBase)

		base = in.BaseScratch
		disp = int32(offset)
	}

	f.MapCallAddr(f.Text.Addr) // Address of instruction pointer during SIGSEGV handling.
	return
}

func invalidAccess(f *gen.Func) (base in.BaseReg, disp int32) {
	asm.Trap(f, trap.MemoryAccessOutOfBounds)

	base = in.BaseZero
	disp = 0
	return
}

func (MacroAssembler) CurrentMemory(f *gen.Func) int32 {
	getCurrentMemoryPages(&f.Text)
	return f.Text.Addr
}

// getCurrentMemoryPages count in RegResult.
func getCurrentMemoryPages(text *code.Buf) {
	in.MOV.RegMemDisp(text, wa.I64, RegScratch, in.BaseText, gen.VectorOffsetCurrentMemory)
	in.CALLcd.Addr32(text, nonabi.TextAddrRetpoline)
}

func (MacroAssembler) GrowMemory(f *gen.Func) int32 {
	in.MOV.RegMemDisp(&f.Text, wa.I64, RegScratch, in.BaseText, gen.VectorOffsetGrowMemory)
	in.CALLcd.Addr32(&f.Text, nonabi.TextAddrRetpoline)
	return f.Text.Addr
}

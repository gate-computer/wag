// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x86

import (
	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/val"
	"github.com/tsavola/wag/internal/isa/prop"
	"github.com/tsavola/wag/internal/module"
	"github.com/tsavola/wag/trap"
	"github.com/tsavola/wag/wasm"
)

type memoryAccess struct {
	insn     binaryInsn
	insnType abi.Type
	zeroExt  bool
}

var memoryLoads = []memoryAccess{
	prop.IndexIntLoad:    {mov, 0, true},
	prop.IndexIntLoad8S:  {binaryInsn{movsx8, noPrefixMIInsn}, 0, false},
	prop.IndexIntLoad8U:  {binaryInsn{movzx8, noPrefixMIInsn}, 0, false},
	prop.IndexIntLoad16S: {binaryInsn{movsx16, noPrefixMIInsn}, 0, false},
	prop.IndexIntLoad16U: {binaryInsn{movzx16, noPrefixMIInsn}, 0, false},
	prop.IndexIntLoad32S: {binaryInsn{movsxd, noPrefixMIInsn}, 0, false}, // type is ignored
	prop.IndexIntLoad32U: {mov, abi.I32, true},
	prop.IndexFloatLoad:  {binaryInsn{movsSSE, noPrefixMIInsn}, 0, false},
}

var memoryStores = []memoryAccess{
	prop.IndexIntStore:   {mov, 0, false},
	prop.IndexIntStore8:  {mov8, abi.I32, false},
	prop.IndexIntStore16: {mov16, abi.I32, false},
	prop.IndexIntStore32: {mov, abi.I32, false},
	prop.IndexFloatStore: {binaryInsn{movsSSE, movImm}, 0, false}, // integer immediate works
}

// LoadOp makes sure that index gets zero-extended if it's a VarReg operand.
func (ISA) LoadOp(f *gen.Func, props uint16, index val.Operand, resultType abi.Type, offset uint32) (result val.Operand) {
	size := props >> 8

	baseReg, indexReg, ownIndexReg, disp := opMemoryAddress(f, size, index, offset)
	if ownIndexReg {
		defer f.Regs.Free(abi.I64, indexReg)
	}

	load := memoryLoads[uint8(props)]

	targetReg, ok := f.Regs.Alloc(resultType)
	if !ok {
		targetReg = RegResult
	}

	result = val.TempRegOperand(resultType, targetReg, load.zeroExt)

	insnType := load.insnType
	if insnType == 0 {
		insnType = resultType
	}

	load.insn.opFromIndirect(&f.Text, insnType, targetReg, 0, indexReg, baseReg, disp)
	return
}

// StoreOp makes sure that index gets zero-extended if it's a VarReg operand.
func (ISA) StoreOp(f *gen.Func, props uint16, index, x val.Operand, offset uint32) {
	size := props >> 8

	baseReg, indexReg, ownIndexReg, disp := opMemoryAddress(f, size, index, offset)
	if ownIndexReg {
		defer f.Regs.Free(abi.I64, indexReg)
	}

	store := memoryStores[uint8(props)]

	insnType := store.insnType
	if insnType == 0 {
		insnType = x.Type
	}

	if x.Storage == val.Imm {
		value := x.ImmValue()
		value32 := int32(value)

		switch {
		case size == 1:
			value32 = int32(int8(value32))

		case size == 2:
			value32 = int32(int16(value32))

		case size == 4 || (value >= -0x80000000 && value < 0x80000000):

		default:
			goto large
		}

		store.insn.opImmToIndirect(&f.Text, insnType, 0, indexReg, baseReg, disp, value32)
		return

	large:
	}

	valueReg, _, own := opBorrowMaybeResultReg(f, x, false)
	if own {
		defer f.Regs.Free(x.Type, valueReg)
	}

	store.insn.opToIndirect(&f.Text, insnType, valueReg, 0, indexReg, baseReg, disp)
}

// opMemoryAddress may return the scratch register as the base.
func opMemoryAddress(f *gen.Func, size uint16, index val.Operand, offset uint32) (baseReg, indexReg reg.R, ownIndexReg bool, disp int32) {
	sizeReach := uint64(size - 1)
	reachOffset := uint64(offset) + sizeReach

	if reachOffset >= 0x80000000 {
		opTrapCall(f, trap.MemoryOutOfBounds)
		return
	}

	alreadyChecked := reachOffset < uint64(index.Bounds.Upper)

	switch index.Storage {
	case val.Imm:
		value := uint64(index.ImmValue())

		if value >= 0x80000000 {
			opTrapCall(f, trap.MemoryOutOfBounds)
			return
		}

		addr := value + uint64(offset)
		reachAddr := addr + sizeReach

		if reachAddr >= 0x80000000 {
			opTrapCall(f, trap.MemoryOutOfBounds)
			return
		}

		if reachAddr < uint64(f.MemoryLimitValues.Initial) || alreadyChecked {
			baseReg = RegMemoryBase
			indexReg = NoIndex
			disp = int32(addr)
			return
		}

		lea.opFromIndirect(&f.Text, abi.I64, RegScratch, 0, NoIndex, RegMemoryBase, int32(reachAddr))

	default:
		r, zeroExt, own := opBorrowMaybeScratchReg(f, index, true)

		if !zeroExt {
			mov.opFromReg(&f.Text, abi.I32, r, r) // zero-extend index
		}

		if alreadyChecked {
			baseReg = RegMemoryBase
			indexReg = r
			ownIndexReg = own
			disp = int32(offset)
			return
		}

		lea.opFromIndirect(&f.Text, abi.I64, RegScratch, 0, r, RegMemoryBase, int32(reachOffset))

		if own {
			f.Regs.Free(abi.I32, r)
		}
	}

	cmp.opFromReg(&f.Text, abi.I64, RegScratch, RegMemoryLimit)

	if addr := f.TrapTrampolineAddr(trap.MemoryOutOfBounds); addr != 0 {
		jge.op(&f.Text, addr)
	} else {
		var checked link.L

		jl.rel8.opStub(&f.Text)
		checked.AddSite(f.Text.Addr)

		opTrapCall(f, trap.MemoryOutOfBounds)

		checked.Addr = f.Text.Addr
		updateLocalBranches(f.M, &checked)
	}

	baseReg = RegScratch
	indexReg = NoIndex
	disp = -int32(sizeReach)
	return
}

func (ISA) OpCurrentMemory(m *module.M) val.Operand {
	mov.opFromReg(&m.Text, abi.I64, RegResult, RegMemoryLimit)
	sub.opFromReg(&m.Text, abi.I64, RegResult, RegMemoryBase)
	shrImm.op(&m.Text, abi.I64, RegResult, wasm.PageBits)

	return val.TempRegOperand(abi.I32, RegResult, true)
}

func (ISA) OpGrowMemory(f *gen.Func, x val.Operand) val.Operand {
	var out link.L
	var fail link.L

	movMMX.opToReg(&f.Text, abi.I64, RegScratch, RegMemoryGrowLimitMMX)

	targetReg, zeroExt := opMaybeResultReg(f, x, false)
	if !zeroExt {
		mov.opFromReg(&f.Text, abi.I32, targetReg, targetReg)
	}

	shlImm.op(&f.Text, abi.I64, targetReg, wasm.PageBits)
	add.opFromReg(&f.Text, abi.I64, targetReg, RegMemoryLimit) // new memory limit
	cmp.opFromReg(&f.Text, abi.I64, targetReg, RegScratch)

	jg.rel8.opStub(&f.Text)
	fail.AddSite(f.Text.Addr)

	mov.opFromReg(&f.Text, abi.I64, RegScratch, RegMemoryLimit)
	mov.opFromReg(&f.Text, abi.I64, RegMemoryLimit, targetReg)
	sub.opFromReg(&f.Text, abi.I64, RegScratch, RegMemoryBase)
	shrImm.op(&f.Text, abi.I64, RegScratch, wasm.PageBits) // value on success
	mov.opFromReg(&f.Text, abi.I32, targetReg, RegScratch)

	jmpRel.rel8.opStub(&f.Text)
	out.AddSite(f.Text.Addr)

	fail.Addr = f.Text.Addr
	updateLocalBranches(f.M, &fail)

	movImm.opImm(&f.Text, abi.I32, targetReg, -1) // value on failure

	out.Addr = f.Text.Addr
	updateLocalBranches(f.M, &out)

	return val.TempRegOperand(abi.I32, targetReg, true)
}

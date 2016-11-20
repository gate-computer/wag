package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/opers"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
	"github.com/tsavola/wag/types"
	"github.com/tsavola/wag/wasm"
)

type memoryAccess struct {
	insn     binaryInsn
	insnType types.T
	zeroExt  bool
}

var memoryLoads = []memoryAccess{
	opers.IndexIntLoad:    {Mov, 0, true},
	opers.IndexIntLoad8S:  {binaryInsn{Movsx8, NoPrefixMIInsn}, 0, false},
	opers.IndexIntLoad8U:  {binaryInsn{Movzx8, NoPrefixMIInsn}, 0, false},
	opers.IndexIntLoad16S: {binaryInsn{Movsx16, NoPrefixMIInsn}, 0, false},
	opers.IndexIntLoad16U: {binaryInsn{Movzx16, NoPrefixMIInsn}, 0, false},
	opers.IndexIntLoad32S: {binaryInsn{Movsxd, NoPrefixMIInsn}, 0, false}, // type is ignored
	opers.IndexIntLoad32U: {Mov, types.I32, true},
	opers.IndexFloatLoad:  {binaryInsn{MovsSSE, NoPrefixMIInsn}, 0, false},
}

var memoryStores = []memoryAccess{
	opers.IndexIntStore:   {Mov, 0, false},
	opers.IndexIntStore8:  {Mov8, types.I32, false},
	opers.IndexIntStore16: {Mov16, types.I32, false},
	opers.IndexIntStore32: {Mov, types.I32, false},
	opers.IndexFloatStore: {binaryInsn{MovsSSE, MovImm}, 0, false}, // integer immediate works
}

// LoadOp makes sure that index gets zero-extended if it's a VarReg operand.
func (mach X86) LoadOp(code gen.RegCoder, oper uint16, index values.Operand, resultType types.T, offset uint32) (result values.Operand) {
	size := oper >> 8

	baseReg, indexReg, ownIndexReg, disp := mach.opMemoryAddress(code, size, index, offset)
	if ownIndexReg {
		defer code.FreeReg(types.I64, indexReg)
	}

	load := memoryLoads[uint8(oper)]

	targetReg, ok := code.TryAllocReg(resultType)
	if !ok {
		targetReg = regResult
	}

	result = values.TempRegOperand(resultType, targetReg, load.zeroExt)

	insnType := load.insnType
	if insnType == 0 {
		insnType = resultType
	}

	load.insn.opFromIndirect(code, insnType, targetReg, 0, indexReg, baseReg, disp)
	return
}

// StoreOp makes sure that index gets zero-extended if it's a VarReg operand.
func (mach X86) StoreOp(code gen.RegCoder, oper uint16, index, x values.Operand, offset uint32) {
	size := oper >> 8

	baseReg, indexReg, ownIndexReg, disp := mach.opMemoryAddress(code, size, index, offset)
	if ownIndexReg {
		defer code.FreeReg(types.I64, indexReg)
	}

	store := memoryStores[uint8(oper)]

	insnType := store.insnType
	if insnType == 0 {
		insnType = x.Type
	}

	if x.Storage == values.Imm {
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

		store.insn.opImmToIndirect(code, insnType, 0, indexReg, baseReg, disp, value32)
		return

	large:
	}

	valueReg, _, own := mach.opBorrowMaybeResultReg(code, x, false)
	if own {
		defer code.FreeReg(x.Type, valueReg)
	}

	store.insn.opToIndirect(code, insnType, valueReg, 0, indexReg, baseReg, disp)
}

// opMemoryAddress may return the scratch register as the base.
func (mach X86) opMemoryAddress(code gen.RegCoder, size uint16, index values.Operand, offset uint32) (baseReg, indexReg regs.R, ownIndexReg bool, disp int32) {
	sizeReach := uint64(size - 1)
	reachOffset := uint64(offset) + sizeReach

	if reachOffset >= 0x80000000 {
		code.OpTrapCall(traps.MemoryOutOfBounds)
		return
	}

	alreadyChecked := reachOffset < uint64(index.Bounds.Upper)

	switch index.Storage {
	case values.Imm:
		value := uint64(index.ImmValue())

		if value >= 0x80000000 {
			code.OpTrapCall(traps.MemoryOutOfBounds)
			return
		}

		addr := value + uint64(offset)
		reachAddr := addr + sizeReach

		if reachAddr >= 0x80000000 {
			code.OpTrapCall(traps.MemoryOutOfBounds)
			return
		}

		if reachAddr < uint64(code.MinMemorySize()) || alreadyChecked {
			baseReg = regMemoryBase
			indexReg = NoIndex
			disp = int32(addr)
			return
		}

		Lea.opFromIndirect(code, types.I64, regScratch, 0, NoIndex, regMemoryBase, int32(reachAddr))

	default:
		reg, zeroExt, own := mach.opBorrowMaybeScratchReg(code, index, true)

		if !zeroExt {
			Mov.opFromReg(code, types.I32, reg, reg) // zero-extend index
		}

		if alreadyChecked {
			baseReg = regMemoryBase
			indexReg = reg
			ownIndexReg = own
			disp = int32(offset)
			return
		}

		Lea.opFromIndirect(code, types.I64, regScratch, 0, reg, regMemoryBase, int32(reachOffset))

		if own {
			code.FreeReg(types.I32, reg)
		}
	}

	Cmp.opFromReg(code, types.I64, regScratch, regMemoryLimit)

	if addr := code.TrapTrampolineAddr(traps.MemoryOutOfBounds); addr != 0 {
		Jge.op(code, addr)
	} else {
		var checked links.L

		Jl.rel8.opStub(code)
		checked.AddSite(code.Len())

		code.OpTrapCall(traps.MemoryOutOfBounds)

		checked.Addr = code.Len()
		mach.updateBranches8(code, &checked)
	}

	baseReg = regScratch
	indexReg = NoIndex
	disp = -int32(sizeReach)
	return
}

func (mach X86) OpCurrentMemory(code gen.RegCoder) values.Operand {
	Mov.opFromReg(code, types.I64, regResult, regMemoryLimit)
	Sub.opFromReg(code, types.I64, regResult, regMemoryBase)
	ShrImm.op(code, types.I64, regResult, wasm.PageBits)

	return values.TempRegOperand(types.I32, regResult, true)
}

func (mach X86) OpGrowMemory(code gen.RegCoder, x values.Operand) values.Operand {
	var out links.L
	var fail links.L

	MovMMX.opToReg(code, types.I64, regScratch, regMemoryGrowLimitMMX)

	targetReg, zeroExt := mach.opMaybeResultReg(code, x, false)
	if !zeroExt {
		Mov.opFromReg(code, types.I32, targetReg, targetReg)
	}

	ShlImm.op(code, types.I64, targetReg, wasm.PageBits)
	Add.opFromReg(code, types.I64, targetReg, regMemoryLimit) // new memory limit
	Cmp.opFromReg(code, types.I64, targetReg, regScratch)

	Jg.rel8.opStub(code)
	fail.AddSite(code.Len())

	Mov.opFromReg(code, types.I64, regScratch, regMemoryLimit)
	Mov.opFromReg(code, types.I64, regMemoryLimit, targetReg)
	Sub.opFromReg(code, types.I64, regScratch, regMemoryBase)
	ShrImm.op(code, types.I64, regScratch, wasm.PageBits) // value on success
	Mov.opFromReg(code, types.I64, targetReg, regScratch)

	JmpRel.rel8.opStub(code)
	out.AddSite(code.Len())

	fail.Addr = code.Len()
	mach.updateBranches8(code, &fail)

	MovImm.opImm(code, types.I32, targetReg, -1) // value on failure

	out.Addr = code.Len()
	mach.updateBranches8(code, &out)

	return values.TempRegOperand(types.I32, targetReg, true)
}

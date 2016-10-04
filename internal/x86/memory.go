package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/traps"
)

type memoryAccess struct {
	truncate int
	zeroExt  bool
	opType   types.T
	insn     binaryInsn
}

type memoryAccesses struct {
	integer map[string]memoryAccess
	float   map[string]memoryAccess
}

func (as memoryAccesses) lookup(t types.T, name string) (a memoryAccess) {
	var found bool

	switch t.Category() {
	case types.Int:
		a, found = as.integer[name]

	case types.Float:
		a, found = as.float[name]

	default:
		panic(t)
	}

	if !found {
		panic(name)
	}
	return
}

var memoryLoads = memoryAccesses{
	integer: map[string]memoryAccess{
		"load":     {0, true, 0, Mov},
		"load8_s":  {1, false, 0, binaryInsn{Movsx8, NoPrefixMIInsn}},
		"load8_u":  {1, false, 0, binaryInsn{Movzx8, NoPrefixMIInsn}},
		"load16_s": {2, false, 0, binaryInsn{Movsx16, NoPrefixMIInsn}},
		"load16_u": {2, false, 0, binaryInsn{Movzx16, NoPrefixMIInsn}},
		"load32_s": {4, false, 0, binaryInsn{Movsxd, NoPrefixMIInsn}}, // type is ignored
		"load32_u": {4, true, types.I32, Mov},
	},
	float: map[string]memoryAccess{
		"load": {0, false, 0, binaryInsn{MovsSSE, NoPrefixMIInsn}},
	},
}

var memoryStores = memoryAccesses{
	integer: map[string]memoryAccess{
		"store":   {0, false, 0, Mov},
		"store8":  {1, false, types.I32, Mov8},
		"store16": {2, false, types.I32, Mov16},
		"store32": {4, false, types.I32, Mov},
	},
	float: map[string]memoryAccess{
		"store": {0, false, 0, binaryInsn{MovsSSE, MovImm}}, // integer immediate instruction will do
	},
}

func (mach X86) LoadOp(code gen.RegCoder, name string, t types.T, x values.Operand, offset int) (result values.Operand, deadend bool) {
	load := memoryLoads.lookup(t, name)

	baseReg, disp, deadend := mach.opMemoryAddress(code, t, x, offset, load.truncate)
	if deadend {
		result = values.ImmOperand(t, 0)
		return
	}

	opType := load.opType
	if opType == 0 {
		opType = t
	}

	load.insn.opFromIndirect(code, opType, regResult, 0, NoIndex, baseReg, disp)
	result = values.TempRegOperand(regResult, load.zeroExt)
	return
}

func (mach X86) StoreOp(code gen.RegCoder, name string, t types.T, a, b values.Operand, offset int) (deadend bool) {
	store := memoryStores.lookup(t, name)

	baseReg, disp, deadend := mach.opMemoryAddress(code, t, a, offset, store.truncate)
	if deadend {
		code.Discard(t, b)
		return
	}

	opType := store.opType
	if opType == 0 {
		opType = t
	}

	if b.Storage == values.Imm {
		value := b.ImmValue(t)

		var bits int
		var ok bool

		switch {
		case store.truncate == 1:
			bits = int(int8(value))
			ok = true

		case store.truncate == 2:
			bits = int(int16(value))
			ok = true

		case store.truncate == 4:
			bits = int(int32(value))
			ok = true

		case value >= -0x80000000 && value < 0x80000000:
			bits = int(value)
			ok = true
		}

		if ok {
			store.insn.opImmToIndirect(code, opType, baseReg, disp, bits)
			return
		}
	}

	valueReg, _, own := mach.opBorrowMaybeResultReg(code, t, b, false)
	if own {
		defer code.FreeReg(t, valueReg)
	}

	store.insn.opToIndirect(code, opType, valueReg, 0, NoIndex, baseReg, disp)
	return
}

// opMemoryAddress may return the scratch register as the base.
func (mach X86) opMemoryAddress(code gen.RegCoder, t types.T, x values.Operand, offset, truncate int) (baseReg regs.R, disp int, deadend bool) {
	var size int
	if truncate != 0 {
		size = truncate
	} else {
		size = int(t.Size())
	}

	var runtimeCheck bool

	if offset < 0 {
		panic("negative offset")
	}

	switch x.Storage {
	case values.Imm:
		addr := x.ImmValue(types.I32) + int64(offset)
		end := addr + int64(size)

		if addr >= 0 && end <= int64(code.MinMemorySize()) {
			// compile-time check only
			baseReg = regMemoryBase
			disp = int(addr)
			return
		}

		if addr >= 0 && end <= 0x80000000 {
			Lea.opFromIndirect(code, types.I64, regScratch, 0, NoIndex, regMemoryBase, int(end))
			runtimeCheck = true
		}

	default:
		reg, zeroExt, own := mach.opBorrowMaybeScratchReg(code, types.I32, x, true)
		if own {
			defer code.FreeReg(types.I32, reg)
		}

		if !zeroExt {
			Mov.opFromReg(code, types.I32, reg, reg)
		}

		end := int64(size) + int64(offset)

		if end <= 0x80000000 {
			Lea.opFromIndirect(code, types.I64, regScratch, 0, reg, regMemoryBase, int(end))
			runtimeCheck = true
		}
	}

	if runtimeCheck {
		Cmp.opFromReg(code, types.I64, regScratch, regMemoryLimit)

		if addr := code.TrapTrampolineAddress(traps.MemoryOutOfBounds); addr != 0 {
			Jg.op(code, addr)
		} else {
			var checked links.L

			Jle.rel8.opStub(code)
			checked.AddSite(code.Len())

			code.OpTrapCall(traps.MemoryOutOfBounds)

			checked.Address = code.Len()
			mach.updateSites8(code, &checked)
		}

		baseReg = regScratch
		disp = -size
	} else {
		code.OpTrapCall(traps.MemoryOutOfBounds)
		deadend = true
	}

	return
}

func (mach X86) OpCurrentMemory(code gen.RegCoder) values.Operand {
	Mov.opFromReg(code, types.I64, regResult, regMemoryLimit)
	Sub.opFromReg(code, types.I64, regResult, regMemoryBase)
	ShrImm.op(code, types.I64, regResult, 16)

	return values.TempRegOperand(regResult, true)
}

func (mach X86) OpGrowMemory(code gen.RegCoder, x values.Operand) values.Operand {
	var out links.L
	var fail links.L

	MovqMMX.opToReg(code, types.I64, regScratch, regMemoryGrowLimitMMX)

	targetReg, zeroExt := mach.opMaybeResultReg(code, types.I32, x, false)
	if !zeroExt {
		Mov.opFromReg(code, types.I32, targetReg, targetReg)
	}

	ShlImm.op(code, types.I64, targetReg, 16)
	Add.opFromReg(code, types.I64, targetReg, regMemoryLimit) // new memory limit
	Cmp.opFromReg(code, types.I64, targetReg, regScratch)

	Jg.rel8.opStub(code)
	fail.AddSite(code.Len())

	Mov.opFromReg(code, types.I64, regScratch, regMemoryLimit)
	Mov.opFromReg(code, types.I64, regMemoryLimit, targetReg)
	Sub.opFromReg(code, types.I64, regScratch, regMemoryBase)
	ShrImm.op(code, types.I64, regScratch, 16) // value on success
	Mov.opFromReg(code, types.I64, targetReg, regScratch)

	JmpRel.rel8.opStub(code)
	out.AddSite(code.Len())

	fail.Address = code.Len()
	mach.updateSites8(code, &fail)

	MovImm.opImm(code, types.I32, targetReg, -1) // value on failure

	out.Address = code.Len()
	mach.updateSites8(code, &out)

	return values.TempRegOperand(targetReg, true)
}

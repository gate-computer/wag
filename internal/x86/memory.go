package x86

import (
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/types"
	"github.com/tsavola/wag/internal/values"
)

type memoryAccess struct {
	truncate int
	zeroExt  bool
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
		"load":     {0, true, Mov},
		"load8_s":  {1, false, binaryInsn{Movsx8, NoImmInst}},
		"load8_u":  {1, false, binaryInsn{Movzx8, NoImmInst}},
		"load16_s": {2, false, binaryInsn{Movsx16, NoImmInst}},
		"load16_u": {2, false, binaryInsn{Movzx16, NoImmInst}},
		"load32_s": {4, false, binaryInsn{Movsxd, NoImmInst}}, // type will be I32
		"load32_u": {4, true, Mov},                            // type will be I32
	},
	float: map[string]memoryAccess{
		"load": {0, false, binaryInsn{MovsSSE, NoImmInst}},
	},
}

var memoryStores = memoryAccesses{
	integer: map[string]memoryAccess{
		"store":   {0, false, Mov},
		"store8":  {1, false, Mov8},
		"store16": {2, false, Mov16},
		"store32": {4, false, Mov}, // type will be I32
	},
	float: map[string]memoryAccess{
		"store": {0, false, binaryInsn{MovsSSE, MovImm}}, // integer immediate instruction will do
	},
}

func (mach X86) LoadOp(code gen.RegCoder, name string, t types.T, x values.Operand) (result values.Operand, deadend bool) {
	load := memoryLoads.lookup(t, name)

	baseReg, disp, deadend := mach.opMemoryAddress(code, t, x, load.truncate)
	if deadend {
		result = values.ImmOperand(t, 0)
		return
	}

	load.insn.opFromIndirect(code, t, regResult, 0, NoIndex, baseReg, disp)
	result = values.TempRegOperand(regResult, load.zeroExt)
	return
}

func (mach X86) StoreOp(code gen.RegCoder, name string, t types.T, a, b values.Operand) (deadend bool) {
	store := memoryStores.lookup(t, name)

	baseReg, disp, deadend := mach.opMemoryAddress(code, t, a, store.truncate)
	if deadend {
		return
	}

	opType := t
	if store.truncate >= 1 && store.truncate <= 4 {
		opType = types.I32 // prevents rexW prefix.  also needed by store32.
	}

	if b.Storage == values.Imm {
		value := b.ImmValue(t)

		var bits int
		var ok bool

		switch {
		case store.truncate == 8:
			bits = int(int8(value))
			ok = true

		case store.truncate == 16:
			bits = int(int16(value))
			ok = true

		case store.truncate == 32:
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

	valueReg, _, own := mach.opBorrowResultReg(code, t, b)
	if own {
		defer code.FreeReg(t, valueReg)
	}

	store.insn.opToIndirect(code, opType, valueReg, 0, NoIndex, baseReg, disp)
	return
}

// opMemoryAddress may return the scratch register as the base.
func (mach X86) opMemoryAddress(code gen.RegCoder, t types.T, x values.Operand, truncate int) (baseReg regs.R, disp int, deadend bool) {
	var size int
	if truncate != 0 {
		size = truncate
	} else {
		size = int(t.Size())
	}

	var after links.L
	var runtimeCheck bool

	switch x.Storage {
	case values.Imm:
		addr := x.ImmValue(types.I32)
		end := addr + int64(size)

		if addr >= 0 && end <= int64(code.MinMemorySize()) {
			// compile-time check only
			baseReg = regMemoryPtr
			disp = int(addr)
			return
		}

		if addr >= 0 && end <= 0x80000000 {
			Lea.opFromIndirect(code, types.I64, regScratch, 0, NoIndex, regMemoryPtr, int(end))
			runtimeCheck = true
		}

	default:
		reg, zeroExt, own := mach.opBorrowScratchReg(code, types.I32, x)
		if own {
			defer code.FreeReg(types.I32, reg)
		}

		if !zeroExt {
			Mov.opFromReg(code, types.I32, reg, reg)
		}

		Lea.opFromIndirect(code, types.I64, regScratch, 0, reg, regMemoryPtr, size)
		runtimeCheck = true
	}

	if runtimeCheck {
		Cmp.opFromReg(code, types.I64, regScratch, regMemoryLimit)
		Jle.rel8.opStub(code)
		after.AddSite(code.Len())

		baseReg = regScratch
		disp = -size
	} else {
		deadend = true
	}

	CallRel.op(code, code.TrapLinks().MemoryOutOfBounds.Address)
	code.AddCallSite(&code.TrapLinks().MemoryOutOfBounds)

	after.SetAddress(code.Len())
	mach.updateSites8(code, &after)
	return
}

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/debug"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/trap"
	"gate.computer/wag/wa"
	"gate.computer/wag/wa/opcode"
	"import.name/pan"
)

// If true, known but unsupported ops will be replaced with breakpoints.
var UnsupportedOpBreakpoint bool

var (
	errUnknownMemory = module.Error("unknown memory")
)

func genOps(f *gen.Func, load *loader.L) {
	if debug.Enabled {
		debug.Printf("{")
		debug.Depth++
	}

	for {
		op := opcode.Opcode(load.Byte())

		if f.DebugMap != nil {
			f.DebugMap.PutInsnAddr(uint32(f.Text.Addr), f.Debugger.SourceAddr(load))
		}
		genBreakpoint(f, load)

		if op == opcode.End {
			break
		}

		genOp(f, load, op)
	}

	if debug.Enabled {
		debug.Depth--
		debug.Printf("}")
	}
}

func genThenOps(f *gen.Func, load *loader.L) (haveElse bool) {
	if debug.Enabled {
		debug.Printf("{")
		debug.Depth++
	}

loop:
	for {
		op := opcode.Opcode(load.Byte())

		if f.DebugMap != nil {
			f.DebugMap.PutInsnAddr(uint32(f.Text.Addr), f.Debugger.SourceAddr(load))
		}
		genBreakpoint(f, load)

		switch op {
		case opcode.End:
			break loop

		case opcode.Else:
			haveElse = true
			break loop
		}

		genOp(f, load, op)
	}

	if debug.Enabled {
		debug.Depth--
		debug.Printf("}")
	}

	return
}

func genBinary(f *gen.Func, load *loader.L, op opcode.Opcode, t wa.Type, props uint64) {
	opStabilizeOperands(f)

	right := popAnyOperand(f, t)
	left := popAnyOperand(f, right.Type)

	opBinary(f, op, left, right, t, props)
}

func genBinaryCommute(f *gen.Func, load *loader.L, op opcode.Opcode, t wa.Type, props uint64) {
	opStabilizeOperands(f)

	right := popAnyOperand(f, t)
	left := popAnyOperand(f, right.Type)

	if left.Storage == storage.Imm {
		left, right = right, left
	}

	opBinary(f, op, left, right, t, props)
}

func opBinary(f *gen.Func, op opcode.Opcode, left, right operand.O, t wa.Type, props uint64) {
	if left.Type != t || right.Type != t {
		pan.Panic(module.Errorf("%s operands have wrong types: %s, %s", op, left.Type, right.Type))
	}

	result := asm.Binary(f, props, left, right)
	pushOperand(f, result)
}

func genConstI32(f *gen.Func, load *loader.L, op opcode.Opcode) {
	opConst(f, wa.I32, uint64(int64(load.Varint32())))
}

func genConstI64(f *gen.Func, load *loader.L, op opcode.Opcode) {
	opConst(f, wa.I64, uint64(load.Varint64()))
}

func genConstF32(f *gen.Func, load *loader.L, op opcode.Opcode) {
	opConst(f, wa.F32, uint64(load.Uint32()))
}

func genConstF64(f *gen.Func, load *loader.L, op opcode.Opcode) {
	opConst(f, wa.F64, load.Uint64())
}

func opConst(f *gen.Func, t wa.Type, value uint64) {
	pushOperand(f, operand.Imm(t, value))
}

func genConvert(f *gen.Func, load *loader.L, op opcode.Opcode, t1, t2 wa.Type, props uint64) {
	x := popOperand(f, t2)

	opStabilizeOperands(f)

	result := asm.Convert(f, props, t1, x)
	pushOperand(f, result)
}

func genLoad(f *gen.Func, load *loader.L, op opcode.Opcode, t wa.Type, maxAlign uint32, props uint64) {
	if !f.Module.Memory {
		pan.Panic(errUnknownMemory)
	}

	index := popOperand(f, wa.I32)

	opStabilizeOperands(f)

	align := load.Varuint32()
	offset := load.Varuint32()

	if align > maxAlign {
		pan.Panic(module.Error("alignment must not be larger than natural"))
	}

	result := asm.Load(f, props, index, t, align, offset)
	pushOperand(f, result)
}

func genStore(f *gen.Func, load *loader.L, op opcode.Opcode, t wa.Type, maxAlign uint32, props uint64) {
	if !f.Module.Memory {
		pan.Panic(errUnknownMemory)
	}

	opStabilizeOperands(f)

	align := load.Varuint32()
	offset := load.Varuint32()

	if align > maxAlign {
		pan.Panic(module.Error("alignment must not be larger than natural"))
	}

	value := popOperand(f, t)
	index := popOperand(f, wa.I32)

	asm.Store(f, props, index, value, align, offset)
}

func genUnary(f *gen.Func, load *loader.L, op opcode.Opcode, t wa.Type, props uint64) {
	x := popOperand(f, t)

	opStabilizeOperands(f)

	result := asm.Unary(f, props, x)
	pushOperand(f, result)
}

func genCurrentMemory(f *gen.Func, load *loader.L, op opcode.Opcode) {
	if !f.Module.Memory {
		pan.Panic(errUnknownMemory)
	}

	opSaveOperands(f)

	if load.Byte() != 0 {
		pan.Panic(module.Errorf("%s: reserved byte is not zero", op))
	}

	f.MapCallAddr(asm.CurrentMemory(f))
	pushResultRegOperand(f, wa.I32)
}

func genDrop(f *gen.Func, load *loader.L, op opcode.Opcode) {
	opDropOperand(f)
}

func genGrowMemory(f *gen.Func, load *loader.L, op opcode.Opcode) {
	if !f.Module.Memory {
		pan.Panic(errUnknownMemory)
	}

	opSaveOperands(f)

	if load.Byte() != 0 {
		pan.Panic(module.Errorf("%s: reserved byte is not zero", op))
	}

	// This is a possible suspension point.  Operands must be on stack, and the
	// size of the following instruction sequence is part of ISA-specific ABI.
	// If the program is restored, the instruction pointer needs the be reset
	// to this point.

	x := popOperand(f, wa.I32)

	if zeroExt := asm.Move(f, reg.Result, x); !zeroExt {
		asm.ZeroExtendResultReg(&f.Prog)
	}

	f.MapCallAddr(asm.GrowMemory(f))
	pushResultRegOperand(f, wa.I32)
}

func genNop(f *gen.Func, load *loader.L, op opcode.Opcode) {
}

func genReturn(f *gen.Func, load *loader.L, op opcode.Opcode) {
	if f.ResultType != wa.Void {
		result := popOperand(f, f.ResultType)
		asm.Move(f, reg.Result, result)
	}

	asm.Return(&f.Prog, f.NumExtra+f.NumLocals+f.StackDepth)
	pushOperand(f, operand.UnreachableSentinel())
	getCurrentBlock(f).Deadend = true
}

func genSelect(f *gen.Func, load *loader.L, op opcode.Opcode) {
	cond := popOperand(f, wa.I32)

	opStabilizeOperands(f)

	right := popAnyOperand(f, wa.I32) // Arbitrary fallback type.
	left := popAnyOperand(f, right.Type)
	if left.Type != right.Type {
		pan.Panic(module.Errorf("%s: operands have inconsistent types: %s, %s", op, left.Type, right.Type))
	}

	result := asm.Select(f, left, right, cond)
	pushOperand(f, result)
}

func genUnreachable(f *gen.Func, load *loader.L, op opcode.Opcode) {
	asm.Trap(f, trap.Unreachable)
	pushOperand(f, operand.UnreachableSentinel())
	getCurrentBlock(f).Deadend = true
}

func genWrap(f *gen.Func, load *loader.L, op opcode.Opcode) {
	x := popOperand(f, wa.I64)

	switch x.Storage {
	case storage.Reg:
		x = operand.Reg(wa.I32, x.Reg())

	default:
		x.Type = wa.I32
	}

	pushOperand(f, x)
}

func badGen(f *gen.Func, load *loader.L, op opcode.Opcode) {
	badOp(load, op)

	if debug.Enabled {
		debug.Printf("unsupported opcode: 0x%02x", byte(op))
	}

	asm.Trap(f, trap.Breakpoint)
	pushOperand(f, operand.UnreachableSentinel())
	getCurrentBlock(f).Deadend = true
}

func badOp(load *loader.L, op opcode.Opcode) {
	if opcode.Exists(byte(op)) {
		pan.Panic(module.Errorf("unexpected opcode: %s", op))
	}

	if UnsupportedOpBreakpoint {
		switch op {
		case 0xc0, 0xc1, 0xc2, 0xc3, 0xc4: // Sign-extension.
			return

		case 0xd0, 0xd1, 0xd2: // Reference types.
			return

		case 0xfc: // Miscellaneous operations.
			switch op := load.Varuint32(); op {
			case 0, 1, 2, 3, 4, 5, 6, 7: // Non-trapping float-to-int conversion.
				return

			case 0x0b: // Bulk memory operations: memory.fill
				load.Byte()
				return
			case 0x0a, 0x0e: // Bulk memory operations: memory.copy, table.copy
				load.Byte()
				load.Byte()
				return
			case 0x09, 0x0d: // Bulk memory operations: data.drop, elem.drop
				load.Varuint32()
				return
			case 0x08, 0x0c: // Bulk memory operations: memory.init, table.init
				load.Varuint32()
				load.Byte()
				return

			default:
				pan.Panic(module.Errorf("unknown opcode: 0xfc 0x%02x", op))
			}
		}
	}

	pan.Panic(module.Errorf("unknown opcode: 0x%02x", byte(op)))
}

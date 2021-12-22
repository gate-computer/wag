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
)

// If true, known but unsupported ops will be replaced with breakpoints.
var UnsupportedOpBreakpoint bool

func genOps(f *gen.Func, load *loader.L) (deadend bool) {
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

		deadend = genOp(f, load, op)
		if deadend {
			skipOps(f, load)
			break
		}
	}

	if debug.Enabled {
		debug.Depth--
		debug.Printf("}")
	}
	return
}

func genThenOps(f *gen.Func, load *loader.L) (deadend, haveElse bool) {
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

		deadend = genOp(f, load, op)
		if deadend {
			haveElse = skipThenOps(f, load)
			break loop
		}
	}

	if debug.Enabled {
		debug.Depth--
		debug.Printf("}")
	}
	return
}

func genOp(f *gen.Func, load *loader.L, op opcode.Opcode) (deadend bool) {
	if debug.Enabled {
		debug.Printf("%s op", op)
		debug.Depth++
	}

	impl := opcodeImpls[op]
	deadend = impl.gen(f, load, op, impl.info)

	if debug.Enabled {
		debug.Depth--
		if deadend {
			debug.Printf("%s operated to deadend", op)
		} else {
			debug.Printf("%s operated", op)
		}
	}

	return
}

func genBinary(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opStabilizeOperands(f)

	right := popAnyOperand(f)
	left := popAnyOperand(f)

	opBinary(f, op, left, right, info)
	return
}

func genBinaryCommute(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opStabilizeOperands(f)

	right := popAnyOperand(f)
	left := popAnyOperand(f)

	if left.Storage == storage.Imm {
		left, right = right, left
	}

	opBinary(f, op, left, right, info)
	return
}

func opBinary(f *gen.Func, op opcode.Opcode, left, right operand.O, info opInfo) {
	if t := info.primaryType(); left.Type != t || right.Type != t {
		panic(module.Errorf("%s operands have wrong types: %s, %s", op, left.Type, right.Type))
	}

	result := asm.Binary(f, info.props(), left, right)
	pushOperand(f, result)
}

func genConstI32(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opConst(f, wa.I32, uint64(int64(load.Varint32())))
	return
}

func genConstI64(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opConst(f, wa.I64, uint64(load.Varint64()))
	return
}

func genConstF32(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opConst(f, wa.F32, uint64(load.Uint32()))
	return
}

func genConstF64(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opConst(f, wa.F64, load.Uint64())
	return
}

func opConst(f *gen.Func, t wa.Type, value uint64) {
	pushOperand(f, operand.Imm(t, value))
}

func genConvert(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	x := popOperand(f, info.secondaryType())

	opStabilizeOperands(f)

	result := asm.Convert(f, info.props(), info.primaryType(), x)
	pushOperand(f, result)
	return
}

func genLoad(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	index := popOperand(f, wa.I32)

	opStabilizeOperands(f)

	align := load.Varuint32()
	offset := load.Varuint32()

	result := asm.Load(f, info.props(), index, info.primaryType(), align, offset)
	pushOperand(f, result)
	return
}

func genStore(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opStabilizeOperands(f)

	align := load.Varuint32()
	offset := load.Varuint32()

	value := popOperand(f, info.primaryType())
	index := popOperand(f, wa.I32)

	asm.Store(f, info.props(), index, value, align, offset)
	return
}

func genUnary(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	x := popOperand(f, info.primaryType())

	opStabilizeOperands(f)

	result := asm.Unary(f, info.props(), x)
	pushOperand(f, result)
	return
}

func genCurrentMemory(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opSaveOperands(f)

	if load.Byte() != 0 {
		panic(module.Errorf("%s: reserved byte is not zero", op))
	}

	f.MapCallAddr(asm.CurrentMemory(f))
	pushResultRegOperand(f, wa.I32)
	return
}

func genDrop(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opDropOperand(f)
	return
}

func genGrowMemory(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opSaveOperands(f)

	if load.Byte() != 0 {
		panic(module.Errorf("%s: reserved byte is not zero", op))
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
	return
}

func genNop(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	return
}

func genReturn(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	if f.ResultType != wa.Void {
		result := popOperand(f, f.ResultType)
		asm.Move(f, reg.Result, result)
	}

	asm.Return(&f.Prog, f.NumExtra+f.NumLocals+f.StackDepth)
	deadend = true
	return
}

func genSelect(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	cond := popOperand(f, wa.I32)

	opStabilizeOperands(f)

	right := popAnyOperand(f)
	left := popAnyOperand(f)
	if left.Type != right.Type {
		panic(module.Errorf("%s: operands have inconsistent types: %s, %s", op, left.Type, right.Type))
	}

	result := asm.Select(f, left, right, cond)
	pushOperand(f, result)
	return
}

func genUnreachable(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	asm.Trap(f, trap.Unreachable)
	deadend = true
	return
}

func genWrap(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	x := popOperand(f, wa.I64)

	switch x.Storage {
	case storage.Reg:
		x = operand.Reg(wa.I32, x.Reg())

	default:
		x.Type = wa.I32
	}

	pushOperand(f, x)
	return
}

func badGen(f *gen.Func, load *loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	badOp(load, op)

	if debug.Enabled {
		debug.Printf("unsupported opcode: 0x%02x", byte(op))
	}

	asm.Trap(f, trap.Breakpoint)
	deadend = true
	return
}

func badOp(load *loader.L, op opcode.Opcode) {
	if opcode.Exists(byte(op)) {
		panic(module.Errorf("unexpected opcode: %s", op))
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
				panic(module.Errorf("unknown opcode: 0xfc 0x%02x", op))
			}
		}
	}

	panic(module.Errorf("unknown opcode: 0x%02x", byte(op)))
}

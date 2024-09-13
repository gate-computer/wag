// Copyright (c) 2024 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/debug"
	"gate.computer/wag/internal/isa/prop"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/wa"
	"gate.computer/wag/wa/opcode"
	"import.name/pan"
)

func genOp(f *gen.Func, load *loader.L, op opcode.Opcode) {
	if debug.Enabled {
		debug.Printf("%s op", op)
		debug.Depth++
	}

	switch op {
	case opcode.Unreachable:
		genUnreachable(f, load, op)
	case opcode.Nop:
		genNop(f, load, op)
	case opcode.Block:
		genBlock(f, load, op)
	case opcode.Loop:
		genLoop(f, load, op)
	case opcode.If:
		genIf(f, load, op)
	case opcode.Else:
		pan.Panic(module.Errorf("unexpected opcode: %s", op))
	case opcode.End:
		panic(op)
	case opcode.Br:
		genBr(f, load, op)
	case opcode.BrIf:
		genBrIf(f, load, op)
	case opcode.BrTable:
		genBrTable(f, load, op)
	case opcode.Return:
		genReturn(f, load, op)
	case opcode.Call:
		genCall(f, load, op)
	case opcode.CallIndirect:
		genCallIndirect(f, load, op)
	case opcode.Drop:
		genDrop(f, load, op)
	case opcode.Select:
		genSelect(f, load, op)
	case opcode.GetLocal:
		genGetLocal(f, load, op)
	case opcode.SetLocal:
		genSetLocal(f, load, op)
	case opcode.TeeLocal:
		genTeeLocal(f, load, op)
	case opcode.GetGlobal:
		genGetGlobal(f, load, op)
	case opcode.SetGlobal:
		genSetGlobal(f, load, op)
	case opcode.I32Load:
		genLoad(f, load, op, wa.I32, 2, uint64(prop.I32Load))
	case opcode.I64Load:
		genLoad(f, load, op, wa.I64, 3, uint64(prop.I64Load))
	case opcode.F32Load:
		genLoad(f, load, op, wa.F32, 2, uint64(prop.F32Load))
	case opcode.F64Load:
		genLoad(f, load, op, wa.F64, 3, uint64(prop.F64Load))
	case opcode.I32Load8S:
		genLoad(f, load, op, wa.I32, 0, uint64(prop.I32Load8S))
	case opcode.I32Load8U:
		genLoad(f, load, op, wa.I32, 0, uint64(prop.I32Load8U))
	case opcode.I32Load16S:
		genLoad(f, load, op, wa.I32, 1, uint64(prop.I32Load16S))
	case opcode.I32Load16U:
		genLoad(f, load, op, wa.I32, 1, uint64(prop.I32Load16U))
	case opcode.I64Load8S:
		genLoad(f, load, op, wa.I64, 0, uint64(prop.I64Load8S))
	case opcode.I64Load8U:
		genLoad(f, load, op, wa.I64, 0, uint64(prop.I64Load8U))
	case opcode.I64Load16S:
		genLoad(f, load, op, wa.I64, 1, uint64(prop.I64Load16S))
	case opcode.I64Load16U:
		genLoad(f, load, op, wa.I64, 1, uint64(prop.I64Load16U))
	case opcode.I64Load32S:
		genLoad(f, load, op, wa.I64, 2, uint64(prop.I64Load32S))
	case opcode.I64Load32U:
		genLoad(f, load, op, wa.I64, 2, uint64(prop.I64Load32U))
	case opcode.I32Store:
		genStore(f, load, op, wa.I32, 2, uint64(prop.I32Store))
	case opcode.I64Store:
		genStore(f, load, op, wa.I64, 3, uint64(prop.I64Store))
	case opcode.F32Store:
		genStore(f, load, op, wa.F32, 2, uint64(prop.F32Store))
	case opcode.F64Store:
		genStore(f, load, op, wa.F64, 3, uint64(prop.F64Store))
	case opcode.I32Store8:
		genStore(f, load, op, wa.I32, 0, uint64(prop.I32Store8))
	case opcode.I32Store16:
		genStore(f, load, op, wa.I32, 1, uint64(prop.I32Store16))
	case opcode.I64Store8:
		genStore(f, load, op, wa.I64, 0, uint64(prop.I64Store8))
	case opcode.I64Store16:
		genStore(f, load, op, wa.I64, 1, uint64(prop.I64Store16))
	case opcode.I64Store32:
		genStore(f, load, op, wa.I64, 2, uint64(prop.I64Store32))
	case opcode.CurrentMemory:
		genCurrentMemory(f, load, op)
	case opcode.GrowMemory:
		genGrowMemory(f, load, op)
	case opcode.I32Const:
		genConstI32(f, load, op)
	case opcode.I64Const:
		genConstI64(f, load, op)
	case opcode.F32Const:
		genConstF32(f, load, op)
	case opcode.F64Const:
		genConstF64(f, load, op)
	case opcode.I32Eqz:
		genUnary(f, load, op, wa.I32, uint64(prop.IntEqz))
	case opcode.I32Eq:
		genBinaryCommute(f, load, op, wa.I32, uint64(prop.IntEq))
	case opcode.I32Ne:
		genBinaryCommute(f, load, op, wa.I32, uint64(prop.IntNe))
	case opcode.I32LtS:
		genBinary(f, load, op, wa.I32, uint64(prop.IntLtS))
	case opcode.I32LtU:
		genBinary(f, load, op, wa.I32, uint64(prop.IntLtU))
	case opcode.I32GtS:
		genBinary(f, load, op, wa.I32, uint64(prop.IntGtS))
	case opcode.I32GtU:
		genBinary(f, load, op, wa.I32, uint64(prop.IntGtU))
	case opcode.I32LeS:
		genBinary(f, load, op, wa.I32, uint64(prop.IntLeS))
	case opcode.I32LeU:
		genBinary(f, load, op, wa.I32, uint64(prop.IntLeU))
	case opcode.I32GeS:
		genBinary(f, load, op, wa.I32, uint64(prop.IntGeS))
	case opcode.I32GeU:
		genBinary(f, load, op, wa.I32, uint64(prop.IntGeU))
	case opcode.I64Eqz:
		genUnary(f, load, op, wa.I64, uint64(prop.IntEqz))
	case opcode.I64Eq:
		genBinaryCommute(f, load, op, wa.I64, uint64(prop.IntEq))
	case opcode.I64Ne:
		genBinaryCommute(f, load, op, wa.I64, uint64(prop.IntNe))
	case opcode.I64LtS:
		genBinary(f, load, op, wa.I64, uint64(prop.IntLtS))
	case opcode.I64LtU:
		genBinary(f, load, op, wa.I64, uint64(prop.IntLtU))
	case opcode.I64GtS:
		genBinary(f, load, op, wa.I64, uint64(prop.IntGtS))
	case opcode.I64GtU:
		genBinary(f, load, op, wa.I64, uint64(prop.IntGtU))
	case opcode.I64LeS:
		genBinary(f, load, op, wa.I64, uint64(prop.IntLeS))
	case opcode.I64LeU:
		genBinary(f, load, op, wa.I64, uint64(prop.IntLeU))
	case opcode.I64GeS:
		genBinary(f, load, op, wa.I64, uint64(prop.IntGeS))
	case opcode.I64GeU:
		genBinary(f, load, op, wa.I64, uint64(prop.IntGeU))
	case opcode.F32Eq:
		genBinaryCommute(f, load, op, wa.F32, uint64(prop.FloatEq))
	case opcode.F32Ne:
		genBinaryCommute(f, load, op, wa.F32, uint64(prop.FloatNe))
	case opcode.F32Lt:
		genBinary(f, load, op, wa.F32, uint64(prop.FloatLt))
	case opcode.F32Gt:
		genBinary(f, load, op, wa.F32, uint64(prop.FloatGt))
	case opcode.F32Le:
		genBinary(f, load, op, wa.F32, uint64(prop.FloatLe))
	case opcode.F32Ge:
		genBinary(f, load, op, wa.F32, uint64(prop.FloatGe))
	case opcode.F64Eq:
		genBinaryCommute(f, load, op, wa.F64, uint64(prop.FloatEq))
	case opcode.F64Ne:
		genBinaryCommute(f, load, op, wa.F64, uint64(prop.FloatNe))
	case opcode.F64Lt:
		genBinary(f, load, op, wa.F64, uint64(prop.FloatLt))
	case opcode.F64Gt:
		genBinary(f, load, op, wa.F64, uint64(prop.FloatGt))
	case opcode.F64Le:
		genBinary(f, load, op, wa.F64, uint64(prop.FloatLe))
	case opcode.F64Ge:
		genBinary(f, load, op, wa.F64, uint64(prop.FloatGe))
	case opcode.I32Clz:
		genUnary(f, load, op, wa.I32, uint64(prop.IntClz))
	case opcode.I32Ctz:
		genUnary(f, load, op, wa.I32, uint64(prop.IntCtz))
	case opcode.I32Popcnt:
		genUnary(f, load, op, wa.I32, uint64(prop.IntPopcnt))
	case opcode.I32Add:
		genBinaryCommute(f, load, op, wa.I32, uint64(prop.IntAdd))
	case opcode.I32Sub:
		genBinary(f, load, op, wa.I32, uint64(prop.IntSub))
	case opcode.I32Mul:
		genBinaryCommute(f, load, op, wa.I32, uint64(prop.IntMul))
	case opcode.I32DivS:
		genBinary(f, load, op, wa.I32, uint64(prop.IntDivS))
	case opcode.I32DivU:
		genBinary(f, load, op, wa.I32, uint64(prop.IntDivU))
	case opcode.I32RemS:
		genBinary(f, load, op, wa.I32, uint64(prop.IntRemS))
	case opcode.I32RemU:
		genBinary(f, load, op, wa.I32, uint64(prop.IntRemU))
	case opcode.I32And:
		genBinaryCommute(f, load, op, wa.I32, uint64(prop.IntAnd))
	case opcode.I32Or:
		genBinaryCommute(f, load, op, wa.I32, uint64(prop.IntOr))
	case opcode.I32Xor:
		genBinaryCommute(f, load, op, wa.I32, uint64(prop.IntXor))
	case opcode.I32Shl:
		genBinary(f, load, op, wa.I32, uint64(prop.IntShl))
	case opcode.I32ShrS:
		genBinary(f, load, op, wa.I32, uint64(prop.IntShrS))
	case opcode.I32ShrU:
		genBinary(f, load, op, wa.I32, uint64(prop.IntShrU))
	case opcode.I32Rotl:
		genBinary(f, load, op, wa.I32, uint64(prop.IntRotl))
	case opcode.I32Rotr:
		genBinary(f, load, op, wa.I32, uint64(prop.IntRotr))
	case opcode.I64Clz:
		genUnary(f, load, op, wa.I64, uint64(prop.IntClz))
	case opcode.I64Ctz:
		genUnary(f, load, op, wa.I64, uint64(prop.IntCtz))
	case opcode.I64Popcnt:
		genUnary(f, load, op, wa.I64, uint64(prop.IntPopcnt))
	case opcode.I64Add:
		genBinaryCommute(f, load, op, wa.I64, uint64(prop.IntAdd))
	case opcode.I64Sub:
		genBinary(f, load, op, wa.I64, uint64(prop.IntSub))
	case opcode.I64Mul:
		genBinaryCommute(f, load, op, wa.I64, uint64(prop.IntMul))
	case opcode.I64DivS:
		genBinary(f, load, op, wa.I64, uint64(prop.IntDivS))
	case opcode.I64DivU:
		genBinary(f, load, op, wa.I64, uint64(prop.IntDivU))
	case opcode.I64RemS:
		genBinary(f, load, op, wa.I64, uint64(prop.IntRemS))
	case opcode.I64RemU:
		genBinary(f, load, op, wa.I64, uint64(prop.IntRemU))
	case opcode.I64And:
		genBinaryCommute(f, load, op, wa.I64, uint64(prop.IntAnd))
	case opcode.I64Or:
		genBinaryCommute(f, load, op, wa.I64, uint64(prop.IntOr))
	case opcode.I64Xor:
		genBinaryCommute(f, load, op, wa.I64, uint64(prop.IntXor))
	case opcode.I64Shl:
		genBinary(f, load, op, wa.I64, uint64(prop.IntShl))
	case opcode.I64ShrS:
		genBinary(f, load, op, wa.I64, uint64(prop.IntShrS))
	case opcode.I64ShrU:
		genBinary(f, load, op, wa.I64, uint64(prop.IntShrU))
	case opcode.I64Rotl:
		genBinary(f, load, op, wa.I64, uint64(prop.IntRotl))
	case opcode.I64Rotr:
		genBinary(f, load, op, wa.I64, uint64(prop.IntRotr))
	case opcode.F32Abs:
		genUnary(f, load, op, wa.F32, uint64(prop.FloatAbs))
	case opcode.F32Neg:
		genUnary(f, load, op, wa.F32, uint64(prop.FloatNeg))
	case opcode.F32Ceil:
		genUnary(f, load, op, wa.F32, uint64(prop.FloatCeil))
	case opcode.F32Floor:
		genUnary(f, load, op, wa.F32, uint64(prop.FloatFloor))
	case opcode.F32Trunc:
		genUnary(f, load, op, wa.F32, uint64(prop.FloatTrunc))
	case opcode.F32Nearest:
		genUnary(f, load, op, wa.F32, uint64(prop.FloatNearest))
	case opcode.F32Sqrt:
		genUnary(f, load, op, wa.F32, uint64(prop.FloatSqrt))
	case opcode.F32Add:
		genBinaryCommute(f, load, op, wa.F32, uint64(prop.FloatAdd))
	case opcode.F32Sub:
		genBinary(f, load, op, wa.F32, uint64(prop.FloatSub))
	case opcode.F32Mul:
		genBinaryCommute(f, load, op, wa.F32, uint64(prop.FloatMul))
	case opcode.F32Div:
		genBinary(f, load, op, wa.F32, uint64(prop.FloatDiv))
	case opcode.F32Min:
		genBinaryCommute(f, load, op, wa.F32, uint64(prop.FloatMin))
	case opcode.F32Max:
		genBinaryCommute(f, load, op, wa.F32, uint64(prop.FloatMax))
	case opcode.F32Copysign:
		genBinary(f, load, op, wa.F32, uint64(prop.FloatCopysign))
	case opcode.F64Abs:
		genUnary(f, load, op, wa.F64, uint64(prop.FloatAbs))
	case opcode.F64Neg:
		genUnary(f, load, op, wa.F64, uint64(prop.FloatNeg))
	case opcode.F64Ceil:
		genUnary(f, load, op, wa.F64, uint64(prop.FloatCeil))
	case opcode.F64Floor:
		genUnary(f, load, op, wa.F64, uint64(prop.FloatFloor))
	case opcode.F64Trunc:
		genUnary(f, load, op, wa.F64, uint64(prop.FloatTrunc))
	case opcode.F64Nearest:
		genUnary(f, load, op, wa.F64, uint64(prop.FloatNearest))
	case opcode.F64Sqrt:
		genUnary(f, load, op, wa.F64, uint64(prop.FloatSqrt))
	case opcode.F64Add:
		genBinaryCommute(f, load, op, wa.F64, uint64(prop.FloatAdd))
	case opcode.F64Sub:
		genBinary(f, load, op, wa.F64, uint64(prop.FloatSub))
	case opcode.F64Mul:
		genBinaryCommute(f, load, op, wa.F64, uint64(prop.FloatMul))
	case opcode.F64Div:
		genBinary(f, load, op, wa.F64, uint64(prop.FloatDiv))
	case opcode.F64Min:
		genBinaryCommute(f, load, op, wa.F64, uint64(prop.FloatMin))
	case opcode.F64Max:
		genBinaryCommute(f, load, op, wa.F64, uint64(prop.FloatMax))
	case opcode.F64Copysign:
		genBinary(f, load, op, wa.F64, uint64(prop.FloatCopysign))
	case opcode.I32WrapI64:
		genWrap(f, load, op)
	case opcode.I32TruncSF32:
		genConvert(f, load, op, wa.I32, wa.F32, uint64(prop.TruncS))
	case opcode.I32TruncUF32:
		genConvert(f, load, op, wa.I32, wa.F32, uint64(prop.TruncU))
	case opcode.I32TruncSF64:
		genConvert(f, load, op, wa.I32, wa.F64, uint64(prop.TruncS))
	case opcode.I32TruncUF64:
		genConvert(f, load, op, wa.I32, wa.F64, uint64(prop.TruncU))
	case opcode.I64ExtendSI32:
		genConvert(f, load, op, wa.I64, wa.I32, uint64(prop.ExtendS))
	case opcode.I64ExtendUI32:
		genConvert(f, load, op, wa.I64, wa.I32, uint64(prop.ExtendU))
	case opcode.I64TruncSF32:
		genConvert(f, load, op, wa.I64, wa.F32, uint64(prop.TruncS))
	case opcode.I64TruncUF32:
		genConvert(f, load, op, wa.I64, wa.F32, uint64(prop.TruncU))
	case opcode.I64TruncSF64:
		genConvert(f, load, op, wa.I64, wa.F64, uint64(prop.TruncS))
	case opcode.I64TruncUF64:
		genConvert(f, load, op, wa.I64, wa.F64, uint64(prop.TruncU))
	case opcode.F32ConvertSI32:
		genConvert(f, load, op, wa.F32, wa.I32, uint64(prop.ConvertS))
	case opcode.F32ConvertUI32:
		genConvert(f, load, op, wa.F32, wa.I32, uint64(prop.ConvertU))
	case opcode.F32ConvertSI64:
		genConvert(f, load, op, wa.F32, wa.I64, uint64(prop.ConvertS))
	case opcode.F32ConvertUI64:
		genConvert(f, load, op, wa.F32, wa.I64, uint64(prop.ConvertU))
	case opcode.F32DemoteF64:
		genConvert(f, load, op, wa.F32, wa.F64, uint64(prop.Demote))
	case opcode.F64ConvertSI32:
		genConvert(f, load, op, wa.F64, wa.I32, uint64(prop.ConvertS))
	case opcode.F64ConvertUI32:
		genConvert(f, load, op, wa.F64, wa.I32, uint64(prop.ConvertU))
	case opcode.F64ConvertSI64:
		genConvert(f, load, op, wa.F64, wa.I64, uint64(prop.ConvertS))
	case opcode.F64ConvertUI64:
		genConvert(f, load, op, wa.F64, wa.I64, uint64(prop.ConvertU))
	case opcode.F64PromoteF32:
		genConvert(f, load, op, wa.F64, wa.F32, uint64(prop.Promote))
	case opcode.I32ReinterpretF32:
		genConvert(f, load, op, wa.I32, wa.F32, uint64(prop.ReinterpretFloat))
	case opcode.I64ReinterpretF64:
		genConvert(f, load, op, wa.I64, wa.F64, uint64(prop.ReinterpretFloat))
	case opcode.F32ReinterpretI32:
		genConvert(f, load, op, wa.F32, wa.I32, uint64(prop.ReinterpretInt))
	case opcode.F64ReinterpretI64:
		genConvert(f, load, op, wa.F64, wa.I64, uint64(prop.ReinterpretInt))
	case 0xc0, 0xc1, 0xc2, 0xc3, 0xc4: // Sign-extension.
		genUnsupported(f, load, op)
	case 0xd0, 0xd1, 0xd2: // Reference types.
		genUnsupported(f, load, op)
	case opcode.MiscPrefix:
		switch op := opcode.MiscOpcode(load.Varuint32()); op {
		case opcode.I32TruncSatSF32:
			genTruncSat(f, load, op, wa.I32, wa.F32, prop.TruncS)
		case opcode.I32TruncSatUF32:
			genTruncSat(f, load, op, wa.I32, wa.F32, prop.TruncU)
		case opcode.I32TruncSatSF64:
			genTruncSat(f, load, op, wa.I32, wa.F64, prop.TruncS)
		case opcode.I32TruncSatUF64:
			genTruncSat(f, load, op, wa.I32, wa.F64, prop.TruncU)
		case opcode.I64TruncSatSF32:
			genTruncSat(f, load, op, wa.I64, wa.F32, prop.TruncS)
		case opcode.I64TruncSatUF32:
			genTruncSat(f, load, op, wa.I64, wa.F32, prop.TruncU)
		case opcode.I64TruncSatSF64:
			genTruncSat(f, load, op, wa.I64, wa.F64, prop.TruncS)
		case opcode.I64TruncSatUF64:
			genTruncSat(f, load, op, wa.I64, wa.F64, prop.TruncU)
		case opcode.MemoryCopy:
			genMemoryCopy(f, load, op)
		case opcode.MemoryFill:
			genMemoryFill(f, load, op)
		case 0x0e: // Bulk memory operations: memory.copy, table.copy
			load.Byte()
			load.Byte()
			genUnsupportedMisc(f, load, op)
		case 0x09, 0x0d: // Bulk memory operations: data.drop, elem.drop
			load.Varuint32()
			genUnsupportedMisc(f, load, op)
		case 0x08, 0x0c: // Bulk memory operations: memory.init, table.init
			load.Varuint32()
			load.Byte()
			genUnsupportedMisc(f, load, op)
		default:
			pan.Panic(module.Errorf("unknown opcode: 0x%02x 0x%02x", byte(opcode.MiscPrefix), uint32(op)))
		}
	default:
		pan.Panic(module.Errorf("unknown opcode: 0x%02x", byte(op)))
	}

	if debug.Enabled {
		debug.Depth--
		debug.Printf("%s operated", op)
	}
}

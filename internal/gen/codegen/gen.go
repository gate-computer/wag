// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/val"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/trap"
)

func genOps(f *gen.Func, load loader.L) (deadend bool) {
	if debug {
		debugf("{")
		debugDepth++
	}

	for {
		op := Opcode(load.Byte())

		if op == OpcodeEnd {
			break
		}

		deadend = genOp(f, load, op)
		if deadend {
			skipOps(load)
			break
		}
	}

	if debug {
		debugDepth--
		debugf("}")
	}
	return
}

func genThenOps(f *gen.Func, load loader.L) (deadend, haveElse bool) {
	if debug {
		debugf("{")
		debugDepth++
	}

loop:
	for {
		op := Opcode(load.Byte())

		switch op {
		case OpcodeEnd:
			break loop

		case OpcodeElse:
			haveElse = true
			break loop
		}

		deadend = genOp(f, load, op)
		if deadend {
			haveElse = skipThenOps(load)
			break loop
		}
	}

	if debug {
		debugDepth--
		debugf("}")
	}
	return
}

func genOp(f *gen.Func, load loader.L, op Opcode) (deadend bool) {
	if debug {
		debugf("%s op", op)
		debugDepth++
	}

	f.Map.PutInsnAddr(f.Text.Addr)

	impl := opcodeImpls[op]
	deadend = impl.gen(f, load, op, impl.info)

	if debug {
		debugDepth--
		if deadend {
			debugf("%s operated to deadend", op)
		} else {
			debugf("%s operated", op)
		}
	}

	return
}

func genBinaryConditionOp(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	opStackCheck(f) // before we create ConditionFlags operand
	return genBinaryOp(f, load, op, info)
}

func genBinaryOp(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	right := opMaterializeOperand(f, popOperand(f))
	left := opMaterializeOperand(f, popOperand(f))

	binaryOp(f, op, left, right, info)
	return
}

func genBinaryConditionCommuteOp(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	opStackCheck(f) // before we create ConditionFlags operand
	return genBinaryCommuteOp(f, load, op, info)
}

func genBinaryCommuteOp(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	right := opMaterializeOperand(f, popOperand(f))
	left := opMaterializeOperand(f, popOperand(f))

	if left.Storage == val.Imm {
		left, right = right, left
	}

	binaryOp(f, op, left, right, info)
	return
}

func binaryOp(f *gen.Func, op Opcode, left, right val.Operand, info opInfo) {
	if t := info.primaryType(); left.Type != t || right.Type != t {
		panic(fmt.Errorf("%s operands have wrong types: %s, %s", op, left.Type, right.Type))
	}

	opStabilizeOperandStack(f)
	result := asm.OpBinary(f, info.props(), left, right)
	pushOperand(f, result)
}

func genConstI32(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	pushImmOperand(f, abi.I32, uint64(int64(load.Varint32())))
	return
}

func genConstI64(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	pushImmOperand(f, abi.I64, uint64(load.Varint64()))
	return
}

func genConstF32(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	pushImmOperand(f, abi.F32, uint64(load.Uint32()))
	return
}

func genConstF64(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	pushImmOperand(f, abi.F64, load.Uint64())
	return
}

func genConversionOp(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	x := opMaterializeOperand(f, popOperand(f))
	if x.Type != info.secondaryType() {
		panic(fmt.Errorf("%s operand has wrong type: %s", op, x.Type))
	}

	opStabilizeOperandStack(f)
	result := asm.Convert(f, info.props(), info.primaryType(), x)
	pushOperand(f, result)
	return
}

func genLoadOp(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	virtualIndex := popOperand(f)
	if virtualIndex.Type != abi.I32 {
		panic(fmt.Errorf("%s index has wrong type: %s", op, virtualIndex.Type))
	}

	index := opMaterializeOperand(f, virtualIndex)

	load.Varuint32() // flags
	offset := load.Varuint32()

	opStabilizeOperandStack(f)
	result := asm.Load(f, info.props(), index, info.primaryType(), offset)
	updateMemoryIndex(f, virtualIndex, offset, info.props())
	pushOperand(f, result)
	return
}

func genStoreOp(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	value := opMaterializeOperand(f, popOperand(f))
	if value.Type != info.primaryType() {
		panic(fmt.Errorf("%s value has wrong type: %s", op, value.Type))
	}

	virtualIndex := opMaterializeOperand(f, popOperand(f))
	if virtualIndex.Type != abi.I32 {
		panic(fmt.Errorf("%s index has wrong type: %s", op, virtualIndex.Type))
	}

	index := opMaterializeOperand(f, virtualIndex)

	load.Varuint32() // flags
	offset := load.Varuint32()

	opStabilizeOperandStack(f)
	asm.Store(f, info.props(), index, value, offset)
	updateMemoryIndex(f, virtualIndex, offset, info.props())
	return
}

func genUnaryConditionOp(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	opStackCheck(f) // before we create ConditionFlags operand
	return genUnaryOp(f, load, op, info)
}

func genUnaryOp(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	x := opMaterializeOperand(f, popOperand(f))
	if x.Type != info.primaryType() {
		panic(fmt.Errorf("%s operand has wrong type: %s", op, x.Type))
	}

	opStabilizeOperandStack(f)
	result := asm.OpUnary(f, info.props(), x)
	pushOperand(f, result)
	return
}

func genCurrentMemory(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	load.Byte() // reserved

	opStabilizeOperandStack(f)
	result := asm.QueryMemorySize(f.M)
	pushOperand(f, result)
	return
}

func genDrop(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	discard(f, popOperand(f))
	return
}

func genGrowMemory(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	load.Byte() // reserved

	x := opMaterializeOperand(f, popOperand(f))
	if x.Type != abi.I32 {
		panic(fmt.Errorf("%s operand has wrong type: %s", op, x.Type))
	}

	opStabilizeOperandStack(f)
	result := asm.GrowMemory(f, x)
	pushOperand(f, result)
	return
}

func genNop(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	return
}

func genReturn(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	if f.ResultType != abi.Void {
		result := popOperand(f)
		if result.Type != f.ResultType {
			panic(fmt.Errorf("%s value operand type is %s, but function result type is %s", op, result.Type, f.ResultType))
		}
		opMove(f, reg.Result, result, false)
	}

	asm.AddStackPtrImm(f.M, f.StackOffset)
	asm.Return(f.M)
	deadend = true
	return
}

func genSelect(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	cond := opPreloadOperand(f, popOperand(f))
	if cond.Type != abi.I32 {
		panic(fmt.Errorf("%s: condition operand has wrong type: %s", op, cond.Type))
	}

	right := opMaterializeOperand(f, popOperand(f))
	left := opMaterializeOperand(f, popOperand(f))
	if left.Type != right.Type {
		panic(fmt.Errorf("%s: operands have inconsistent types: %s, %s", op, left.Type, right.Type))
	}

	result := asm.Select(f, left, right, cond)
	pushOperand(f, result)
	return
}

func genUnreachable(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	asm.Trap(f, trap.Unreachable)
	deadend = true
	return
}

func badGen(f *gen.Func, load loader.L, op Opcode, info opInfo) (deadend bool) {
	badOp(op)
	return
}

func badOp(op Opcode) {
	if s := opcodeStrings[op]; s != "" {
		panic(fmt.Errorf("unexpected opcode: %s", s))
	} else {
		panic(fmt.Errorf("invalid opcode: 0x%02x", byte(op)))
	}
}

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"fmt"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/values"
	"github.com/tsavola/wag/meta"
	"github.com/tsavola/wag/trap"
)

func genOps(f *function, load loader.L) (deadend bool) {
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

func genThenOps(f *function, load loader.L) (deadend, haveElse bool) {
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

func genOp(f *function, load loader.L, op Opcode) (deadend bool) {
	if debug {
		debugf("%s op", op)
		debugDepth++
	}

	f.insnMap.PutInsn(meta.TextAddr(f.Pos()))

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

func genBinaryConditionOp(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	opStackCheck(f) // before we create ConditionFlags operand
	return genBinaryOp(f, load, op, info)
}

func genBinaryOp(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	right := opMaterializeOperand(f, popOperand(f))
	left := opMaterializeOperand(f, popOperand(f))

	binaryOp(f, op, left, right, info)
	return
}

func genBinaryConditionCommuteOp(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	opStackCheck(f) // before we create ConditionFlags operand
	return genBinaryCommuteOp(f, load, op, info)
}

func genBinaryCommuteOp(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	right := opMaterializeOperand(f, popOperand(f))
	left := opMaterializeOperand(f, popOperand(f))

	if left.Storage == values.Imm {
		left, right = right, left
	}

	binaryOp(f, op, left, right, info)
	return
}

func binaryOp(f *function, op Opcode, left, right values.Operand, info opInfo) {
	if t := info.primaryType(); left.Type != t || right.Type != t {
		panic(fmt.Errorf("%s operands have wrong types: %s, %s", op, left.Type, right.Type))
	}

	opStabilizeOperandStack(f)
	result := isa.BinaryOp(f, info.oper(), left, right)
	pushOperand(f, result)
}

func genConstI32(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	pushImmOperand(f, abi.I32, uint64(int64(load.Varint32())))
	return
}

func genConstI64(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	pushImmOperand(f, abi.I64, uint64(load.Varint64()))
	return
}

func genConstF32(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	pushImmOperand(f, abi.F32, uint64(load.Uint32()))
	return
}

func genConstF64(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	pushImmOperand(f, abi.F64, load.Uint64())
	return
}

func genConversionOp(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	x := opMaterializeOperand(f, popOperand(f))
	if x.Type != info.secondaryType() {
		panic(fmt.Errorf("%s operand has wrong type: %s", op, x.Type))
	}

	opStabilizeOperandStack(f)
	result := isa.ConversionOp(f, info.oper(), info.primaryType(), x)
	pushOperand(f, result)
	return
}

func genLoadOp(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	virtualIndex := popOperand(f)
	if virtualIndex.Type != abi.I32 {
		panic(fmt.Errorf("%s index has wrong type: %s", op, virtualIndex.Type))
	}

	index := opMaterializeOperand(f, virtualIndex)

	load.Varuint32() // flags
	offset := load.Varuint32()

	opStabilizeOperandStack(f)
	result := isa.LoadOp(f, info.oper(), index, info.primaryType(), offset)
	updateMemoryIndex(f, virtualIndex, offset, info.oper())
	pushOperand(f, result)
	return
}

func genStoreOp(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
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
	isa.StoreOp(f, info.oper(), index, value, offset)
	updateMemoryIndex(f, virtualIndex, offset, info.oper())
	return
}

func genUnaryConditionOp(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	opStackCheck(f) // before we create ConditionFlags operand
	return genUnaryOp(f, load, op, info)
}

func genUnaryOp(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	x := opMaterializeOperand(f, popOperand(f))
	if x.Type != info.primaryType() {
		panic(fmt.Errorf("%s operand has wrong type: %s", op, x.Type))
	}

	opStabilizeOperandStack(f)
	result := isa.UnaryOp(f, info.oper(), x)
	pushOperand(f, result)
	return
}

func genCurrentMemory(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	load.Byte() // reserved

	opStabilizeOperandStack(f)
	result := isa.OpCurrentMemory(f)
	pushOperand(f, result)
	return
}

func genDrop(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	discard(f, popOperand(f))
	return
}

func genGrowMemory(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	load.Byte() // reserved

	x := opMaterializeOperand(f, popOperand(f))
	if x.Type != abi.I32 {
		panic(fmt.Errorf("%s operand has wrong type: %s", op, x.Type))
	}

	opStabilizeOperandStack(f)
	result := isa.OpGrowMemory(f, x)
	pushOperand(f, result)
	return
}

func genNop(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	return
}

func genReturn(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	if f.resultType != abi.Void {
		result := popOperand(f)
		if result.Type != f.resultType {
			panic(fmt.Errorf("%s value operand type is %s, but function result type is %s", op, result.Type, f.resultType))
		}
		opMove(f, regs.Result, result, false)
	}

	isa.OpAddImmToStackPtr(f, f.stackOffset)
	isa.OpReturn(f)
	deadend = true
	return
}

func genSelect(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	cond := opPreloadOperand(f, popOperand(f))
	if cond.Type != abi.I32 {
		panic(fmt.Errorf("%s: condition operand has wrong type: %s", op, cond.Type))
	}

	right := opMaterializeOperand(f, popOperand(f))
	left := opMaterializeOperand(f, popOperand(f))
	if left.Type != right.Type {
		panic(fmt.Errorf("%s: operands have inconsistent types: %s, %s", op, left.Type, right.Type))
	}

	result := isa.OpSelect(f, left, right, cond)
	pushOperand(f, result)
	return
}

func genUnreachable(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	opTrapCall(f, trap.Unreachable)
	deadend = true
	return
}

func badGen(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
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

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"errors"
	"fmt"

	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/gen/debug"
	"github.com/tsavola/wag/internal/gen/link"
	"github.com/tsavola/wag/internal/gen/operand"
	"github.com/tsavola/wag/internal/gen/reg"
	"github.com/tsavola/wag/internal/gen/storage"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/opcode"
	"github.com/tsavola/wag/internal/typedecode"
	"github.com/tsavola/wag/wa"
)

func stealDeadBlockOperandReg(f *gen.Func, t wa.Type) (r reg.R) {
	cat := t.Category()

	for i := len(f.Operands) - 1; i >= f.FrameBase; i-- {
		x := &f.Operands[i]

		if x.Storage == storage.Reg && x.Type.Category() == cat && x.Reg() != reg.Result {
			debug.Printf("steal operand #%d register: %s", i, *x)

			r = x.Reg()
			x.SetPlaceholder()
			return
		}
	}

	panic("suitable allocated register operand not found during robbery")
}

// allocStealDeadReg may take current block's operand's register without
// spilling it to stack.  It can only be used in a deadend situation.
func allocStealDeadReg(f *gen.Func, t wa.Type) (r reg.R) {
	r = f.Regs.AllocResult(t)
	if r == reg.Result {
		r = stealDeadBlockOperandReg(f, t)
	}
	return
}

func pushBranchTarget(f *gen.Func, valueType wa.Type, funcEnd bool) {
	f.BranchTargets = append(f.BranchTargets, &gen.BranchTarget{
		StackDepth: f.StackDepth,
		ValueType:  valueType,
		FuncEnd:    funcEnd,
	})
}

func popBranchTarget(f *gen.Func) (finalizedLabel *link.L) {
	n := len(f.BranchTargets) - 1
	finalizedLabel = &f.BranchTargets[n].Label
	f.BranchTargets = f.BranchTargets[:n]
	return
}

func getBranchTarget(f *gen.Func, depth uint32) *gen.BranchTarget {
	if depth >= uint32(len(f.BranchTargets)) {
		panic(fmt.Errorf("relative branch depth out of bounds: %d", depth))
	}
	return f.BranchTargets[len(f.BranchTargets)-int(depth)-1]
}

// getCurrentBlock can be called only if there certainly are branch targets,
// e.g. after successfully calling getBranchTarget.
func getCurrentBlock(f *gen.Func) *gen.Block {
	return &f.BranchTargets[len(f.BranchTargets)-1].Block
}

func label(f *gen.Func, l *link.L) {
	debug.Printf("label")
	l.Addr = f.Text.Addr
}

func genBlock(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) bool {
	opSaveOperands(f)

	blockType := typedecode.Block(load.Varint7())

	pushBranchTarget(f, blockType, false) // end

	debug.Printf("type: %s", blockType)
	debug.Printf("operands: %d", len(f.Operands))
	debug.Printf("stack depth: %d", f.StackDepth)

	frame := beginFrame(f)
	deadend := genOps(f, load)

	if blockType != wa.Void {
		result := popBlockResultOperand(f, blockType, deadend)
		opMoveResult(f, result, deadend)
		debug.Printf("result: %s", result)
	}

	debug.Printf("operands: %d", len(f.Operands))
	debug.Printf("stack depth: %d", f.StackDepth)

	truncateBlockOperands(f)
	frame.end(f)
	pushResultRegOperand(f, blockType)

	end := popBranchTarget(f)
	label(f, end)
	isa.UpdateFarBranches(f.Text.Bytes(), end)

	return false
}

func genBr(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	relativeDepth := load.Varuint32()
	target := getBranchTarget(f, relativeDepth)

	if target.ValueType != wa.Void {
		value := popOperand(f, target.ValueType)
		asm.Move(f, reg.Result, value)
		debug.Printf("value: %s", value)
	}

	debug.Printf("operands: %d", len(f.Operands))
	debug.Printf("stack depth: %d", f.StackDepth)
	debug.Printf("target stack depth: %d", target.StackDepth)

	if target.FuncEnd {
		asm.Return(&f.Prog, f.NumLocals+f.StackDepth)
	} else {
		asm.DropStackValues(&f.Prog, f.StackDepth-target.StackDepth)

		if b := getCurrentBlock(f); target.Label.Addr != 0 && !b.Suspension {
			debug.Printf("loop")
			asm.TrapIfLoopSuspendedElse(f, target.Label.Addr)
			b.Suspension = true
		}

		opBranch(f, &target.Label)
	}

	deadend = true
	return
}

func genBrIf(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	relativeDepth := load.Varuint32()
	target := getBranchTarget(f, relativeDepth)

	cond := popOperand(f, wa.I32)

	if target.ValueType != wa.Void {
		value := popOperand(f, target.ValueType)
		debug.Printf("value: %s", value)

		if cond.Storage == storage.Reg && cond.Reg() == reg.Result {
			r := opAllocReg(f, wa.I32)
			asm.MoveReg(&f.Prog, wa.I32, r, reg.Result)
			cond.SetReg(r)
		}
		asm.Move(f, reg.Result, value)
	}

	drop := f.StackDepth - target.StackDepth

	if target.Label.Addr == 0 || getCurrentBlock(f).Suspension {
		asm.DropStackValues(&f.Prog, drop)

		retAddrs := asm.BranchIfStub(f, cond, true, false)
		target.Label.AddSites(retAddrs)

		asm.DropStackValues(&f.Prog, -drop)
	} else {
		debug.Printf("suspension")

		if target.ValueType != wa.Void {
			panic("backward branch with value")
		}

		retAddrs := asm.BranchIfStub(f, cond, false, true)

		asm.DropStackValues(&f.Prog, drop)
		asm.TrapIfLoopSuspendedElse(f, target.Label.Addr)
		asm.Branch(&f.Prog, target.Label.Addr)

		isa.UpdateNearBranches(f.Text.Bytes(), retAddrs)

		getCurrentBlock(f).Suspension = true
	}

	pushResultRegOperand(f, target.ValueType)

	return
}

func genBrTable(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	targetCount := load.Varuint32()
	if targetCount >= uint32(MaxBranchTableSize) {
		panic(fmt.Errorf("%s has too many targets: %d", op, targetCount))
	}

	targetTable := make([]*gen.BranchTarget, targetCount)

	for i := range targetTable {
		relativeDepth := load.Varuint32()
		targetTable[i] = getBranchTarget(f, relativeDepth)
	}

	relativeDepth := load.Varuint32()
	defaultTarget := getBranchTarget(f, relativeDepth)

	index := popOperand(f, wa.I32)
	debug.Printf("index: %s", index)

	loop := (defaultTarget.Label.Addr != 0)
	commonStackDepth := defaultTarget.StackDepth
	tableType := wa.I32

	for i, target := range targetTable {
		if debug.Enabled {
			if i < 10 {
				debug.Printf("target #%d stack depth: %d", i, target.StackDepth)
			} else if i == 10 {
				debug.Printf("...")
			}
		}

		if target.Label.Addr != 0 {
			loop = true
		}

		if target.StackDepth != commonStackDepth {
			commonStackDepth = -1
			tableType = wa.I64 // need space for target-specific operand counts
		}

		if target.ValueType != defaultTarget.ValueType {
			panic(fmt.Errorf("%s targets have inconsistent value types: %s (default target) vs. %s (target #%d)", op, defaultTarget.ValueType, target.ValueType, i))
		}
	}

	debug.Printf("operands: %d", len(f.Operands))
	debug.Printf("stack depth: %d", f.StackDepth)
	debug.Printf("default target stack depth: %d", defaultTarget.StackDepth)
	debug.Printf("common target stack depth: %d", commonStackDepth)
	debug.Printf("table element type: %s", tableType)
	debug.Printf("loop: %v", loop)

	var value operand.O
	if defaultTarget.ValueType != wa.Void {
		value = popOperand(f, defaultTarget.ValueType)
		debug.Printf("value: %s", value)
	}

	if value.Type != wa.Void {
		if index.Storage == storage.Reg && index.Reg() == reg.Result {
			indexReg := allocStealDeadReg(f, wa.I32)
			asm.MoveReg(&f.Prog, wa.I32, indexReg, reg.Result)
			index.SetReg(indexReg)
		}
		asm.Move(f, reg.Result, value)
	}

	var r reg.R
	if index.Storage == storage.Reg {
		r = index.Reg()
	} else {
		r = allocStealDeadReg(f, wa.I32)
		asm.Move(f, r, index)
	}

	defaultDrop := f.StackDepth - defaultTarget.StackDepth
	debug.Printf("drop values from physical stack for default target: %d", defaultDrop)
	asm.DropStackValues(&f.Prog, defaultDrop)

	if b := getCurrentBlock(f); loop && !b.Suspension {
		if value.Type != wa.Void {
			panic("backward branch with value")
		}
		asm.TrapIfLoopSuspendedSaveInt(f, r)
		b.Suspension = true
	}

	opBranchIfOutOfBounds(f, r, int32(len(targetTable)), &defaultTarget.Label)
	loadInsnAddr := asm.LoadIntStubNear(f, tableType, r)

	if tableType == wa.I32 {
		drop := defaultTarget.StackDepth - commonStackDepth
		debug.Printf("drop values from physical stack for dynamic target: %d", drop)
		asm.DropStackValues(&f.Prog, drop)
	} else {
		debug.Printf("drop values from physical stack for dynamic target")
		indexOnly := allocStealDeadReg(f, wa.I32)
		asm.MoveReg(&f.Prog, wa.I32, indexOnly, r)
		asm.AddToStackPtrUpper32(f, r)
		r = indexOnly
	}

	asm.BranchIndirect(f, r)
	deadend = true

	isa.AlignData(&f.Prog, int(tableType.Size()))
	isa.UpdateNearLoad(f.Text.Bytes(), loadInsnAddr)
	tableAddr := f.Text.Addr
	tableSize := len(targetTable) * int(tableType.Size())
	f.Text.Extend(tableSize)
	f.Map.PutDataBlock(tableAddr, tableSize)

	table := gen.BranchTable{
		Addr:    tableAddr,
		Targets: targetTable,
	}
	if tableType == wa.I32 {
		// Common operand count
		table.StackDepth = -1
	} else {
		// Target-specific operand counts
		table.StackDepth = defaultTarget.StackDepth
	}
	f.BranchTables = append(f.BranchTables, table)
	return
}

func genIf(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) bool {
	ifType := typedecode.Block(load.Varint7())

	debug.Printf("type: %s", ifType)
	debug.Printf("operands: %d", len(f.Operands))
	debug.Printf("stack depth: %d", f.StackDepth)

	cond := popOperand(f, wa.I32)

	opSaveOperands(f)

	pushBranchTarget(f, ifType, false) // end
	var afterThen link.L

	retAddrs := asm.BranchIfStub(f, cond, false, false)
	afterThen.AddSites(retAddrs)

	frame := beginFrame(f)
	thenDeadend, haveElse := genThenOps(f, load)

	if ifType != wa.Void && !haveElse {
		panic(errors.New("if without else has result type"))
	}

	if ifType != wa.Void {
		result := popBlockResultOperand(f, ifType, thenDeadend)
		opMoveResult(f, result, thenDeadend)
		debug.Printf("result: %s", result)
	}

	debug.Printf("operands: %d", len(f.Operands))
	debug.Printf("stack depth: %d", f.StackDepth)

	truncateBlockOperands(f)

	if haveElse && !thenDeadend {
		opBranch(f, &getBranchTarget(f, 0).Label) // end
	}

	label(f, &afterThen)
	isa.UpdateFarBranches(f.Text.Bytes(), &afterThen)

	if haveElse {
		elseDeadend := genOps(f, load)

		if ifType != wa.Void {
			result := popBlockResultOperand(f, ifType, elseDeadend)
			opMoveResult(f, result, elseDeadend)
			debug.Printf("result: %s", result)
		}

		debug.Printf("operands: %d", len(f.Operands))
		debug.Printf("stack depth: %d", f.StackDepth)

		truncateBlockOperands(f)
	}

	frame.end(f)
	pushResultRegOperand(f, ifType)

	end := popBranchTarget(f)
	label(f, end)
	isa.UpdateFarBranches(f.Text.Bytes(), end)

	return false
}

func genLoop(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opSaveOperands(f)

	blockType := typedecode.Block(load.Varint7())

	pushBranchTarget(f, wa.Void, false) // begin
	label(f, &getBranchTarget(f, 0).Label)

	debug.Printf("type: %s", blockType)
	debug.Printf("operands: %d", len(f.Operands))
	debug.Printf("stack depth: %d", f.StackDepth)

	frame := beginFrame(f)
	deadend = genOps(f, load)

	var result operand.O
	if blockType != wa.Void {
		result = popBlockResultOperand(f, blockType, deadend)
		debug.Printf("result: %s", result)
	}

	debug.Printf("operands: %d", len(f.Operands))
	debug.Printf("stack depth: %d", f.StackDepth)

	truncateBlockOperands(f)
	frame.end(f)
	if blockType != wa.Void {
		pushOperand(f, result)
	}

	popBranchTarget(f) // no need to update branch addresses

	return
}

func opBranch(f *gen.Func, l *link.L) {
	retAddr := asm.Branch(&f.Prog, l.Addr)
	if l.Addr == 0 {
		l.AddSite(retAddr)
	}
}

func opBranchIfOutOfBounds(f *gen.Func, indexReg reg.R, upperBound int32, l *link.L) {
	site := asm.BranchIfOutOfBounds(&f.Prog, indexReg, upperBound, l.Addr)
	if l.Addr == 0 {
		l.AddSite(site)
	}
}

// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"gate.computer/wag/internal/gen"
	"gate.computer/wag/internal/gen/debug"
	"gate.computer/wag/internal/gen/link"
	"gate.computer/wag/internal/gen/operand"
	"gate.computer/wag/internal/gen/reg"
	"gate.computer/wag/internal/gen/storage"
	"gate.computer/wag/internal/loader"
	"gate.computer/wag/internal/module"
	"gate.computer/wag/internal/typedecode"
	"gate.computer/wag/wa"
	"gate.computer/wag/wa/opcode"
	errors "golang.org/x/xerrors"
)

var (
	errIfResultType    = module.Error("if without else has result type")
	errBranchLoopValue = module.Error("looping branch with return value")
)

func stealDeadBlockOperandReg(f *gen.Func, t wa.Type) (r reg.R) {
	cat := t.Category()

	for i := len(f.Operands) - 1; i >= f.FrameBase; i-- {
		x := &f.Operands[i]

		if x.Storage == storage.Reg && x.Type.Category() == cat && x.Reg() != reg.Result {
			if debug.Enabled {
				debug.Printf("steal operand #%d register: %s", i, *x)
			}

			r = x.Reg()
			x.SetPlaceholder()
			return
		}
	}

	panic(errors.New("suitable allocated register operand not found during robbery"))
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
		panic(module.Errorf("relative branch depth out of bounds: %d", depth))
	}
	return f.BranchTargets[len(f.BranchTargets)-int(depth)-1]
}

// getCurrentBlock can be called only if there certainly are branch targets,
// e.g. after successfully calling getBranchTarget.
func getCurrentBlock(f *gen.Func) *gen.Block {
	return &f.BranchTargets[len(f.BranchTargets)-1].Block
}

func label(f *gen.Func, l *link.L) {
	if debug.Enabled {
		debug.Printf("label")
	}

	l.Addr = f.Text.Addr
}

func genBlock(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) bool {
	opSaveOperands(f)

	blockType := typedecode.Block(load.Varint7())

	pushBranchTarget(f, blockType, false) // end

	if debug.Enabled {
		debug.Printf("type: %s", blockType)
		debug.Printf("operands: %d", len(f.Operands))
		debug.Printf("stack depth: %d", f.StackDepth)
	}

	frame := beginFrame(f)
	deadend := genOps(f, load)

	if blockType != wa.Void {
		result := popBlockResultOperand(f, blockType, deadend)
		opMoveResult(f, result, deadend)

		if debug.Enabled {
			debug.Printf("result: %s", result)
		}
	}

	if debug.Enabled {
		debug.Printf("operands: %d", len(f.Operands))
		debug.Printf("stack depth: %d", f.StackDepth)
	}

	opTruncateBlockOperands(f)
	frame.end(f)
	pushResultRegOperand(f, blockType)

	end := popBranchTarget(f)
	label(f, end)
	linker.UpdateFarBranches(f.Text.Bytes(), end)

	return false
}

func genBr(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	relativeDepth := load.Varuint32()
	target := getBranchTarget(f, relativeDepth)

	if target.ValueType != wa.Void {
		value := popOperand(f, target.ValueType)
		asm.Move(f, reg.Result, value)

		if debug.Enabled {
			debug.Printf("value: %s", value)
		}
	}

	if debug.Enabled {
		debug.Printf("operands: %d", len(f.Operands))
		debug.Printf("stack depth: %d", f.StackDepth)
		debug.Printf("target stack depth: %d", target.StackDepth)
	}

	if target.FuncEnd {
		asm.Return(&f.Prog, f.NumExtra+f.NumLocals+f.StackDepth)
	} else {
		if drop := f.StackDepth - target.StackDepth; drop != 0 {
			asm.DropStackValues(&f.Prog, drop)
		}

		if b := getCurrentBlock(f); target.Label.Addr != 0 && !b.Suspension && f.ImportContext == nil {
			asm.BranchSuspend(f, target.Label.Addr)
			b.Suspension = true
		} else {
			opBranch(f, &target.Label)
		}
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

		if debug.Enabled {
			debug.Printf("value: %s", value)
		}

		if cond.Storage == storage.Reg && cond.Reg() == reg.Result {
			r, _ := opAllocReg(f, wa.I32)
			asm.MoveReg(&f.Prog, wa.I32, r, reg.Result)
			cond.SetReg(r)
		}
		asm.Move(f, reg.Result, value)
	}

	drop := f.StackDepth - target.StackDepth

	if forward := target.Label.Addr == 0; forward || getCurrentBlock(f).Suspension || f.ImportContext != nil {
		if drop == 0 {
			opBranchIf(f, cond, &target.Label)
		} else {
			retAddrs := asm.BranchIfStub(f, cond, false, true)

			asm.DropStackValues(&f.Prog, drop)
			opBranch(f, &target.Label)

			linker.UpdateNearBranches(f.Text.Bytes(), retAddrs)
		}
	} else {
		if debug.Enabled {
			debug.Printf("suspension")
		}

		if target.ValueType != wa.Void {
			panic(errBranchLoopValue)
		}

		retAddrs := asm.BranchIfStub(f, cond, false, true)

		if drop != 0 {
			asm.DropStackValues(&f.Prog, drop)
		}
		asm.BranchSuspend(f, target.Label.Addr)

		linker.UpdateNearBranches(f.Text.Bytes(), retAddrs)

		getCurrentBlock(f).Suspension = true
	}

	pushResultRegOperand(f, target.ValueType)

	return
}

func genBrTable(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	targetCount := load.Varuint32()
	if targetCount >= uint32(MaxBranchTableLen) {
		panic(module.Errorf("branch table target count is too large: %d", targetCount))
	}

	targetTable := make([]*gen.BranchTarget, targetCount)

	for i := range targetTable {
		relativeDepth := load.Varuint32()
		targetTable[i] = getBranchTarget(f, relativeDepth)
	}

	relativeDepth := load.Varuint32()
	defaultTarget := getBranchTarget(f, relativeDepth)

	index := popOperand(f, wa.I32)

	if debug.Enabled {
		debug.Printf("index: %s", index)
	}

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
			panic(module.Errorf("%s targets have inconsistent value types: %s (default target) vs. %s (target #%d)", op, defaultTarget.ValueType, target.ValueType, i))
		}
	}

	if debug.Enabled {
		debug.Printf("operands: %d", len(f.Operands))
		debug.Printf("stack depth: %d", f.StackDepth)
		debug.Printf("default target stack depth: %d", defaultTarget.StackDepth)
		debug.Printf("common target stack depth: %d", commonStackDepth)
		debug.Printf("table element type: %s", tableType)
		debug.Printf("loop: %v", loop)
	}

	var value operand.O
	if defaultTarget.ValueType != wa.Void {
		value = popOperand(f, defaultTarget.ValueType)

		if debug.Enabled {
			debug.Printf("value: %s", value)
		}
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

	if debug.Enabled {
		debug.Printf("drop values from physical stack for default target: %d", defaultDrop)
	}

	if defaultDrop != 0 {
		asm.DropStackValues(&f.Prog, defaultDrop)
	}

	if b := getCurrentBlock(f); loop && !b.Suspension && f.ImportContext == nil {
		if value.Type != wa.Void {
			panic(errBranchLoopValue)
		}
		opReserveStackEntry(f)
		asm.SuspendSaveInt(f, r)
		opReleaseStackEntry(f)
		b.Suspension = true
	}

	opBranchIfOutOfBounds(f, r, int32(len(targetTable)), &defaultTarget.Label)
	loadInsnAddr := asm.LoadIntStubNear(f, tableType, r)

	if tableType == wa.I32 {
		drop := defaultTarget.StackDepth - commonStackDepth

		if debug.Enabled {
			debug.Printf("drop values from physical stack for dynamic target: %d", drop)
		}

		if drop != 0 {
			asm.DropStackValues(&f.Prog, drop)
		}
	} else {
		if debug.Enabled {
			debug.Printf("drop values from physical stack for dynamic target")
		}

		indexOnly := allocStealDeadReg(f, wa.I32)
		asm.MoveReg(&f.Prog, wa.I32, indexOnly, r)
		asm.AddToStackPtrUpper32(f, r)
		r = indexOnly
	}

	asm.BranchIndirect(f, r)
	deadend = true

	asm.AlignData(&f.Prog, int(tableType.Size()))
	linker.UpdateNearLoad(f.Text.Bytes(), loadInsnAddr)
	tableAddr := f.Text.Addr
	tableSize := len(targetTable) * int(tableType.Size())
	f.Text.Extend(tableSize)
	if f.DebugMap != nil {
		f.DebugMap.PutDataBlock(uint32(tableAddr), int32(tableSize))
	}

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

	if debug.Enabled {
		debug.Printf("type: %s", ifType)
		debug.Printf("operands: %d", len(f.Operands))
		debug.Printf("stack depth: %d", f.StackDepth)
	}

	cond := popOperand(f, wa.I32)

	opSaveOperands(f)

	pushBranchTarget(f, ifType, false) // end
	var afterThen link.L

	retAddrs := asm.BranchIfStub(f, cond, false, false)
	afterThen.AddSites(retAddrs)

	frame := beginFrame(f)
	thenDeadend, haveElse := genThenOps(f, load)

	if ifType != wa.Void && !haveElse {
		panic(errIfResultType)
	}

	if ifType != wa.Void {
		result := popBlockResultOperand(f, ifType, thenDeadend)
		opMoveResult(f, result, thenDeadend)

		if debug.Enabled {
			debug.Printf("result: %s", result)
		}
	}

	if debug.Enabled {
		debug.Printf("operands: %d", len(f.Operands))
		debug.Printf("stack depth: %d", f.StackDepth)
	}

	opTruncateBlockOperands(f)

	if haveElse && !thenDeadend {
		opBranch(f, &getBranchTarget(f, 0).Label) // end
	}

	label(f, &afterThen)
	linker.UpdateFarBranches(f.Text.Bytes(), &afterThen)

	if haveElse {
		elseDeadend := genOps(f, load)

		if ifType != wa.Void {
			result := popBlockResultOperand(f, ifType, elseDeadend)
			opMoveResult(f, result, elseDeadend)

			if debug.Enabled {
				debug.Printf("result: %s", result)
			}
		}

		if debug.Enabled {
			debug.Printf("operands: %d", len(f.Operands))
			debug.Printf("stack depth: %d", f.StackDepth)
		}

		opTruncateBlockOperands(f)
	}

	frame.end(f)
	pushResultRegOperand(f, ifType)

	end := popBranchTarget(f)
	label(f, end)
	linker.UpdateFarBranches(f.Text.Bytes(), end)

	return false
}

func genLoop(f *gen.Func, load loader.L, op opcode.Opcode, info opInfo) (deadend bool) {
	opSaveOperands(f)

	blockType := typedecode.Block(load.Varint7())

	pushBranchTarget(f, wa.Void, false) // begin
	label(f, &getBranchTarget(f, 0).Label)

	if debug.Enabled {
		debug.Printf("type: %s", blockType)
		debug.Printf("operands: %d", len(f.Operands))
		debug.Printf("stack depth: %d", f.StackDepth)
	}

	frame := beginFrame(f)
	deadend = genOps(f, load)

	var result operand.O
	if blockType != wa.Void {
		result = popBlockResultOperand(f, blockType, deadend)

		if debug.Enabled {
			debug.Printf("result: %s", result)
		}
	}

	if debug.Enabled {
		debug.Printf("operands: %d", len(f.Operands))
		debug.Printf("stack depth: %d", f.StackDepth)
	}

	opTruncateBlockOperands(f)
	frame.end(f)
	if blockType != wa.Void {
		pushOperand(f, result)
	}

	popBranchTarget(f) // no need to update branch addresses

	return
}

func opBranch(f *gen.Func, l *link.L) {
	if l.Addr != 0 {
		asm.Branch(&f.Prog, l.Addr)
	} else {
		l.AddSite(asm.BranchStub(&f.Prog))
	}
}

func opBranchIf(f *gen.Func, cond operand.O, l *link.L) {
	if l.Addr != 0 {
		asm.BranchIf(f, cond, l.Addr)
	} else {
		l.AddSites(asm.BranchIfStub(f, cond, true, false))
	}
}

func opBranchIfOutOfBounds(f *gen.Func, indexReg reg.R, upperBound int32, l *link.L) {
	if l.Addr != 0 {
		asm.BranchIfOutOfBounds(&f.Prog, indexReg, upperBound, l.Addr)
	} else {
		l.AddSite(asm.BranchIfOutOfBoundsStub(&f.Prog, indexReg, upperBound))
	}
}

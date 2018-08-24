// Copyright (c) 2016 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codegen

import (
	"errors"
	"fmt"

	"github.com/tsavola/wag/abi"
	"github.com/tsavola/wag/internal/gen"
	"github.com/tsavola/wag/internal/links"
	"github.com/tsavola/wag/internal/loader"
	"github.com/tsavola/wag/internal/regs"
	"github.com/tsavola/wag/internal/typeutil"
	"github.com/tsavola/wag/internal/values"
)

type branchTarget struct {
	label       links.L
	stackOffset int32
	valueType   abi.Type
	funcEnd     bool
}

type branchTable struct {
	roDataAddr      int32
	targets         []*branchTarget
	codeStackOffset int32 // -1 indicates common offset
}

func pushBranchTarget(f *function, valueType abi.Type, funcEnd bool) {
	stackOffset := f.stackOffset

	if int(f.numInitedVars) < len(f.vars) {
		// init still in progress, but any branch expressions will have
		// initialized all vars before we reach the target
		numRegParams := int32(len(f.vars)) - f.numStackParams
		stackOffset = numRegParams * gen.WordSize
	}

	f.branchTargets = append(f.branchTargets, &branchTarget{
		stackOffset: stackOffset,
		valueType:   valueType,
		funcEnd:     funcEnd,
	})
}

func popBranchTarget(f *function) (finalizedLabel *links.L) {
	n := len(f.branchTargets) - 1
	finalizedLabel = &f.branchTargets[n].label
	f.branchTargets = f.branchTargets[:n]

	trimBoundsStacks(f)
	return
}

func getBranchTarget(f *function, depth uint32) *branchTarget {
	if depth >= uint32(len(f.branchTargets)) {
		panic(fmt.Errorf("relative branch depth out of bounds: %d", depth))
	}
	return f.branchTargets[len(f.branchTargets)-int(depth)-1]
}

func boundsStackLevel(f *function) int {
	return len(f.branchTargets)
}

func trimBoundsStacks(f *function) {
	size := boundsStackLevel(f) + 1
	for i := range f.vars {
		f.vars[i].trimBoundsStack(size)
	}
}

func genBlock(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	t := typeutil.BlockTypeByEncoding(load.Varint7())

	opSaveTemporaryOperands(f)
	opInitVars(f)
	opStoreVars(f, false)

	pushBranchTarget(f, t, false) // end

	savedMinBlockOperand := f.minBlockOperand
	f.minBlockOperand = len(f.operands)

	deadend = genOps(f, load)

	var result values.Operand

	if deadend {
		for len(f.operands) > f.minBlockOperand {
			x := popOperand(f)
			debugf("discarding operand at end of %s due to deadend: %s", op, x)
			discard(f, x)
		}
	} else {
		if t != abi.Void {
			result = popOperand(f)
			if result.Type != t {
				panic(fmt.Errorf("%s result has wrong type: %s", op, result.Type))
			}
		}

		if len(f.operands) != f.minBlockOperand {
			panic(fmt.Errorf("operands remain on stack after %s", op))
		}
	}

	f.minBlockOperand = savedMinBlockOperand

	if end := popBranchTarget(f); end.Live() {
		if result.Storage != values.Nowhere {
			opMove(f, regs.Result, result, false)
		}

		if t != abi.Void {
			result = values.TempRegOperand(t, regs.Result, false)
		}

		opLabel(f, end)
		isa.UpdateBranches(f.Text.Bytes(), end)
		deadend = false
	}

	if result.Storage != values.Nowhere {
		pushOperand(f, result)
	}

	return
}

func genBr(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	relativeDepth := load.Varuint32()
	target := getBranchTarget(f, relativeDepth)

	if target.valueType != abi.Void {
		value := popOperand(f)
		if value.Type != target.valueType {
			panic(fmt.Errorf("%s value operand type is %s, but target expects %s", op, value.Type, target.valueType))
		}
		opMove(f, regs.Result, value, false)
	}

	if target.funcEnd {
		isa.OpAddImmToStackPtr(f.Module, f.stackOffset)
		isa.OpReturn(f.Module)
	} else {
		opSaveTemporaryOperands(f) // TODO: avoid saving operands which we are going to skip over
		opInitVars(f)
		opStoreVars(f, true)
		isa.OpAddImmToStackPtr(f.Module, f.stackOffset-target.stackOffset)
		opBranch(f, &target.label)
	}

	deadend = true
	return
}

func genBrIf(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	relativeDepth := load.Varuint32()
	target := getBranchTarget(f, relativeDepth)

	cond := opPreloadOperand(f, popOperand(f))
	if cond.Type != abi.I32 {
		panic(fmt.Errorf("%s: condition operand has wrong type: %s", op, cond.Type))
	}

	var value values.Operand

	if target.valueType != abi.Void {
		value = popOperand(f)
		if value.Type != target.valueType {
			panic(fmt.Errorf("%s: value operand has wrong type: %s", op, value.Type))
		}
	}

	opSaveTemporaryOperands(f)
	opInitVars(f)
	opStoreVars(f, false)

	if value.Type != abi.Void {
		if cond.Storage == values.TempReg && cond.Reg() == regs.Result {
			reg := opAllocReg(f, abi.I32)
			zeroExt := opMove(f, reg, cond, true)
			cond = values.TempRegOperand(cond.Type, reg, zeroExt)
		}

		opMove(f, regs.Result, value, true)
	}

	stackDelta := f.stackOffset - target.stackOffset

	isa.OpAddImmToStackPtr(f.Module, stackDelta)
	opBranchIf(f, cond, true, &target.label)
	isa.OpAddImmToStackPtr(f.Module, -stackDelta)

	if target.valueType != abi.Void {
		pushResultRegOperand(f, target.valueType)
	}
	return
}

func genBrTable(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	targetCount := load.Varuint32()
	if targetCount >= uint32(MaxBranchTableSize) {
		panic(fmt.Errorf("%s has too many targets: %d", op, targetCount))
	}

	targetTable := make([]*branchTarget, targetCount)

	for i := range targetTable {
		relativeDepth := load.Varuint32()
		target := getBranchTarget(f, relativeDepth)
		target.label.SetLive()
		targetTable[i] = target
	}

	relativeDepth := load.Varuint32()
	defaultTarget := getBranchTarget(f, relativeDepth)
	defaultTarget.label.SetLive()

	index := opPreloadOperand(f, popOperand(f))
	if index.Type != abi.I32 {
		panic(fmt.Errorf("%s: index operand has wrong type: %s", op, index.Type))
	}

	valueType := defaultTarget.valueType

	for i, target := range targetTable {
		if target.valueType != valueType {
			panic(fmt.Errorf("%s targets have inconsistent value types: %s (default target) vs. %s (target #%d)", op, valueType, target.valueType, i))
		}
	}

	var value values.Operand

	if valueType != abi.Void {
		value = popOperand(f)
		if value.Type != valueType {
			panic(fmt.Errorf("%s: value operand has wrong type: %s", op, value.Type))
		}
	}

	var commonStackOffset int32
	var tableType = abi.I32
	var tableScale uint8 = 2

	if len(targetTable) > 0 {
		commonStackOffset = targetTable[0].stackOffset
		for _, target := range targetTable[1:] {
			if target.stackOffset != commonStackOffset {
				commonStackOffset = -1
				tableType = abi.I64
				tableScale = 3
				break
			}
		}
	}

	tableSize := len(targetTable) << tableScale
	alignMask := (1 << tableScale) - 1
	tableAddr := (len(f.ROData.Bytes()) + alignMask) &^ alignMask
	f.ROData.ResizeBytes(tableAddr + tableSize)

	opSaveTemporaryOperands(f) // TODO: avoid saving operands which we are going to skip over?
	opInitVars(f)
	opStoreVars(f, false)

	var reg2 regs.R

	if commonStackOffset < 0 {
		reg2 = opAllocReg(f, abi.I32)
	}

	if value.Type != abi.Void {
		if index.Storage == values.TempReg && index.Reg() == regs.Result {
			reg := opAllocReg(f, abi.I32)
			zeroExt := opMove(f, reg, index, true)
			index = values.TempRegOperand(index.Type, reg, zeroExt)
		}

		opMove(f, regs.Result, value, true)
	}

	var reg regs.R
	var regZeroExt bool

	if index.Storage.IsReg() {
		reg = index.Reg()
		regZeroExt = index.RegZeroExt()
	} else {
		reg = opAllocReg(f, abi.I32)
		regZeroExt = isa.OpMove(f.Module, f, reg, index, false)
	}

	f.Regs.FreeAll()

	// vars were already stored and regs freed
	for i := range f.vars {
		f.vars[i].resetCache()
	}

	// if index yielded a var register, then it was just freed, but the
	// register retains its value.  don't call anything that allocates
	// registers until the critical section ends.

	defaultDelta := f.stackOffset - defaultTarget.stackOffset

	isa.OpAddImmToStackPtr(f.Module, defaultDelta)
	tableStackOffset := f.stackOffset - defaultDelta
	opBranchIfOutOfBounds(f, reg, int32(len(targetTable)), &defaultTarget.label)
	regZeroExt = isa.OpLoadROIntIndex32ScaleDisp(f.Module, f, tableType, reg, regZeroExt, tableScale, int32(tableAddr))

	if commonStackOffset >= 0 {
		isa.OpAddImmToStackPtr(f.Module, tableStackOffset-commonStackOffset)
	} else {
		isa.OpMoveReg(f.Module, abi.I64, reg2, reg)
		isa.OpShiftRightLogical32Bits(f.Module, reg2)
		isa.OpAddToStackPtr(f.Module, reg2)

		regZeroExt = false
	}

	isa.OpBranchIndirect32(f.Module, reg, regZeroExt)

	// end of critical section.

	t := branchTable{
		roDataAddr: int32(tableAddr),
		targets:    targetTable,
	}
	if commonStackOffset >= 0 {
		t.codeStackOffset = -1
	} else {
		// no common offset
		t.codeStackOffset = tableStackOffset
	}
	f.branchTables = append(f.branchTables, t)

	deadend = true
	return
}

func genIf(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	t := typeutil.BlockTypeByEncoding(load.Varint7())

	pushBranchTarget(f, t, false) // end
	var afterThen links.L

	cond := popOperand(f)
	if cond.Type != abi.I32 {
		panic(fmt.Errorf("if condition has wrong type: %s", cond.Type))
	}

	opSaveTemporaryOperands(f)
	opInitVars(f)
	opStoreVars(f, false)
	opBranchIf(f, cond, false, &afterThen)

	thenDeadend, haveElse := genThenOps(f, load)

	if !haveElse && t != abi.Void {
		panic(errors.New("if without else has a value type"))
	}

	if !thenDeadend {
		if t != abi.Void {
			value := popOperand(f)
			if value.Type != t {
				panic(fmt.Errorf("%s value operand has type %s, but target expects %s", op, value.Type, t))
			}
			opMove(f, regs.Result, value, false)
		}

		if haveElse {
			opSaveTemporaryOperands(f)
			opStoreVars(f, true)
			opBranch(f, &getBranchTarget(f, 0).label) // end
		}
	}

	opLabel(f, &afterThen)
	isa.UpdateBranches(f.Text.Bytes(), &afterThen)

	if haveElse {
		deadend = genOps(f, load)

		if t != abi.Void && !deadend {
			value := popOperand(f)
			if value.Type != t {
				panic(fmt.Errorf("%s value operand has type %s, but target expects %s", op, value.Type, t))
			}
			opMove(f, regs.Result, value, false)
		}
	}

	end := popBranchTarget(f)
	if end.Live() { // includes thenDeadend information
		deadend = false
	}
	if !deadend {
		opLabel(f, end)
		isa.UpdateBranches(f.Text.Bytes(), end)
	}

	if t != abi.Void {
		pushResultRegOperand(f, t)
	}
	return
}

func genLoop(f *function, load loader.L, op Opcode, info opInfo) (deadend bool) {
	encodedBlockType := load.Varint7()

	opSaveTemporaryOperands(f)
	opInitVars(f)
	opStoreVars(f, false)

	pushBranchTarget(f, abi.Void, false) // begin
	opLabel(f, &getBranchTarget(f, 0).label)

	savedMinBlockOperand := f.minBlockOperand
	f.minBlockOperand = len(f.operands)

	deadend = genOps(f, load)

	if deadend {
		for len(f.operands) > f.minBlockOperand {
			x := popOperand(f)
			debugf("discarding operand at end of %s due to deadend: %s", op, x)
			discard(f, x)
		}
	} else {
		need := f.minBlockOperand
		if encodedBlockType != 0 {
			need++ // result remains on stack
		}
		if len(f.operands) > need { // let the next guy deal with missing operands
			panic(fmt.Errorf("operands remain on stack after %s", op))
		}
	}

	f.minBlockOperand = savedMinBlockOperand

	begin := popBranchTarget(f)
	isa.UpdateBranches(f.Text.Bytes(), begin)
	return
}

func opLabel(f *function, l *links.L) {
	opSaveTemporaryOperands(f)
	opStoreVars(f, true)
	l.Addr = f.Text.Pos()

	debugf("label")
}

func opBranch(f *function, l *links.L) {
	retAddr := isa.OpBranch(f.Module, l.Addr)
	if l.Addr == 0 {
		l.AddSite(retAddr)
	}
}

func opBranchIf(f *function, x values.Operand, yes bool, l *links.L) {
	x = effectiveOperand(f, x)
	retAddrs := isa.OpBranchIf(f.Module, f, x, yes, l.Addr)
	if l.Addr == 0 {
		l.AddSites(retAddrs)
	}
}

func opBranchIfOutOfBounds(f *function, indexReg regs.R, upperBound int32, l *links.L) {
	site := isa.OpBranchIfOutOfBounds(f.Module, indexReg, upperBound, l.Addr)
	if l.Addr == 0 {
		l.AddSite(site)
	}
}
